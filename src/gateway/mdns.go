package gateway

import (
	"bytes"
	"encoding/binary"
	"log"
	"math/rand"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Finding the kiosks over mDNS.
//
// A kiosk with its remote admin and "Find other kiosks" on announces
// ks-<id>._kiosk-satellite._tcp.local every 30 s: PTR, SRV, TXT (id, name,
// version, port = the admin port, tls=1) and an A record with its own
// address, and a goodbye (TTL 0) when it stops. The gateway listens on 5353
// for those and also asks from a port of its own: a kiosk answers such a
// legacy query straight to the sender, which still works when another
// responder on the host (Avahi) keeps 5353 to itself.

const (
	mdnsService     = "_kiosk-satellite._tcp.local"
	mdnsQueryEvery  = 30 * time.Second
	mdnsForgetAfter = 100 * time.Second // three announcements missed
)

var mdnsGroup = &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}

// DiscoveredKiosk is a kiosk as its announcement describes it.
type DiscoveredKiosk struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Version string    `json:"version"`
	Address string    `json:"address"`
	Port    int       `json:"port"` // remote admin port
	TLS     bool      `json:"tls"`
	Seen    time.Time `json:"-"`
	SeenAgo int       `json:"seen_ago"` // seconds
}

// Discovery keeps the kiosks heard on the network. The zero value is not
// usable; NewDiscovery makes one, Start opens its sockets.
type Discovery struct {
	mu        sync.Mutex
	peers     map[string]DiscoveredKiosk
	query     *net.UDPConn
	group     *net.UDPConn
	listening bool
	quit      chan struct{}
	wg        sync.WaitGroup
}

func NewDiscovery() *Discovery {
	return &Discovery{peers: map[string]DiscoveredKiosk{}, quit: make(chan struct{})}
}

// Start opens the query socket and, when it can, joins the group on 5353.
func (d *Discovery) Start() error {
	q, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return err
	}
	d.query = q
	d.wg.Add(2)
	go d.readLoop(q)
	go d.queryLoop()
	if g, err := net.ListenMulticastUDP("udp4", nil, mdnsGroup); err == nil {
		d.mu.Lock()
		d.group, d.listening = g, true
		d.mu.Unlock()
		d.wg.Add(1)
		go d.readLoop(g)
	} else {
		log.Printf("mdns: not listening on 5353 (%v), finding kiosks by query only", err)
	}
	return nil
}

func (d *Discovery) Close() {
	close(d.quit)
	if d.query != nil {
		d.query.Close()
	}
	d.mu.Lock()
	g := d.group
	d.mu.Unlock()
	if g != nil {
		g.Close()
	}
	d.wg.Wait()
}

// Listening is whether announcements on 5353 reach the gateway; without
// that it only hears the answers to its queries.
func (d *Discovery) Listening() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.listening
}

// Scan asks every kiosk to answer now.
func (d *Discovery) Scan() {
	if d.query == nil {
		return
	}
	if _, err := d.query.WriteToUDP(mdnsQuery(), mdnsGroup); err != nil {
		log.Printf("mdns: query: %v", err)
	}
}

func (d *Discovery) queryLoop() {
	defer d.wg.Done()
	t := time.NewTicker(mdnsQueryEvery)
	defer t.Stop()
	for {
		d.Scan()
		select {
		case <-d.quit:
			return
		case <-t.C:
		}
	}
}

func (d *Discovery) readLoop(c *net.UDPConn) {
	defer d.wg.Done()
	buf := make([]byte, 9000)
	for {
		n, src, err := c.ReadFromUDP(buf)
		if err != nil {
			return
		}
		d.HandlePacket(buf[:n], src)
	}
}

// List returns the kiosks heard lately, by name.
func (d *Discovery) List() []DiscoveredKiosk {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	out := make([]DiscoveredKiosk, 0, len(d.peers))
	for id, p := range d.peers {
		if now.Sub(p.Seen) > mdnsForgetAfter {
			delete(d.peers, id)
			continue
		}
		p.SeenAgo = int(now.Sub(p.Seen).Seconds())
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if a, b := sortKey(out[i].Name), sortKey(out[j].Name); a != b {
			return a < b
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Lookup returns the kiosk with this id while it is heard.
func (d *Discovery) Lookup(id string) (DiscoveredKiosk, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	p, ok := d.peers[id]
	if !ok || time.Since(p.Seen) > mdnsForgetAfter {
		return DiscoveredKiosk{}, false
	}
	return p, true
}

// HandlePacket takes one mDNS packet. Tests call it directly.
func (d *Discovery) HandlePacket(p []byte, src *net.UDPAddr) {
	// Responses only, and only those that mention the service: a busy
	// network sends hundreds a second that are none of our business.
	if len(p) < 12 || p[2]&0x80 == 0 || !bytes.Contains(p, []byte("_kiosk-satellite")) {
		return
	}
	be16 := func(o int) int { return int(binary.BigEndian.Uint16(p[o:])) }
	qd, n := be16(4), be16(6)+be16(8)+be16(10)
	off := 12
	for i := 0; i < qd; i++ {
		var ok bool
		if _, off, ok = readName(p, off); !ok || off+4 > len(p) {
			return
		}
		off += 4
	}
	type srvRec struct {
		port   int
		target string
	}
	names := map[string]bool{}
	srv := map[string]srvRec{}
	txt := map[string]map[string]string{}
	ttls := map[string]uint32{}
	addrs := map[string]string{}
	for i := 0; i < n; i++ {
		name, o, ok := readName(p, off)
		if !ok || o+10 > len(p) {
			return
		}
		typ, ttl, rdlen := be16(o), binary.BigEndian.Uint32(p[o+4:]), be16(o+8)
		o += 10
		end := o + rdlen
		if end > len(p) {
			return
		}
		name = strings.ToLower(name)
		switch typ {
		case 12: // PTR
			if name == mdnsService {
				if t, _, ok := readName(p, o); ok {
					t = strings.ToLower(t)
					names[t], ttls[t] = true, ttl
				}
			}
		case 33: // SRV
			if rdlen >= 7 {
				if t, _, ok := readName(p, o+6); ok {
					srv[name] = srvRec{be16(o + 4), strings.ToLower(t)}
					names[name], ttls[name] = true, ttl
				}
			}
		case 16: // TXT
			m := map[string]string{}
			for q := o; q < end; {
				l := int(p[q])
				q++
				if q+l > end {
					break
				}
				if k, v, ok := strings.Cut(string(p[q:q+l]), "="); ok && k != "" {
					m[k] = v
				}
				q += l
			}
			txt[name] = m
			names[name] = true
		case 1: // A
			if rdlen == 4 {
				addrs[name] = net.IP(p[o:end]).String()
			}
		}
		off = end
	}
	suffix := "." + mdnsService
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	for inst := range names {
		s, ok := srv[inst]
		e, ok2 := txt[inst]
		if !strings.HasSuffix(inst, suffix) || !ok || !ok2 {
			continue
		}
		id := e["id"]
		if id == "" {
			id = strings.TrimPrefix(strings.TrimSuffix(inst, suffix), "ks-")
		}
		if ttls[inst] == 0 {
			delete(d.peers, id)
			continue
		}
		// The announcement's own address first: through an mDNS reflector
		// the packet comes from the router.
		addr := addrs[s.target]
		if !usableAddr(addr) {
			if src == nil {
				continue
			}
			addr = src.IP.String()
		}
		port, err := strconv.Atoi(e["port"])
		if err != nil || port <= 0 || port > 65535 {
			port = s.port
		}
		name := e["name"]
		if name == "" {
			name = id
		}
		d.peers[id] = DiscoveredKiosk{ID: id, Name: name, Version: e["version"], Address: addr, Port: port,
			TLS: e["tls"] == "1", Seen: now}
	}
}

func usableAddr(a string) bool {
	return a != "" && a != "0.0.0.0" && !strings.HasPrefix(a, "127.") && !strings.HasPrefix(a, "169.254.")
}

// mdnsQuery asks for the service's PTR records.
func mdnsQuery() []byte {
	b := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(b, uint16(rand.Intn(1<<16)))
	b[5] = 1 // one question
	for _, l := range strings.Split(mdnsService, ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0, 0, 12, 0, 1)
}

// readName reads a DNS name at off, following compression pointers, and
// returns it with the offset just past it.
func readName(p []byte, off int) (string, int, bool) {
	var labels []string
	end := -1
	for steps := 0; steps < 128; steps++ {
		if off >= len(p) {
			return "", 0, false
		}
		l := int(p[off])
		switch {
		case l == 0:
			if end < 0 {
				end = off + 1
			}
			return strings.Join(labels, "."), end, true
		case l&0xC0 == 0xC0:
			if off+1 >= len(p) {
				return "", 0, false
			}
			if end < 0 {
				end = off + 2
			}
			off = int(binary.BigEndian.Uint16(p[off:]) & 0x3FFF)
		case l&0xC0 != 0:
			return "", 0, false
		default:
			if off+1+l > len(p) {
				return "", 0, false
			}
			labels = append(labels, string(p[off+1:off+1+l]))
			off += 1 + l
		}
	}
	return "", 0, false
}
