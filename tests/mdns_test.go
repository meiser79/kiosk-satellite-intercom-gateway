package tests

import (
	"encoding/binary"
	"net"
	"strconv"
	"strings"
	"testing"

	"ks-intercom-gateway/src/gateway"
)

const kioskService = "_kiosk-satellite._tcp.local"

// dnsName writes a name without compression, as the kiosk does.
func dnsName(b []byte, name string) []byte {
	for _, l := range strings.Split(name, ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0)
}

func dnsRecord(b []byte, name string, typ, class uint16, ttl int, rdata []byte) []byte {
	b = dnsName(b, name)
	b = binary.BigEndian.AppendUint16(b, typ)
	b = binary.BigEndian.AppendUint16(b, class)
	b = binary.BigEndian.AppendUint32(b, uint32(ttl))
	b = binary.BigEndian.AppendUint16(b, uint16(len(rdata)))
	return append(b, rdata...)
}

// announcement is what Kiosk Satellite's FleetDiscovery sends: five records
// in one response, TXT with id, name, version and the admin port, and the
// kiosk's own address in the A record. ttl 0 is the goodbye.
func announcement(id, name, addr string, port, ttl int) []byte {
	inst := "ks-" + id + "." + kioskService
	host := "ks-" + id + ".local"
	b := []byte{0, 0, 0x84, 0, 0, 0, 0, 5, 0, 0, 0, 0}
	b = dnsRecord(b, "_services._dns-sd._udp.local", 12, 1, ttl, dnsName(nil, kioskService))
	b = dnsRecord(b, kioskService, 12, 1, ttl, dnsName(nil, inst))
	srv := binary.BigEndian.AppendUint16([]byte{0, 0, 0, 0}, uint16(port))
	b = dnsRecord(b, inst, 33, 0x8001, ttl, dnsName(srv, host))
	var txt []byte
	for _, e := range []string{"id=" + id, "name=" + name, "version=1.4.0", "port=" + strconv.Itoa(port)} {
		txt = append(txt, byte(len(e)))
		txt = append(txt, e...)
	}
	b = dnsRecord(b, inst, 16, 0x8001, ttl, txt)
	return dnsRecord(b, host, 1, 0x8001, ttl, net.ParseIP(addr).To4())
}

func from(ip string) *net.UDPAddr { return &net.UDPAddr{IP: net.ParseIP(ip), Port: 5353} }

func TestDiscoveryReadsAnnouncement(t *testing.T) {
	d := gateway.NewDiscovery()
	d.HandlePacket(announcement("a1b2", "Küche", "192.168.1.50", 2324, 120), from("192.168.1.50"))
	l := d.List()
	if len(l) != 1 {
		t.Fatalf("kiosks: %+v", l)
	}
	k := l[0]
	if k.ID != "a1b2" || k.Name != "Küche" || k.Version != "1.4.0" || k.Address != "192.168.1.50" || k.Port != 2324 || k.TLS {
		t.Fatalf("kiosk: %+v", k)
	}
	if _, ok := d.Lookup("a1b2"); !ok {
		t.Fatal("lookup by id failed")
	}
}

func TestDiscoveryGoodbyeRemovesKiosk(t *testing.T) {
	d := gateway.NewDiscovery()
	d.HandlePacket(announcement("a1b2", "Küche", "192.168.1.50", 2324, 120), from("192.168.1.50"))
	d.HandlePacket(announcement("a1b2", "Küche", "192.168.1.50", 2324, 0), from("192.168.1.50"))
	if l := d.List(); len(l) != 0 {
		t.Fatalf("kiosk still listed after its goodbye: %+v", l)
	}
}

// Through an mDNS reflector between VLANs the packet comes from the router;
// the address in the announcement is the kiosk's.
func TestDiscoveryPrefersAnnouncedAddress(t *testing.T) {
	d := gateway.NewDiscovery()
	d.HandlePacket(announcement("a1b2", "Küche", "192.168.20.7", 2324, 120), from("192.168.1.1"))
	if l := d.List(); len(l) != 1 || l[0].Address != "192.168.20.7" {
		t.Fatalf("kiosks: %+v", l)
	}
}

func TestDiscoveryIgnoresOtherServices(t *testing.T) {
	d := gateway.NewDiscovery()
	b := []byte{0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0}
	b = dnsRecord(b, "_http._tcp.local", 12, 1, 120, dnsName(nil, "printer._http._tcp.local"))
	d.HandlePacket(b, from("192.168.1.9"))
	if l := d.List(); len(l) != 0 {
		t.Fatalf("kiosks: %+v", l)
	}
}

// Other responders, a reflector among them, compress names.
func TestDiscoveryReadsCompressedNames(t *testing.T) {
	b := []byte{0, 0, 0x84, 0, 0, 0, 0, 3, 0, 0, 0, 0}
	svc := len(b) // the service name starts here
	b = dnsName(b, kioskService)
	b = append(b, 0, 12, 0, 1, 0, 0, 0, 120)
	inst := len(b) + 2 // PTR rdata: "ks-c1" + pointer to the service
	rdata := append([]byte{5}, "ks-c1"...)
	rdata = append(rdata, 0xC0|byte(svc>>8), byte(svc))
	b = binary.BigEndian.AppendUint16(b, uint16(len(rdata)))
	b = append(b, rdata...)
	ptr := []byte{0xC0 | byte(inst>>8), byte(inst)}

	b = append(b, ptr...)
	b = append(b, 0, 33, 0x80, 1, 0, 0, 0, 120)
	srv := dnsName([]byte{0, 0, 0, 0, 0x09, 0x14}, "c1.local") // port 2324
	b = binary.BigEndian.AppendUint16(b, uint16(len(srv)))
	b = append(b, srv...)

	b = append(b, ptr...)
	b = append(b, 0, 16, 0x80, 1, 0, 0, 0, 120)
	txt := append([]byte{5}, "id=c1"...)
	txt = append(txt, 9)
	txt = append(txt, "name=Flur"...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(txt)))
	b = append(b, txt...)

	d := gateway.NewDiscovery()
	d.HandlePacket(b, from("192.168.1.60"))
	if l := d.List(); len(l) != 1 || l[0].ID != "c1" || l[0].Name != "Flur" || l[0].Port != 2324 || l[0].Address != "192.168.1.60" {
		t.Fatalf("kiosks: %+v", l)
	}
}

// The list is in the same order as the bridges and their kiosks.
func TestDiscoveryListsByName(t *testing.T) {
	d := gateway.NewDiscovery()
	for i, n := range []string{"Zimmer", "flur", "Ärztezimmer", "Bad"} {
		d.HandlePacket(announcement("k"+strconv.Itoa(i), n, "192.168.1."+strconv.Itoa(10+i), 2324, 120), from("192.168.1.1"))
	}
	var got []string
	for _, k := range d.List() {
		got = append(got, k.Name)
	}
	if strings.Join(got, ",") != "Ärztezimmer,Bad,flur,Zimmer" {
		t.Fatalf("order %v", got)
	}
}
