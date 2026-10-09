package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type regStatus struct {
	State  string
	Detail string
}

type Manager struct {
	store               *Store
	sigPort, sigTLSPort int

	mu   sync.Mutex
	cfg  Config
	ic   *icClient
	ua   *SIPUA
	ver  Verifier
	legs map[string]*leg
	runs map[*callRun]struct{}
	reg  map[string]regStatus
}

func NewManager(store *Store, sigPort, sigTLSPort int) *Manager {
	return &Manager{
		store: store, sigPort: sigPort, sigTLSPort: sigTLSPort,
		legs: map[string]*leg{}, runs: map[*callRun]struct{}{}, reg: map[string]regStatus{},
	}
}

func (m *Manager) Reload(cfg Config) error {
	m.mu.Lock()
	old := m.ua
	m.ua = nil
	m.mu.Unlock()
	if old != nil {
		old.Close()
	}
	m.mu.Lock()
	m.cfg = cfg
	m.ic = newICClient(cfg.IntercomKey, cfg.GatewayID, gatewayName)
	m.reg = map[string]regStatus{}
	m.mu.Unlock()

	var accts []acctCfg
	for _, b := range cfg.Bridges {
		if b.Enabled && b.User != "" {
			accts = append(accts, acctCfg{User: b.User, AuthUser: b.AuthUser, Password: b.Password})
		}
	}
	if len(accts) == 0 || cfg.SIP.Server == "" {
		return nil
	}
	ua, err := NewSIPUA(cfg.SIP, accts, m.onInvite, m.onReg)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.ua = ua
	m.mu.Unlock()
	return nil
}

func (m *Manager) Close() {
	m.mu.Lock()
	ua := m.ua
	m.ua = nil
	m.mu.Unlock()
	if ua != nil {
		ua.Close()
	}
}

func (m *Manager) onReg(user, state, detail string) {
	m.mu.Lock()
	m.reg[user] = regStatus{state, detail}
	m.mu.Unlock()
}

// ---- one call from the PBX --------------------------------------------------

type leg struct {
	id     string
	kiosk  Kiosk
	info   *kioskInfo
	status string
	run    *callRun
}

type legEvent struct {
	leg    *leg
	action string
}

type callRun struct {
	m      *Manager
	c      *SIPCall
	br     Bridge
	cfg    Config
	ic     *icClient
	events chan legEvent
	legs   []*leg
	since  time.Time

	mu    sync.Mutex
	state string
}

func (r *callRun) setState(s string) { r.mu.Lock(); r.state = s; r.mu.Unlock() }

func (m *Manager) onInvite(c *SIPCall) {
	m.mu.Lock()
	cfg, ic := m.cfg, m.ic
	m.mu.Unlock()
	var br *Bridge
	for i := range cfg.Bridges {
		if cfg.Bridges[i].Enabled && cfg.Bridges[i].User == c.Account() {
			br = &cfg.Bridges[i]
		}
	}
	if br == nil || ic == nil {
		c.Reject(404, "Not Found")
		return
	}
	if cfg.IntercomKey == "" {
		log.Printf("call: no intercom key configured")
		c.Reject(503, "Service Unavailable")
		return
	}
	r := &callRun{m: m, c: c, br: *br, cfg: cfg, ic: ic, events: make(chan legEvent, 32), since: time.Now(), state: "calling"}
	m.mu.Lock()
	m.runs[r] = struct{}{}
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		delete(m.runs, r)
		for _, l := range r.legs {
			delete(m.legs, l.id)
		}
		m.mu.Unlock()
	}()
	r.exec()
}

func routeIP(host string, port int) string {
	c, err := net.Dial("udp4", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return ""
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP.String()
}

// inviteLegs probes and rings every kiosk of the bridge in parallel.
func (r *callRun) inviteLegs(kind string) {
	for _, k := range r.br.Kiosks {
		r.legs = append(r.legs, &leg{id: randHex(8), kiosk: k, run: r})
	}
	r.m.mu.Lock()
	for _, l := range r.legs {
		r.m.legs[l.id] = l
	}
	r.m.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for _, l := range r.legs {
		wg.Add(1)
		go func(l *leg) {
			defer wg.Done()
			info, err := r.ic.probe(ctx, l.kiosk.Host, l.kiosk.Port)
			if err != nil {
				l.status = "unreachable"
				log.Printf("call %s: %s: %v", r.c.callID, l.kiosk.Name, err)
				return
			}
			l.info = info
			if why := r.ic.check(info); why != "" {
				l.status = why
				return
			}
			port := r.m.sigPort
			if info.CallTLS {
				port = r.m.sigTLSPort
			}
			l.status = r.ic.invite(ctx, info, l.id, kind, routeIP(info.Host, info.CallPort), port, r.c.CallerLabel())
		}(l)
	}
	wg.Wait()
	for _, l := range r.legs {
		log.Printf("call %s: %s -> %s", r.c.callID, l.kiosk.Name, l.status)
	}
}

func rejectFor(legs []*leg) (int, string) {
	allBusy := len(legs) > 0
	for _, l := range legs {
		switch l.status {
		case "key", "tls", "off", "refused":
			return 503, "Service Unavailable"
		case "dnd", "busy":
		default:
			allBusy = false
		}
	}
	if allBusy {
		return 486, "Busy Here"
	}
	return 480, "Temporarily Unavailable"
}

func (r *callRun) cancelLegs(except *leg) {
	for _, l := range r.legs {
		if l == except || l.info == nil || !(l.status == "ringing" || l.status == "auto") {
			continue
		}
		go func(l *leg) {
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			_ = r.ic.signal(ctx, l.info, l.id, "cancel")
		}(l)
	}
}

func (r *callRun) exec() {
	announce := r.br.Mode == "announce"
	kind := "call"
	if announce {
		kind = "broadcast"
	}
	r.inviteLegs(kind)
	var active []*leg
	for _, l := range r.legs {
		if (!announce && (l.status == "ringing" || l.status == "auto")) || (announce && l.status == "listening") {
			active = append(active, l)
		}
	}
	select {
	case <-r.c.Done(): // the caller gave up while we probed
		r.cancelLegs(nil)
		return
	default:
	}
	if len(active) == 0 {
		code, reason := rejectFor(r.legs)
		r.c.Reject(code, reason)
		return
	}
	var links []*link
	var winners []*leg
	if announce {
		r.setState("announcing")
		links, winners = r.openAudio(active)
		if len(links) == 0 {
			r.c.Reject(480, "Temporarily Unavailable")
			return
		}
	} else {
		r.c.Ringing()
		r.setState("ringing")
		w := r.waitAnswer(active)
		if w == nil {
			return
		}
		links, winners = r.openAudio([]*leg{w})
		if len(links) == 0 {
			r.c.Reject(503, "Service Unavailable")
			return
		}
	}
	rtp, err := r.c.Answer(r.cfg.SIP.RTPMin, r.cfg.SIP.RTPMax)
	if err != nil {
		log.Printf("call %s: answer: %v", r.c.callID, err)
		for _, l := range links {
			l.close()
		}
		r.hangupKiosks(winners)
		return
	}
	r.session(rtp, links, winners, announce)
}

// waitAnswer returns the leg that answered first, or nil when the call is over.
func (r *callRun) waitAnswer(active []*leg) *leg {
	timeout := time.NewTimer(time.Duration(r.cfg.SIP.RingTimeout) * time.Second)
	defer timeout.Stop()
	pending := map[*leg]bool{}
	for _, l := range active {
		pending[l] = true
	}
	declined := false
	for {
		select {
		case <-r.c.Done():
			r.cancelLegs(nil)
			return nil
		case <-timeout.C:
			r.cancelLegs(nil)
			r.c.Reject(480, "Temporarily Unavailable")
			return nil
		case ev := <-r.events:
			if !pending[ev.leg] {
				continue
			}
			switch ev.action {
			case "answer":
				r.cancelLegs(ev.leg)
				return ev.leg
			case "decline", "missed":
				delete(pending, ev.leg)
				ev.leg.status = ev.action
				declined = declined || ev.action == "decline"
				if len(pending) == 0 {
					if declined {
						r.c.Reject(603, "Decline")
					} else {
						r.c.Reject(480, "Temporarily Unavailable")
					}
					return nil
				}
			}
		}
	}
}

// openAudio dials the audio socket of each leg. It returns the links that came up.
func (r *callRun) openAudio(legs []*leg) ([]*link, []*leg) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	type res struct {
		l *leg
		k *link
	}
	ch := make(chan res, len(legs))
	for _, l := range legs {
		go func(l *leg) {
			conn, err := r.ic.dialAudio(ctx, l.info, l.id)
			if err != nil {
				log.Printf("call %s: audio %s: %v", r.c.callID, l.kiosk.Name, err)
				ch <- res{l, nil}
				return
			}
			ch <- res{l, newLink(conn)}
		}(l)
	}
	var links []*link
	var ok []*leg
	for range legs {
		x := <-ch
		if x.k != nil {
			links = append(links, x.k)
			ok = append(ok, x.l)
		} else {
			go func(l *leg) {
				c2, c := context.WithTimeout(context.Background(), 4*time.Second)
				defer c()
				_ = r.ic.signal(c2, l.info, l.id, "hangup")
			}(x.l)
		}
	}
	return links, ok
}

func (r *callRun) hangupKiosks(legs []*leg) {
	for _, l := range legs {
		go func(l *leg) {
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			_ = r.ic.signal(ctx, l.info, l.id, "hangup")
		}(l)
	}
}

func (r *callRun) session(rtp *rtpSession, links []*link, legs []*leg, announce bool) {
	r.setState("in_call")
	log.Printf("call %s: in call with %d kiosk(s)", r.c.callID, len(links))
	if !announce {
		links[0].onAudio = rtp.PushFromKiosk
	}
	for _, l := range links {
		l.start()
	}
	rtp.Start(func(frame []byte) {
		for _, l := range links {
			l.send(frame)
		}
	})
	sessDone := make(chan struct{})
	allEnded := make(chan struct{})
	go func() {
		for _, l := range links {
			select {
			case <-l.ended:
			case <-sessDone:
				return
			}
		}
		close(allEnded)
	}()
	kioskHungUp := false
	select {
	case <-r.c.Done():
	case <-allEnded:
		kioskHungUp = true
		r.c.Hangup()
	}
	close(sessDone)
	for _, l := range links {
		l.close()
	}
	if !kioskHungUp {
		r.hangupKiosks(legs)
	}
	log.Printf("call %s: finished after %s", r.c.callID, time.Since(r.since).Round(time.Second))
}

// ---- callbacks from the kiosks --------------------------------------------------

// SignalHandler serves what a kiosk tells us about a call: answer, decline,
// missed or hangup, as POST /api/intercom/call/<id> with our own token.
func (m *Manager) SignalHandler() http.Handler {
	const prefix = "/api/intercom/call/"
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost || !strings.HasPrefix(req.URL.Path, prefix) {
			http.NotFound(w, req)
			return
		}
		id := strings.TrimPrefix(req.URL.Path, prefix)
		var body struct {
			Action string `json:"action"`
		}
		if err := json.NewDecoder(io.LimitReader(req.Body, 1<<16)).Decode(&body); err != nil {
			http.Error(w, `{"error":"invalid JSON"}`, http.StatusBadRequest)
			return
		}
		m.mu.Lock()
		l, key := m.legs[id], m.cfg.IntercomKey
		m.mu.Unlock()
		if l == nil {
			http.Error(w, `{"error":"no such call"}`, http.StatusNotFound)
			return
		}
		tok := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
		if !m.ver.Verify(key, tok, id) {
			http.Error(w, `{"error":"refused"}`, http.StatusForbidden)
			return
		}
		select {
		case l.run.events <- legEvent{l, body.Action}:
		default:
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
}

// ---- status and tests -----------------------------------------------------------

type AccountStatus struct {
	Bridge string `json:"bridge"`
	User   string `json:"user"`
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
}

type CallStatus struct {
	Bridge  string   `json:"bridge"`
	From    string   `json:"from"`
	State   string   `json:"state"`
	Seconds int      `json:"seconds"`
	Kiosks  []string `json:"kiosks"`
}

type Status struct {
	Accounts []AccountStatus `json:"accounts"`
	Calls    []CallStatus    `json:"calls"`
	KeySet   bool            `json:"key_set"`
}

func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := Status{KeySet: m.cfg.IntercomKey != "", Accounts: []AccountStatus{}, Calls: []CallStatus{}}
	for _, b := range m.cfg.Bridges {
		if !b.Enabled {
			continue
		}
		rs, ok := m.reg[b.User]
		if !ok {
			rs = regStatus{State: "starting"}
		}
		st.Accounts = append(st.Accounts, AccountStatus{b.Name, b.User, rs.State, rs.Detail})
	}
	for r := range m.runs {
		r.mu.Lock()
		cs := CallStatus{Bridge: r.br.Name, From: r.c.From(), State: r.state, Seconds: int(time.Since(r.since).Seconds())}
		r.mu.Unlock()
		for _, l := range r.legs {
			cs.Kiosks = append(cs.Kiosks, fmt.Sprintf("%s (%s)", l.kiosk.Name, l.status))
		}
		st.Calls = append(st.Calls, cs)
	}
	sort.Slice(st.Calls, func(i, j int) bool { return st.Calls[i].Seconds > st.Calls[j].Seconds })
	return st
}

// TestKiosk tells whether a kiosk could be called right now.
func (m *Manager) TestKiosk(host string, port int) (string, string) {
	m.mu.Lock()
	ic := m.ic
	m.mu.Unlock()
	if ic == nil {
		return "unreachable", "not configured"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	info, err := ic.probe(ctx, host, port)
	if err != nil {
		return "unreachable", err.Error()
	}
	if why := ic.check(info); why != "" {
		return why, info.Name
	}
	return "ready", fmt.Sprintf("%s (%s, %s)", info.Name, map[bool]string{true: "TLS", false: "no TLS"}[info.CallTLS], info.ID)
}
