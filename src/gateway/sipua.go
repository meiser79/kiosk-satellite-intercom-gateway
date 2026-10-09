package gateway

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type acctCfg struct{ User, AuthUser, Password string }

type SIPUA struct {
	cfg       SIPConfig
	conn      *net.UDPConn
	pbx       *net.UDPAddr
	domain    string
	localIP   string
	localPort int
	onInvite  func(*SIPCall)
	onReg     func(user, state, detail string)

	mu      sync.Mutex
	accts   map[string]*sipAccount
	pending map[string]chan *sipMsg
	calls   map[string]*SIPCall

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func NewSIPUA(cfg SIPConfig, accts []acctCfg, onInvite func(*SIPCall), onReg func(user, state, detail string)) (*SIPUA, error) {
	host, port, err := net.SplitHostPort(cfg.Server)
	if err != nil {
		host, port = cfg.Server, "5060"
	}
	pbx, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(host, port))
	if err != nil {
		return nil, fmt.Errorf("SIP-Server %q: %w", cfg.Server, err)
	}
	localIP := cfg.LocalIP
	if localIP == "" {
		c, err := net.DialUDP("udp4", nil, pbx)
		if err != nil {
			return nil, err
		}
		localIP = c.LocalAddr().(*net.UDPAddr).IP.String()
		c.Close()
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: cfg.LocalPort})
	if err != nil {
		return nil, err
	}
	ua := &SIPUA{
		cfg: cfg, conn: conn, pbx: pbx, domain: cfg.Server, localIP: localIP,
		localPort: conn.LocalAddr().(*net.UDPAddr).Port,
		onInvite:  onInvite, onReg: onReg,
		accts: map[string]*sipAccount{}, pending: map[string]chan *sipMsg{}, calls: map[string]*SIPCall{},
	}
	if ua.onReg == nil {
		ua.onReg = func(string, string, string) {}
	}
	ua.ctx, ua.cancel = context.WithCancel(context.Background())
	ua.wg.Add(1)
	go ua.readLoop()
	for _, a := range accts {
		acc := &sipAccount{ua: ua, cfg: a, callID: randHex(8) + "@" + localIP, fromTag: randHex(4)}
		ua.accts[a.User] = acc
		ua.wg.Add(1)
		go acc.run()
	}
	log.Printf("sip: UA on %s:%d, PBX %s", localIP, ua.localPort, pbx)
	return ua, nil
}

func (ua *SIPUA) send(b []byte, to *net.UDPAddr) {
	if _, err := ua.conn.WriteToUDP(b, to); err != nil {
		log.Printf("sip: send: %v", err)
	}
}

func (ua *SIPUA) newVia() string {
	return fmt.Sprintf("SIP/2.0/UDP %s:%d;branch=%s;rport", ua.localIP, ua.localPort, newBranch())
}

func (ua *SIPUA) contact(user string) string {
	return fmt.Sprintf("<sip:%s@%s:%d>", user, ua.localIP, ua.localPort)
}

// Close hangs up all calls, unregisters and stops.
func (ua *SIPUA) Close() {
	ua.mu.Lock()
	calls := make([]*SIPCall, 0, len(ua.calls))
	for _, c := range ua.calls {
		calls = append(calls, c)
	}
	accts := make([]*sipAccount, 0, len(ua.accts))
	for _, a := range ua.accts {
		accts = append(accts, a)
	}
	ua.mu.Unlock()
	for _, c := range calls {
		c.Hangup()
	}
	var wg sync.WaitGroup
	for _, a := range accts {
		wg.Add(1)
		go func(a *sipAccount) {
			defer wg.Done()
			if a.isRegistered() {
				_, _ = a.register(0)
			}
		}(a)
	}
	wg.Wait()
	ua.cancel()
	ua.conn.Close()
	ua.wg.Wait()
}

func (ua *SIPUA) readLoop() {
	defer ua.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, src, err := ua.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if !src.IP.Equal(ua.pbx.IP) {
			log.Printf("sip: ignoring packet from %s", src)
			continue
		}
		if n < 16 {
			continue // keep-alives
		}
		m, err := parseSIP(append([]byte(nil), buf[:n]...))
		if err != nil {
			log.Printf("sip: parse: %v", err)
			continue
		}
		if !m.isReq {
			ua.mu.Lock()
			ch := ua.pending[topBranch(m.get("via"))]
			ua.mu.Unlock()
			if ch != nil {
				select {
				case ch <- m:
				default:
				}
			}
			continue
		}
		ua.handleRequest(m, src)
	}
}

// transaction sends a request, retransmitting, and returns the final response.
func (ua *SIPUA) transaction(req *sipMsg, tries int) (*sipMsg, error) {
	branch := topBranch(req.get("via"))
	ch := make(chan *sipMsg, 8)
	ua.mu.Lock()
	ua.pending[branch] = ch
	ua.mu.Unlock()
	defer func() {
		ua.mu.Lock()
		delete(ua.pending, branch)
		ua.mu.Unlock()
	}()
	data := req.bytes()
	d := 500 * time.Millisecond
	for i := 0; i < tries; i++ {
		ua.send(data, ua.pbx)
		timer := time.NewTimer(d)
	wait:
		for {
			select {
			case r := <-ch:
				if r.status >= 200 {
					timer.Stop()
					return r, nil
				}
			case <-timer.C:
				break wait
			case <-ua.ctx.Done():
				timer.Stop()
				return nil, ua.ctx.Err()
			}
		}
		if d *= 2; d > 4*time.Second {
			d = 4 * time.Second
		}
	}
	return nil, errors.New("timeout")
}

// ---- registration -----------------------------------------------------------

type sipAccount struct {
	ua      *SIPUA
	cfg     acctCfg
	callID  string
	fromTag string
	cseq    int
	mu      sync.Mutex
	regd    bool
}

func (a *sipAccount) isRegistered() bool { a.mu.Lock(); defer a.mu.Unlock(); return a.regd }

func (a *sipAccount) setReg(v bool) { a.mu.Lock(); a.regd = v; a.mu.Unlock() }

func (a *sipAccount) run() {
	defer a.ua.wg.Done()
	for {
		a.ua.onReg(a.cfg.User, "registering", "")
		exp, err := a.register(300)
		if a.ua.ctx.Err() != nil {
			return
		}
		wait := 30 * time.Second
		if err != nil {
			a.setReg(false)
			a.ua.onReg(a.cfg.User, "error", err.Error())
			log.Printf("sip: register %s: %v", a.cfg.User, err)
		} else {
			a.setReg(true)
			a.ua.onReg(a.cfg.User, "registered", "")
			wait = time.Duration(exp) * time.Second * 8 / 10
			if wait < 10*time.Second {
				wait = 10 * time.Second
			}
		}
		select {
		case <-a.ua.ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func (a *sipAccount) buildRegister(expires int, authName, authVal string) *sipMsg {
	ua := a.ua
	uri := "sip:" + ua.domain
	m := &sipMsg{isReq: true, method: "REGISTER", ruri: uri}
	m.add("via", ua.newVia())
	m.add("max-forwards", "70")
	m.add("from", fmt.Sprintf("<sip:%s@%s>;tag=%s", a.cfg.User, ua.domain, a.fromTag))
	m.add("to", fmt.Sprintf("<sip:%s@%s>", a.cfg.User, ua.domain))
	m.add("call-id", a.callID)
	m.add("cseq", fmt.Sprintf("%d REGISTER", a.cseq))
	m.add("contact", ua.contact(a.cfg.User))
	m.add("expires", strconv.Itoa(expires))
	m.add("user-agent", "ks-intercom-gateway/"+Version)
	if authName != "" {
		m.add(authName, authVal)
	}
	return m
}

func (a *sipAccount) register(expires int) (int, error) {
	tries := 6
	if expires == 0 {
		tries = 2
	}
	a.mu.Lock()
	a.cseq++
	req := a.buildRegister(expires, "", "")
	a.mu.Unlock()
	resp, err := a.ua.transaction(req, tries)
	if err != nil {
		return 0, err
	}
	if resp.status == 401 || resp.status == 407 {
		name, hn := "authorization", "www-authenticate"
		if resp.status == 407 {
			name, hn = "proxy-authorization", "proxy-authenticate"
		}
		user := a.cfg.AuthUser
		if user == "" {
			user = a.cfg.User
		}
		val, err := digestAuth(resp.get(hn), "REGISTER", req.ruri, user, a.cfg.Password)
		if err != nil {
			return 0, err
		}
		a.mu.Lock()
		a.cseq++
		req = a.buildRegister(expires, name, val)
		a.mu.Unlock()
		if resp, err = a.ua.transaction(req, tries); err != nil {
			return 0, err
		}
	}
	if resp.status/100 != 2 {
		return 0, fmt.Errorf("%d %s", resp.status, resp.reason)
	}
	if expires == 0 {
		return 0, nil
	}
	exp := expires
	for _, c := range resp.all("contact") {
		if e := hparam(c, "expires"); e != "" {
			if n, err := strconv.Atoi(e); err == nil {
				exp = n
			}
		}
	}
	return exp, nil
}

// ---- requests from the PBX ---------------------------------------------------------

func (ua *SIPUA) buildResponse(req *sipMsg, code int, reason, toTag string) *sipMsg {
	r := &sipMsg{status: code, reason: reason}
	for _, v := range req.all("via") {
		r.add("via", v)
	}
	for _, v := range req.all("record-route") {
		r.add("record-route", v)
	}
	r.add("from", req.get("from"))
	to := req.get("to")
	if toTag != "" && hparam(to, "tag") == "" {
		to += ";tag=" + toTag
	}
	r.add("to", to)
	r.add("call-id", req.get("call-id"))
	r.add("cseq", req.get("cseq"))
	r.add("server", "ks-intercom-gateway/"+Version)
	return r
}

func (ua *SIPUA) reply(req *sipMsg, src *net.UDPAddr, code int, reason string) {
	ua.send(ua.buildResponse(req, code, reason, "").bytes(), src)
}

func (ua *SIPUA) handleRequest(req *sipMsg, src *net.UDPAddr) {
	callID := req.get("call-id")
	ua.mu.Lock()
	call := ua.calls[callID]
	ua.mu.Unlock()
	switch req.method {
	case "OPTIONS":
		r := ua.buildResponse(req, 200, "OK", "")
		r.add("allow", "INVITE, ACK, CANCEL, BYE, OPTIONS")
		ua.send(r.bytes(), src)
	case "INVITE":
		ua.handleInvite(req, src, call)
	case "ACK":
		if call != nil {
			call.gotACK()
		}
	case "BYE":
		if call == nil {
			ua.send(ua.buildResponse(req, 481, "Call/Transaction Does Not Exist", "").bytes(), src)
			return
		}
		ua.send(ua.buildResponse(req, 200, "OK", call.localTag).bytes(), src)
		call.terminate("bye")
	case "CANCEL":
		if call == nil {
			ua.send(ua.buildResponse(req, 481, "Call/Transaction Does Not Exist", "").bytes(), src)
			return
		}
		ua.send(ua.buildResponse(req, 200, "OK", call.localTag).bytes(), src)
		call.onCancel()
	case "NOTIFY", "INFO", "MESSAGE":
		ua.reply(req, src, 200, "OK")
	default:
		ua.reply(req, src, 501, "Not Implemented")
	}
}

func (ua *SIPUA) handleInvite(req *sipMsg, src *net.UDPAddr, existing *SIPCall) {
	if existing != nil {
		if hparam(req.get("to"), "tag") != "" {
			existing.onReinvite(req)
		} else {
			existing.resendLast()
		}
		return
	}
	user := uriUser(req.ruri)
	ua.mu.Lock()
	acct := ua.accts[user]
	ua.mu.Unlock()
	if acct == nil {
		ua.reply(req, src, 404, "Not Found")
		return
	}
	ua.reply(req, src, 100, "Trying")
	offer, err := parseSDP(req.body)
	if err != nil {
		ua.reply(req, src, 488, "Not Acceptable Here")
		return
	}
	pt, ok := offer.pickCodec()
	if !ok {
		ua.reply(req, src, 488, "Not Acceptable Here")
		return
	}
	c := &SIPCall{
		ua: ua, acct: acct, req: req, src: src, localTag: randHex(4), offer: offer, pt: pt,
		callID:    req.get("call-id"),
		remoteTag: hparam(req.get("from"), "tag"),
		ackCh:     make(chan struct{}), done: make(chan struct{}),
		state: stateEarly,
	}
	c.routes = req.all("record-route")
	ua.mu.Lock()
	ua.calls[c.callID] = c
	ua.mu.Unlock()
	log.Printf("sip: INVITE %s from %s", user, c.From())
	go ua.onInvite(c)
}

// ---- one incoming call --------------------------------------------------------

const (
	stateEarly = iota
	stateAnswered
	stateConfirmed
	stateTerminated
)

type SIPCall struct {
	ua        *SIPUA
	acct      *sipAccount
	callID    string
	req       *sipMsg
	src       *net.UDPAddr
	localTag  string
	remoteTag string
	routes    []string
	offer     *sdpOffer
	pt        uint8

	mu       sync.Mutex
	state    int
	lastResp []byte
	rtp      *rtpSession
	ackCh    chan struct{}
	ackOnce  sync.Once
	done     chan struct{}
	reason   string
}

func (c *SIPCall) Account() string       { return c.acct.cfg.User }
func (c *SIPCall) Done() <-chan struct{} { return c.done }
func (c *SIPCall) Reason() string        { c.mu.Lock(); defer c.mu.Unlock(); return c.reason }

func (c *SIPCall) From() string {
	f := c.req.get("from")
	if u := uriUser(angleURI(f)); u != "" {
		return u
	}
	return angleURI(f)
}

// CallerLabel is the caller as the kiosk should show it.
func (c *SIPCall) CallerLabel() string {
	return CallerLabel(c.req.get("from"), c.req.get("p-asserted-identity"))
}

func (c *SIPCall) withContact(r *sipMsg) {
	r.add("contact", c.ua.contact(c.acct.cfg.User))
	r.add("allow", "INVITE, ACK, CANCEL, BYE, OPTIONS")
}

func (c *SIPCall) sendFinal(r *sipMsg) {
	c.lastResp = r.bytes()
	c.ua.send(c.lastResp, c.src)
}

func (c *SIPCall) resendLast() {
	c.mu.Lock()
	b := c.lastResp
	c.mu.Unlock()
	if b != nil {
		c.ua.send(b, c.src)
	}
}

// Ringing sends 180. Harmless when called twice.
func (c *SIPCall) Ringing() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != stateEarly {
		return
	}
	r := c.ua.buildResponse(c.req, 180, "Ringing", c.localTag)
	c.withContact(r)
	c.sendFinal(r)
}

// Reject answers the INVITE with a failure.
func (c *SIPCall) Reject(code int, reason string) {
	c.mu.Lock()
	if c.state != stateEarly {
		c.mu.Unlock()
		return
	}
	c.sendFinal(c.ua.buildResponse(c.req, code, reason, c.localTag))
	c.mu.Unlock()
	c.terminate(fmt.Sprintf("rejected %d", code))
}

// Answer sends 200 OK and returns the media session, not yet started.
func (c *SIPCall) Answer(minPort, maxPort int) (*rtpSession, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != stateEarly {
		return nil, errors.New("call is not ringing")
	}
	rtp, err := newRTPSession(c.ua.localIP, minPort, maxPort)
	if err != nil {
		return nil, err
	}
	rtp.SetRemote(c.offer.addr, c.pt)
	c.rtp = rtp
	r := c.ua.buildResponse(c.req, 200, "OK", c.localTag)
	c.withContact(r)
	r.add("content-type", "application/sdp")
	r.body = buildSDP(c.ua.localIP, rtp.Port(), c.pt)
	c.sendFinal(r)
	c.state = stateAnswered
	go c.retransmit200()
	return rtp, nil
}

func (c *SIPCall) retransmit200() {
	d := 500 * time.Millisecond
	deadline := time.Now().Add(32 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-c.ackCh:
			return
		case <-c.done:
			return
		case <-time.After(d):
			c.resendLast()
		}
		if d *= 2; d > 4*time.Second {
			d = 4 * time.Second
		}
	}
	log.Printf("sip: no ACK for %s, hanging up", c.callID)
	c.Hangup()
}

func (c *SIPCall) gotACK() {
	c.mu.Lock()
	if c.state == stateAnswered {
		c.state = stateConfirmed
	}
	c.mu.Unlock()
	c.ackOnce.Do(func() { close(c.ackCh) })
}

func (c *SIPCall) onCancel() {
	c.mu.Lock()
	if c.state != stateEarly {
		c.mu.Unlock()
		return
	}
	c.sendFinal(c.ua.buildResponse(c.req, 487, "Request Terminated", c.localTag))
	c.mu.Unlock()
	c.terminate("cancelled")
}

// onReinvite answers a session refresh or hold with the same media.
func (c *SIPCall) onReinvite(req *sipMsg) {
	c.mu.Lock()
	rtp := c.rtp
	c.mu.Unlock()
	if rtp == nil {
		c.ua.send(c.ua.buildResponse(req, 491, "Request Pending", c.localTag).bytes(), c.src)
		return
	}
	if o, err := parseSDP(req.body); err == nil {
		rtp.SetRemote(o.addr, c.pt)
	}
	r := c.ua.buildResponse(req, 200, "OK", c.localTag)
	c.withContact(r)
	r.add("content-type", "application/sdp")
	r.body = buildSDP(c.ua.localIP, rtp.Port(), c.pt)
	c.ua.send(r.bytes(), c.src)
}

// Hangup ends the call from our side.
func (c *SIPCall) Hangup() {
	c.mu.Lock()
	answered := c.state == stateAnswered || c.state == stateConfirmed
	early := c.state == stateEarly
	c.mu.Unlock()
	switch {
	case answered:
		c.sendBye()
		c.terminate("local hangup")
	case early:
		c.Reject(487, "Request Terminated")
	}
}

func (c *SIPCall) sendBye() {
	ua := c.ua
	m := &sipMsg{isReq: true, method: "BYE", ruri: angleURI(c.req.get("contact"))}
	if m.ruri == "" {
		m.ruri = angleURI(c.req.get("from"))
	}
	m.add("via", ua.newVia())
	m.add("max-forwards", "70")
	for _, r := range c.routes {
		m.add("route", r)
	}
	m.add("from", c.req.get("to")+";tag="+c.localTag)
	m.add("to", c.req.get("from"))
	m.add("call-id", c.callID)
	m.add("cseq", "101 BYE")
	m.add("user-agent", "ks-intercom-gateway/"+Version)
	ua.wg.Add(1)
	go func() {
		defer ua.wg.Done()
		_, _ = ua.transaction(m, 4)
	}()
}

func (c *SIPCall) terminate(reason string) {
	c.mu.Lock()
	if c.state == stateTerminated {
		c.mu.Unlock()
		return
	}
	wasAnswered := c.state != stateEarly
	c.state = stateTerminated
	c.reason = reason
	rtp := c.rtp
	c.mu.Unlock()
	close(c.done)
	if rtp != nil {
		rtp.Close()
	}
	if wasAnswered {
		c.ua.dropCall(c.callID)
	} else {
		// Keep it for retransmitted INVITEs and the ACK of the final answer.
		time.AfterFunc(32*time.Second, func() { c.ua.dropCall(c.callID) })
	}
	log.Printf("sip: call %s ended (%s)", c.callID, reason)
}

func (ua *SIPUA) dropCall(id string) {
	ua.mu.Lock()
	delete(ua.calls, id)
	ua.mu.Unlock()
}

var _ = strings.TrimSpace
