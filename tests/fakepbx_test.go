package tests

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const (
	pbxRealm = "asterisk"
	pbxNonce = "abc123"
	pbxUser  = "2001"
	pbxPass  = "pw"
)

// fakePBX is a tiny Asterisk: it registers one account with digest auth and
// can place calls to the gateway.
type fakePBX struct {
	t       *testing.T
	conn    *net.UDPConn
	rtp     *net.UDPConn
	gw      *net.UDPAddr
	in      chan *msg
	regd    chan struct{}
	authBad atomic.Bool
	down    atomic.Bool  // restarting: drops everything
	pings   atomic.Int32 // OPTIONS that passed digest auth
	optChal atomic.Int32 // OPTIONS challenged with 401
	optNC   int64        // last nonce count of an OPTIONS, only touched by run
	fromHdr string
}

func newFakePBX(t *testing.T) *fakePBX {
	lo := &net.UDPAddr{IP: net.ParseIP("127.0.0.1")}
	c, err := net.ListenUDP("udp4", lo)
	if err != nil {
		t.Fatal(err)
	}
	r, err := net.ListenUDP("udp4", lo)
	if err != nil {
		t.Fatal(err)
	}
	p := &fakePBX{t: t, conn: c, rtp: r, in: make(chan *msg, 32), regd: make(chan struct{}, 4),
		fromHdr: "<sip:caller@pbx>;tag=pbxtag"}
	t.Cleanup(func() { c.Close(); r.Close() })
	go p.run()
	return p
}

func (p *fakePBX) port() int    { return p.conn.LocalAddr().(*net.UDPAddr).Port }
func (p *fakePBX) rtpPort() int { return p.rtp.LocalAddr().(*net.UDPAddr).Port }

func (p *fakePBX) run() {
	buf := make([]byte, 65535)
	for {
		n, src, err := p.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if p.down.Load() {
			continue
		}
		m := parse(append([]byte(nil), buf[:n]...))
		switch {
		case m.isReq() && m.method() == "OPTIONS":
			// Asterisk challenges OPTIONS from an endpoint with credentials.
			// Unlike Asterisk, a nonce count that does not go up is a replay.
			auth := m.get("authorization")
			nc := nonceCount(auth)
			if !digestOK(auth, "OPTIONS", pbxUser, pbxPass, pbxRealm, pbxNonce) || nc <= p.optNC {
				p.optChal.Add(1)
				p.conn.WriteToUDP(reply(m, 401, "Unauthorized", "x",
					[2]string{"WWW-Authenticate", fmt.Sprintf(`Digest realm="%s", nonce="%s", algorithm=MD5, qop="auth"`, pbxRealm, pbxNonce)}), src)
				continue
			}
			p.optNC = nc
			p.pings.Add(1)
			p.conn.WriteToUDP(reply(m, 200, "OK", "x"), src)
		case m.isReq() && m.method() == "REGISTER":
			auth := m.get("authorization")
			switch {
			case auth == "":
				p.conn.WriteToUDP(reply(m, 401, "Unauthorized", "x",
					[2]string{"WWW-Authenticate", fmt.Sprintf(`Digest realm="%s", nonce="%s", algorithm=MD5, qop="auth"`, pbxRealm, pbxNonce)}), src)
			case !digestOK(auth, "REGISTER", pbxUser, pbxPass, pbxRealm, pbxNonce):
				p.authBad.Store(true)
				p.conn.WriteToUDP(reply(m, 403, "Forbidden", "x"), src)
			default:
				p.conn.WriteToUDP(reply(m, 200, "OK", "x", [2]string{"Contact", "<" + uriOf(m.get("contact")) + ">;expires=300"}), src)
				p.gw = src
				p.regd <- struct{}{}
			}
		default:
			p.in <- m
		}
	}
}

func (p *fakePBX) send(method, call string, cseq int, toTag string, body []byte, extra ...[2]string) {
	to := "<sip:2001@pbx>"
	if toTag != "" {
		to += ";tag=" + toTag
	}
	h := [][2]string{
		{"Via", fmt.Sprintf("SIP/2.0/UDP 127.0.0.1:%d;branch=z9hG4bK%s", p.port(), randHex(5))},
		{"Max-Forwards", "70"}, {"From", p.fromHdr}, {"To", to}, {"Call-ID", call},
		{"CSeq", fmt.Sprintf("%d %s", cseq, method)},
		{"Contact", fmt.Sprintf("<sip:caller@127.0.0.1:%d>", p.port())},
	}
	h = append(h, extra...)
	if body != nil {
		h = append(h, [2]string{"Content-Type", "application/sdp"})
	}
	p.conn.WriteToUDP(build(fmt.Sprintf("%s sip:2001@127.0.0.1:%d SIP/2.0", method, p.gw.Port), h, body), p.gw)
}

func (p *fakePBX) invite(call string) {
	sdp := fmt.Sprintf("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio %d RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\n", p.rtpPort())
	p.send("INVITE", call, 1, "", []byte(sdp))
}

// wait returns the first response with this status; a different final
// failure while waiting for a non-failure fails the test.
func (p *fakePBX) wait(want int, d time.Duration) *msg {
	p.t.Helper()
	dl := time.After(d)
	for {
		select {
		case m := <-p.in:
			if m.isReq() {
				continue
			}
			if m.status() == want {
				return m
			}
			if want < 300 && m.status() >= 300 {
				p.t.Fatalf("got %s while waiting for %d", m.start, want)
			}
		case <-dl:
			p.t.Fatalf("timeout waiting for SIP %d", want)
		}
	}
}

// checkOrigin fails unless the answer's o= line carries decimal session id
// and version, as RFC 4566 and Asterisk require.
func checkOrigin(t *testing.T, ok *msg) {
	t.Helper()
	for _, l := range strings.Split(string(ok.body), "\n") {
		if !strings.HasPrefix(l, "o=") {
			continue
		}
		f := strings.Fields(strings.TrimSpace(l))
		if len(f) != 6 {
			t.Fatalf("origin line %q", l)
		}
		for _, v := range f[1:3] {
			if _, err := strconv.ParseUint(v, 10, 64); err != nil {
				t.Fatalf("origin line %q: %q is not decimal", l, v)
			}
		}
		return
	}
	t.Fatal("answer has no origin line")
}

// media returns where the gateway wants RTP, from its 200 OK.
func mediaAddr(ok *msg) *net.UDPAddr {
	var ip string
	port := 0
	for _, l := range strings.Split(string(ok.body), "\n") {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "c=IN IP4 ") {
			ip = strings.Fields(l)[2]
		}
		if strings.HasPrefix(l, "m=audio ") {
			fmt.Sscanf(l, "m=audio %d", &port)
		}
	}
	return &net.UDPAddr{IP: net.ParseIP(ip), Port: port}
}
