// Package tests exercises the gateway from the outside: through its exported
// API and over the wire. The fake PBX and the fake kiosk deliberately do not
// reuse the gateway's own SIP, digest or token code, so a bug there cannot
// cancel out against the same bug in the test.
package tests

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

const kioskFrame = 1280 // 80 ms of 16 kHz audio, in samples

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ---- tokens (spec: app/lib/managers/remote/auth.dart) ---------------------

func fingerprint(key string) string {
	s := sha256.Sum256([]byte(key))
	return hex.EncodeToString(s[:])[:8]
}

func sign(key, data string) string {
	m := hmac.New(sha256.New, []byte("intercom:"+key))
	m.Write([]byte(data))
	return base64.URLEncoding.EncodeToString(m.Sum(nil))
}

func makeToken(key, callID, from string) string {
	b, _ := json.Marshal(map[string]any{
		"intercom": callID, "from": from, "n": randHex(4), "exp": time.Now().Add(time.Minute).UnixMilli(),
	})
	p := base64.URLEncoding.EncodeToString(b)
	return p + "." + sign(key, p)
}

type tokenChecker struct {
	mu   sync.Mutex
	seen map[string]bool
}

func (c *tokenChecker) ok(key, tok, callID string) bool {
	parts := strings.Split(tok, ".")
	if len(parts) != 2 || parts[1] != sign(key, parts[0]) {
		return false
	}
	raw, err := base64.URLEncoding.DecodeString(parts[0])
	if err != nil {
		return false
	}
	var cl struct {
		Intercom string  `json:"intercom"`
		Exp      float64 `json:"exp"`
	}
	if json.Unmarshal(raw, &cl) != nil || cl.Intercom != callID || int64(cl.Exp) <= time.Now().UnixMilli() {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.seen == nil {
		c.seen = map[string]bool{}
	}
	if c.seen[tok] {
		return false
	}
	c.seen[tok] = true
	return true
}

// ---- a small SIP toolkit ------------------------------------------------------

type msg struct {
	start string
	h     [][2]string
	body  []byte
}

var compact = map[string]string{"i": "call-id", "v": "via", "f": "from", "t": "to", "m": "contact", "l": "content-length", "c": "content-type"}

func parse(b []byte) *msg {
	head, body := string(b), []byte(nil)
	if i := strings.Index(head, "\r\n\r\n"); i >= 0 {
		head, body = head[:i], b[i+4:]
	}
	lines := strings.Split(head, "\r\n")
	m := &msg{start: lines[0], body: body}
	for _, l := range lines[1:] {
		if i := strings.IndexByte(l, ':'); i > 0 {
			n := strings.ToLower(strings.TrimSpace(l[:i]))
			if f, ok := compact[n]; ok {
				n = f
			}
			m.h = append(m.h, [2]string{n, strings.TrimSpace(l[i+1:])})
		}
	}
	return m
}

func (m *msg) all(name string) (out []string) {
	for _, h := range m.h {
		if h[0] == name {
			out = append(out, h[1])
		}
	}
	return
}

func (m *msg) get(name string) string {
	if v := m.all(name); len(v) > 0 {
		return v[0]
	}
	return ""
}

func (m *msg) isReq() bool { return !strings.HasPrefix(m.start, "SIP/2.0") }

func (m *msg) method() string { return strings.Fields(m.start)[0] }

func (m *msg) status() int {
	var n int
	fmt.Sscanf(m.start, "SIP/2.0 %d", &n)
	return n
}

func (m *msg) ruri() string { return strings.Fields(m.start)[1] }

func build(start string, h [][2]string, body []byte) []byte {
	var sb strings.Builder
	sb.WriteString(start + "\r\n")
	for _, kv := range h {
		sb.WriteString(kv[0] + ": " + kv[1] + "\r\n")
	}
	fmt.Fprintf(&sb, "Content-Length: %d\r\n\r\n", len(body))
	return append([]byte(sb.String()), body...)
}

func reply(req *msg, code int, reason, toTag string, extra ...[2]string) []byte {
	var h [][2]string
	for _, v := range req.all("via") {
		h = append(h, [2]string{"Via", v})
	}
	h = append(h, [2]string{"From", req.get("from")})
	to := req.get("to")
	if toTag != "" && !strings.Contains(to, "tag=") {
		to += ";tag=" + toTag
	}
	h = append(h, [2]string{"To", to}, [2]string{"Call-ID", req.get("call-id")}, [2]string{"CSeq", req.get("cseq")})
	h = append(h, extra...)
	return build(fmt.Sprintf("SIP/2.0 %d %s", code, reason), h, nil)
}

// param reads ;name=value after the closing angle bracket of a header value.
func param(v, name string) string {
	if i := strings.LastIndexByte(v, '>'); i >= 0 {
		v = v[i:]
	}
	for _, p := range strings.Split(v, ";")[1:] {
		kv := strings.SplitN(strings.TrimSpace(p), "=", 2)
		if kv[0] == name && len(kv) == 2 {
			return kv[1]
		}
	}
	return ""
}

func uriOf(v string) string {
	if i := strings.IndexByte(v, '<'); i >= 0 {
		return v[i+1 : strings.IndexByte(v, '>')]
	}
	return strings.Split(v, ";")[0]
}

var authParam = regexp.MustCompile(`(\w+)=("[^"]*"|[^,\s]+)`)

func md5hex(s string) string { h := md5.Sum([]byte(s)); return hex.EncodeToString(h[:]) }

// digestOK checks an Authorization header the way a PBX would (RFC 2617, qop=auth).
func digestOK(auth, method, user, pass, realm, nonce string) bool {
	p := map[string]string{}
	for _, m := range authParam.FindAllStringSubmatch(strings.TrimPrefix(auth, "Digest "), -1) {
		p[m[1]] = strings.Trim(m[2], `"`)
	}
	if p["username"] != user || p["realm"] != realm || p["nonce"] != nonce || p["qop"] != "auth" {
		return false
	}
	ha1 := md5hex(user + ":" + realm + ":" + pass)
	ha2 := md5hex(method + ":" + p["uri"])
	return p["response"] == md5hex(ha1+":"+nonce+":"+p["nc"]+":"+p["cnonce"]+":auth:"+ha2)
}

// ---- audio helpers ----------------------------------------------------------

func pcm16(s []int16) []byte {
	b := make([]byte, 2*len(s))
	for i, v := range s {
		binary.LittleEndian.PutUint16(b[2*i:], uint16(v))
	}
	return b
}

func samples(b []byte) []int16 {
	s := make([]int16, len(b)/2)
	for i := range s {
		s[i] = int16(binary.LittleEndian.Uint16(b[2*i:]))
	}
	return s
}

func freeUDP(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}
