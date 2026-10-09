package gateway

import (
	"bytes"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"ks-intercom-gateway/src/audio"
)

type hdr struct{ name, value string }

type sipMsg struct {
	isReq  bool
	method string
	ruri   string
	status int
	reason string
	h      []hdr
	body   []byte
}

var compact = map[string]string{
	"i": "call-id", "v": "via", "f": "from", "t": "to", "m": "contact",
	"l": "content-length", "c": "content-type",
}

func parseSIP(b []byte) (*sipMsg, error) {
	head, body := b, []byte(nil)
	if i := bytes.Index(b, []byte("\r\n\r\n")); i >= 0 {
		head, body = b[:i], b[i+4:]
	}
	lines := strings.Split(string(head), "\r\n")
	if len(lines) == 0 || lines[0] == "" {
		return nil, errors.New("empty message")
	}
	m := &sipMsg{}
	first := strings.Fields(lines[0])
	switch {
	case len(first) >= 3 && first[0] == "SIP/2.0":
		code, err := strconv.Atoi(first[1])
		if err != nil {
			return nil, errors.New("bad status")
		}
		m.status = code
		m.reason = strings.Join(first[2:], " ")
	case len(first) == 3 && first[2] == "SIP/2.0":
		m.isReq, m.method, m.ruri = true, first[0], first[1]
	default:
		return nil, errors.New("bad start line")
	}
	for _, l := range lines[1:] {
		if l == "" {
			continue
		}
		if (l[0] == ' ' || l[0] == '\t') && len(m.h) > 0 {
			m.h[len(m.h)-1].value += " " + strings.TrimSpace(l)
			continue
		}
		i := strings.IndexByte(l, ':')
		if i < 0 {
			continue
		}
		name := strings.ToLower(strings.TrimSpace(l[:i]))
		if full, ok := compact[name]; ok {
			name = full
		}
		m.h = append(m.h, hdr{name, strings.TrimSpace(l[i+1:])})
	}
	if cl := m.get("content-length"); cl != "" {
		if n, err := strconv.Atoi(cl); err == nil && n >= 0 && n < len(body) {
			body = body[:n]
		}
	}
	m.body = body
	return m, nil
}

func (m *sipMsg) get(name string) string {
	for _, h := range m.h {
		if h.name == name {
			return h.value
		}
	}
	return ""
}

func (m *sipMsg) all(name string) []string {
	var out []string
	for _, h := range m.h {
		if h.name == name {
			out = append(out, h.value)
		}
	}
	return out
}

func (m *sipMsg) add(name, value string) { m.h = append(m.h, hdr{strings.ToLower(name), value}) }

func canon(n string) string {
	switch n {
	case "call-id":
		return "Call-ID"
	case "cseq":
		return "CSeq"
	case "www-authenticate":
		return "WWW-Authenticate"
	}
	parts := strings.Split(n, "-")
	for i, p := range parts {
		if p != "" {
			parts[i] = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	return strings.Join(parts, "-")
}

func (m *sipMsg) bytes() []byte {
	var b bytes.Buffer
	if m.isReq {
		fmt.Fprintf(&b, "%s %s SIP/2.0\r\n", m.method, m.ruri)
	} else {
		fmt.Fprintf(&b, "SIP/2.0 %d %s\r\n", m.status, m.reason)
	}
	for _, h := range m.h {
		if h.name == "content-length" {
			continue
		}
		fmt.Fprintf(&b, "%s: %s\r\n", canon(h.name), h.value)
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\n\r\n", len(m.body))
	b.Write(m.body)
	return b.Bytes()
}

// ---- header helpers -------------------------------------------------------

// angleURI returns the URI of a From/To/Contact value.
func angleURI(v string) string {
	if i := strings.IndexByte(v, '<'); i >= 0 {
		if j := strings.IndexByte(v[i:], '>'); j > 0 {
			return v[i+1 : i+j]
		}
	}
	if i := strings.IndexAny(v, ";,"); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(v)
}

func uriUser(uri string) string {
	uri = strings.TrimPrefix(strings.TrimPrefix(uri, "sips:"), "sip:")
	if i := strings.IndexByte(uri, '@'); i >= 0 {
		return uri[:i]
	}
	return ""
}

func uriHostPort(uri string) string {
	uri = strings.TrimPrefix(strings.TrimPrefix(uri, "sips:"), "sip:")
	if i := strings.IndexByte(uri, '@'); i >= 0 {
		uri = uri[i+1:]
	}
	if i := strings.IndexAny(uri, ";?"); i >= 0 {
		uri = uri[:i]
	}
	return uri
}

// hparam reads ;name=value from a header value, outside the angle brackets.
func hparam(v, name string) string {
	if i := strings.LastIndexByte(v, '>'); i >= 0 {
		v = v[i:]
	}
	for _, p := range strings.Split(v, ";")[1:] {
		kv := strings.SplitN(strings.TrimSpace(p), "=", 2)
		if strings.EqualFold(kv[0], name) && len(kv) == 2 {
			return strings.Trim(strings.TrimSpace(kv[1]), "\"")
		}
	}
	return ""
}

func newBranch() string { return "z9hG4bK" + randHex(6) }

func topBranch(via string) string {
	for _, p := range strings.Split(via, ";") {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(strings.ToLower(p), "branch=") {
			return p[7:]
		}
	}
	return ""
}

// ---- digest authentication (MD5, RFC 2617) -----------------------------------

var digestParam = regexp.MustCompile(`(\w+)=("([^"]*)"|[^,\s]+)`)

func md5hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func digestAuth(challenge, method, uri, user, pass string) (string, error) {
	if !strings.HasPrefix(strings.ToLower(challenge), "digest") {
		return "", errors.New("unsupported auth scheme")
	}
	p := map[string]string{}
	for _, m := range digestParam.FindAllStringSubmatch(challenge[6:], -1) {
		v := m[2]
		if strings.HasPrefix(v, "\"") {
			v = m[3]
		}
		p[strings.ToLower(m[1])] = v
	}
	if alg := p["algorithm"]; alg != "" && !strings.EqualFold(alg, "MD5") {
		return "", fmt.Errorf("unsupported digest algorithm %s", alg)
	}
	realm, nonce := p["realm"], p["nonce"]
	ha1 := md5hex(user + ":" + realm + ":" + pass)
	ha2 := md5hex(method + ":" + uri)
	var resp, extra string
	if qop := p["qop"]; strings.Contains(qop, "auth") {
		cnonce, nc := randHex(8), "00000001"
		resp = md5hex(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":auth:" + ha2)
		extra = fmt.Sprintf(`, qop=auth, nc=%s, cnonce="%s"`, nc, cnonce)
	} else {
		resp = md5hex(ha1 + ":" + nonce + ":" + ha2)
	}
	out := fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s", algorithm=MD5%s`,
		user, realm, nonce, uri, resp, extra)
	if op := p["opaque"]; op != "" {
		out += fmt.Sprintf(`, opaque="%s"`, op)
	}
	return out, nil
}

// ---- SDP -----------------------------------------------------------------

type sdpOffer struct {
	addr *net.UDPAddr
	pts  []int
}

func parseSDP(body []byte) (*sdpOffer, error) {
	var sessIP, mediaIP string
	port := 0
	var pts []int
	inAudio := false
	for _, l := range strings.Split(string(body), "\n") {
		l = strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(l, "c=IN IP4 "):
			ip := strings.Fields(l[9:])[0]
			if inAudio {
				mediaIP = ip
			} else {
				sessIP = ip
			}
		case strings.HasPrefix(l, "m="):
			inAudio = false
			f := strings.Fields(l[2:])
			if len(f) >= 4 && f[0] == "audio" && port == 0 {
				p, err := strconv.Atoi(f[1])
				if err != nil {
					continue
				}
				port, inAudio = p, true
				for _, s := range f[3:] {
					if n, err := strconv.Atoi(s); err == nil {
						pts = append(pts, n)
					}
				}
			}
		}
	}
	ip := mediaIP
	if ip == "" {
		ip = sessIP
	}
	if port == 0 || ip == "" {
		return nil, errors.New("no audio media in SDP")
	}
	a := net.ParseIP(ip)
	if a == nil {
		return nil, errors.New("bad SDP address")
	}
	return &sdpOffer{addr: &net.UDPAddr{IP: a, Port: port}, pts: pts}, nil
}

func (o *sdpOffer) pickCodec() (uint8, bool) {
	for _, p := range o.pts {
		if p == audio.PCMU || p == audio.PCMA {
			return uint8(p), true
		}
	}
	return 0, false
}

func buildSDP(ip string, port int, pt uint8) []byte {
	name := "PCMU"
	if pt == audio.PCMA {
		name = "PCMA"
	}
	sess := randHex(4)
	return []byte(fmt.Sprintf("v=0\r\no=- %s %s IN IP4 %s\r\ns=ks-intercom-gateway\r\nc=IN IP4 %s\r\nt=0 0\r\nm=audio %d RTP/AVP %d\r\na=rtpmap:%d %s/8000\r\na=ptime:20\r\na=sendrecv\r\n",
		sess, sess, ip, ip, port, pt, pt, name))
}

// displayName returns the quoted or bare display name of a From/PAI value.
func displayName(v string) string {
	i := strings.IndexByte(v, '<')
	if i <= 0 {
		return ""
	}
	n := strings.TrimSpace(v[:i])
	if len(n) >= 2 && n[0] == '"' && strings.HasSuffix(n, `"`) {
		n = strings.ReplaceAll(n[1:len(n)-1], `\"`, `"`)
	}
	return strings.TrimSpace(n)
}

// callerLabel is what the kiosk shows for a SIP caller: "Name (number)",
// or just the number or the name. P-Asserted-Identity wins over From, as a
// PBX puts the verified caller id there on trunk calls.
func CallerLabel(from, pai string) string {
	v := from
	if p := strings.TrimSpace(strings.Split(pai, ",")[0]); p != "" {
		v = p
	}
	num := uriUser(angleURI(v))
	if u, err := url.PathUnescape(num); err == nil {
		num = u
	}
	name := displayName(v)
	var out string
	switch {
	case name != "" && num != "" && name != num:
		out = name + " (" + num + ")"
	case name != "":
		out = name
	default:
		out = num
	}
	clean := make([]rune, 0, len(out))
	for _, r := range out {
		if r >= 0x20 && r != 0x7f {
			clean = append(clean, r)
		}
	}
	if len(clean) > 40 {
		clean = append(clean[:39], '…')
	}
	return strings.TrimSpace(string(clean))
}
