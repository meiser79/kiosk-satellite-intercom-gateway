package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Client side of Kiosk Satellite's intercom wire (docs/intercom.md).

type kioskInfo struct {
	Host      string
	AdminPort int
	ID        string
	Name      string
	Enabled   bool
	KeyFP     string
	DND       bool
	CallPort  int
	CallTLS   bool
}

func (k *kioskInfo) baseURL() string {
	sch := "http"
	if k.CallTLS {
		sch = "https"
	}
	return sch + "://" + net.JoinHostPort(k.Host, strconv.Itoa(k.CallPort))
}

type icClient struct {
	key, selfID, selfName string
	hc                    *http.Client
	insecure              *tls.Config

	mu      sync.Mutex
	schemes map[string]string
	cache   map[string]cachedInfo
}

type cachedInfo struct {
	info *kioskInfo
	at   time.Time
}

func newICClient(key, id, name string) *icClient {
	cfg := &tls.Config{InsecureSkipVerify: true} // kiosks use self-signed certificates and nothing is pinned
	return &icClient{
		key: key, selfID: id, selfName: name, insecure: cfg,
		hc: &http.Client{
			Timeout:   6 * time.Second,
			Transport: &http.Transport{TLSClientConfig: cfg, IdleConnTimeout: 20 * time.Second},
		},
		schemes: map[string]string{},
		cache:   map[string]cachedInfo{},
	}
}

var errRateLimited = errors.New("probe rate-limited")

func (c *icClient) probe(ctx context.Context, host string, port int) (*kioskInfo, error) {
	if port == 0 {
		port = defaultAdmin
	}
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	c.mu.Lock()
	order := []string{"http", "https"}
	if c.schemes[addr] == "https" {
		order = []string{"https", "http"}
	}
	c.mu.Unlock()
	var lastErr error
	for _, sch := range order {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, sch+"://"+addr+"/api/intercom/identity", nil)
		resp, err := c.hc.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
		resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusNotFound: // a build without intercom
			c.remember(addr, sch)
			return &kioskInfo{Host: host, AdminPort: port, Enabled: false}, nil
		case http.StatusTooManyRequests:
			c.mu.Lock()
			ci, ok := c.cache[addr]
			c.mu.Unlock()
			if ok && time.Since(ci.at) < 5*time.Minute {
				return ci.info, nil
			}
			return nil, errRateLimited
		case http.StatusOK:
		default:
			lastErr = fmt.Errorf("identity: HTTP %d", resp.StatusCode)
			continue
		}
		var d struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Enabled  bool   `json:"enabled"`
			Key      string `json:"key"`
			DND      bool   `json:"dnd"`
			Endpoint *struct {
				Port int  `json:"port"`
				TLS  bool `json:"tls"`
			} `json:"endpoint"`
		}
		if err := json.Unmarshal(body, &d); err != nil {
			lastErr = fmt.Errorf("identity: %w", err)
			continue
		}
		c.remember(addr, sch)
		info := &kioskInfo{
			Host: host, AdminPort: port, ID: d.ID, Name: d.Name, Enabled: d.Enabled, KeyFP: d.Key, DND: d.DND,
			CallPort: port, CallTLS: sch == "https",
		}
		if e := d.Endpoint; e != nil && e.Port > 0 && e.Port <= 65535 {
			info.CallPort, info.CallTLS = e.Port, e.TLS
		}
		c.mu.Lock()
		c.cache[addr] = cachedInfo{info, time.Now()}
		c.mu.Unlock()
		return info, nil
	}
	return nil, lastErr
}

func (c *icClient) remember(addr, sch string) {
	c.mu.Lock()
	c.schemes[addr] = sch
	c.mu.Unlock()
}

// check says why a kiosk cannot be called, or "" when it can.
func (c *icClient) check(info *kioskInfo) string {
	switch {
	case !info.Enabled:
		return "off"
	case info.KeyFP != KeyFingerprint(c.key):
		return "key"
	case info.DND:
		return "dnd"
	}
	return ""
}

func (c *icClient) post(ctx context.Context, rawURL, callID string, body any) (int, map[string]any, error) {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(b))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+IssueToken(c.key, callID, c.selfID))
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out, nil
}

// invite rings a kiosk (kind "call") or announces to it (kind "broadcast").
// selfPort is the gateway's callback port matching the kiosk's TLS setting.
// callerName is what the kiosk shows as the caller: the SIP caller id.
// It returns the kiosk's status word: ringing, auto, listening, busy, dnd,
// off, key, tls, refused or unreachable.
func (c *icClient) invite(ctx context.Context, info *kioskInfo, callID, kind, selfAddr string, selfPort int, callerName string) string {
	if callerName == "" {
		callerName = c.selfName
	}
	from := map[string]any{
		"id": c.selfID, "name": callerName, "address": selfAddr, "port": selfPort,
		"version": "ks-intercom-gateway/" + Version, "tls": info.CallTLS,
	}
	code, out, err := c.post(ctx, info.baseURL()+"/api/intercom/call", callID,
		map[string]any{"call": callID, "kind": kind, "from": from})
	switch {
	case err != nil:
		return "unreachable"
	case code == http.StatusForbidden:
		return "key"
	case code == http.StatusConflict || code == http.StatusUpgradeRequired:
		return "tls"
	}
	if st, _ := out["status"].(string); st != "" {
		return st
	}
	return "failed"
}

func (c *icClient) signal(ctx context.Context, info *kioskInfo, callID, action string) error {
	code, _, err := c.post(ctx, info.baseURL()+"/api/intercom/call/"+callID, callID, map[string]any{"action": action})
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("signal %s: HTTP %d", action, code)
	}
	return nil
}

func (c *icClient) dialAudio(ctx context.Context, info *kioskInfo, callID string) (*websocket.Conn, error) {
	sch := "ws"
	if info.CallTLS {
		sch = "wss"
	}
	u := url.URL{
		Scheme: sch, Host: net.JoinHostPort(info.Host, strconv.Itoa(info.CallPort)),
		Path:     "/api/intercom/audio/" + callID,
		RawQuery: "token=" + url.QueryEscape(IssueToken(c.key, callID, c.selfID)),
	}
	d := websocket.Dialer{HandshakeTimeout: 6 * time.Second, TLSClientConfig: c.insecure}
	conn, _, err := d.DialContext(ctx, u.String(), nil)
	return conn, err
}

// ---- one audio link ------------------------------------------------------

type link struct {
	conn    *websocket.Conn
	out     chan []byte
	quit    chan struct{}
	once    sync.Once
	ended   chan struct{} // closed when the socket is gone
	endOnce sync.Once
	onAudio func([]byte) // frames from the kiosk's microphone
}

func newLink(conn *websocket.Conn) *link {
	return &link{conn: conn, out: make(chan []byte, 16), quit: make(chan struct{}), ended: make(chan struct{})}
}

func (l *link) start() {
	go l.writer()
	go l.reader()
}

func (l *link) markEnded() { l.endOnce.Do(func() { close(l.ended) }) }

// send queues a frame. A slow kiosk loses audio instead of holding the call.
func (l *link) send(frame []byte) {
	select {
	case l.out <- frame:
	default:
	}
}

func (l *link) close() { l.once.Do(func() { close(l.quit) }) }

func (l *link) writer() {
	defer l.markEnded()
	if err := l.conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"talk","on":true}`)); err != nil {
		l.conn.Close()
		return
	}
	for {
		select {
		case f := <-l.out:
			if err := l.conn.WriteMessage(websocket.BinaryMessage, f); err != nil {
				l.conn.Close()
				return
			}
		case <-l.quit:
			_ = l.conn.WriteMessage(websocket.TextMessage, []byte(`{"type":"end"}`))
			_ = l.conn.WriteControl(websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second))
			l.conn.Close()
			return
		}
	}
}

func (l *link) reader() {
	defer l.markEnded()
	for {
		typ, data, err := l.conn.ReadMessage()
		if err != nil {
			return
		}
		switch typ {
		case websocket.BinaryMessage:
			if l.onAudio != nil {
				l.onAudio(data)
			}
		case websocket.TextMessage:
			var m struct {
				Type string `json:"type"`
			}
			if json.Unmarshal(data, &m) == nil && m.Type == "end" {
				return
			}
		}
	}
}
