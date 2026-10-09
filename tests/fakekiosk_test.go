package tests

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// fakeKiosk speaks Kiosk Satellite's side of the intercom wire.
type fakeKiosk struct {
	t       *testing.T
	srv     *httptest.Server
	key     string
	mode    string // answer | decline | dnd
	chk     tokenChecker
	calls   chan string // kind of each call received
	names   chan string // caller name shown for each call
	frames  chan []byte // audio received from the gateway
	ended   chan struct{}
	signals chan string // cancel / hangup from the gateway
	closed  atomic.Bool
}

func newFakeKiosk(t *testing.T, key, mode string) *fakeKiosk {
	k := &fakeKiosk{t: t, key: key, mode: mode, calls: make(chan string, 4), names: make(chan string, 4),
		frames: make(chan []byte, 256), ended: make(chan struct{}, 2), signals: make(chan string, 8)}
	up := websocket.Upgrader{}
	k.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		switch {
		case r.URL.Path == "/api/intercom/identity":
			port := k.srv.Listener.Addr().(*net.TCPAddr).Port
			json.NewEncoder(w).Encode(map[string]any{
				"id": "kiosk-" + mode, "name": "Kiosk " + mode, "enabled": true, "key": fingerprint(k.key),
				"dnd": mode == "dnd", "endpoint": map[string]any{"port": port, "tls": false},
			})
		case r.URL.Path == "/api/intercom/call" && r.Method == http.MethodPost:
			var b struct {
				Call string
				Kind string
				From map[string]any
			}
			json.NewDecoder(r.Body).Decode(&b)
			if !k.chk.ok(k.key, bearer, b.Call) {
				http.Error(w, "refused", http.StatusForbidden)
				return
			}
			k.calls <- b.Kind
			k.names <- fmt.Sprint(b.From["name"])
			json.NewEncoder(w).Encode(map[string]string{"status": "ringing"})
			back := fmt.Sprintf("http://%v:%v/api/intercom/call/%s", b.From["address"], b.From["port"], b.Call)
			go k.callBack(back, b.Call)
		case strings.HasPrefix(r.URL.Path, "/api/intercom/call/"): // cancel / hangup from the gateway
			id := strings.TrimPrefix(r.URL.Path, "/api/intercom/call/")
			var b struct{ Action string }
			json.NewDecoder(r.Body).Decode(&b)
			if !k.chk.ok(k.key, bearer, id) {
				http.Error(w, "refused", http.StatusForbidden)
				return
			}
			k.signals <- b.Action
			w.Write([]byte(`{"ok":true}`))
		case strings.HasPrefix(r.URL.Path, "/api/intercom/audio/"):
			id := strings.TrimPrefix(r.URL.Path, "/api/intercom/audio/")
			if !k.chk.ok(k.key, r.URL.Query().Get("token"), id) {
				http.Error(w, "refused", http.StatusForbidden)
				return
			}
			c, err := up.Upgrade(w, r, nil)
			if err != nil {
				return
			}
			go k.audio(c)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(func() { k.closed.Store(true); k.srv.Close() })
	return k
}

// callBack is the user pressing Answer (or Decline) after a short ring.
func (k *fakeKiosk) callBack(url, call string) {
	time.Sleep(150 * time.Millisecond)
	action := "answer"
	if k.mode == "decline" {
		action = "decline"
	}
	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(`{"action":"`+action+`"}`))
	req.Header.Set("Authorization", "Bearer "+makeToken(k.key, call, "kiosk-"+k.mode))
	resp, err := http.DefaultClient.Do(req)
	if (err != nil || resp.StatusCode != 200) && !k.closed.Load() {
		k.t.Errorf("kiosk callback: %v %v", err, resp)
	}
}

// audio plays the microphone (a 440 Hz tone, 80 ms frames) and collects what it hears.
func (k *fakeKiosk) audio(c *websocket.Conn) {
	done := make(chan struct{})
	go func() {
		ph := 0
		tk := time.NewTicker(80 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-done:
				return
			case <-tk.C:
				s := make([]int16, kioskFrame)
				for i := range s {
					s[i] = int16(8000 * math.Sin(2*math.Pi*440*float64(ph)/16000))
					ph++
				}
				if c.WriteMessage(websocket.BinaryMessage, pcm16(s)) != nil {
					return
				}
			}
		}
	}()
	for {
		typ, data, err := c.ReadMessage()
		if err != nil {
			break
		}
		if typ == websocket.BinaryMessage {
			select {
			case k.frames <- data:
			default:
			}
		} else if strings.Contains(string(data), `"end"`) {
			k.ended <- struct{}{}
			break
		}
	}
	close(done)
	c.Close()
}
