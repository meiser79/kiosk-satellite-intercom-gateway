package gateway

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
)

//go:embed web/index.html
var indexHTML []byte

// LogBuffer keeps the last log lines for the UI. The zero value is ready to use.
type LogBuffer struct {
	mu    sync.Mutex
	lines []string
}

func (b *LogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	b.lines = append(b.lines, strings.TrimRight(string(p), "\n"))
	if len(b.lines) > 300 {
		b.lines = b.lines[len(b.lines)-300:]
	}
	b.mu.Unlock()
	return len(p), nil
}

// Text returns the buffered lines.
func (b *LogBuffer) Text() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.Join(b.lines, "\n")
}

// NewUI is the configuration page and its JSON API. allow is a comma list of
// client IPs (empty: any); user/pass enable basic auth when pass is set.
func NewUI(store *Store, mgr *Manager, logs *LogBuffer, allow, user, pass string) http.Handler {
	allowed := map[string]bool{}
	for _, a := range strings.Split(allow, ",") {
		if a = strings.TrimSpace(a); a != "" {
			allowed[a] = true
		}
	}
	mux := http.NewServeMux()
	writeJSON := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(indexHTML)
	})
	mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, 200, store.Get().Public())
		case http.MethodPut:
			var in Config
			if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&in); err != nil {
				writeJSON(w, 400, map[string]string{"error": err.Error()})
				return
			}
			cfg, err := store.Update(in)
			if err != nil {
				writeJSON(w, 400, map[string]string{"error": err.Error()})
				return
			}
			if err := mgr.Reload(cfg); err != nil {
				writeJSON(w, 502, map[string]string{"error": "saved, but: " + err.Error()})
				return
			}
			writeJSON(w, 200, cfg.Public())
		default:
			http.Error(w, "method", 405)
		}
	})
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, mgr.Status()) })
	mux.HandleFunc("/api/logs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, logs.Text())
	})
	mux.HandleFunc("/api/test", func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Host string `json:"host"`
			Port int    `json:"port"`
		}
		if r.Method != http.MethodPost || json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in) != nil || in.Host == "" {
			http.Error(w, "bad request", 400)
			return
		}
		st, detail := mgr.TestKiosk(in.Host, in.Port)
		writeJSON(w, 200, map[string]string{"status": st, "detail": detail})
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(allowed) > 0 {
			host, _, _ := net.SplitHostPort(r.RemoteAddr)
			if !allowed[host] {
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
		}
		if pass != "" {
			u, p, ok := r.BasicAuth()
			if !ok || u != user || p != pass {
				w.Header().Set("WWW-Authenticate", `Basic realm="ks-intercom-gateway"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}
