package gateway

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const (
	gatewayName  = "Kiosk Satellite Intercom Gateway"
	Version      = "0.1.0"
	defaultAdmin = 2324
)

// Kiosk is one Kiosk Satellite device a bridge rings.
type Kiosk struct {
	Name string `json:"name"`
	Host string `json:"host"`
	Port int    `json:"port"` // remote admin port, 2324 by default
}

// Bridge maps one SIP account to one or more kiosks.
type Bridge struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Enabled     bool    `json:"enabled"`
	User        string  `json:"user"`
	AuthUser    string  `json:"auth_user"`
	Password    string  `json:"password,omitempty"`
	PasswordSet bool    `json:"password_set,omitempty"`
	Mode        string  `json:"mode"` // "ring": all ring, first answer wins; "announce": one way to all
	Kiosks      []Kiosk `json:"kiosks"`
}

type SIPConfig struct {
	Server      string `json:"server"`       // PBX host[:port]
	LocalIP     string `json:"local_ip"`     // optional, detected when empty
	LocalPort   int    `json:"local_port"`   // UDP port of the gateway's SIP socket
	RTPMin      int    `json:"rtp_min"`      //
	RTPMax      int    `json:"rtp_max"`      //
	RingTimeout int    `json:"ring_timeout"` // seconds
}

type Config struct {
	GatewayID      string    `json:"gateway_id"`
	IntercomKey    string    `json:"intercom_key,omitempty"`
	IntercomKeySet bool      `json:"intercom_key_set,omitempty"`
	SIP            SIPConfig `json:"sip"`
	Bridges        []Bridge  `json:"bridges"`
}

func defaultConfig() Config {
	return Config{
		GatewayID: randHex(6),
		SIP:       SIPConfig{LocalPort: 5070, RTPMin: 10000, RTPMax: 10100, RingTimeout: 40},
	}
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Store keeps the configuration in <dir>/config.json (HA: addon_config).
type Store struct {
	mu   sync.RWMutex
	path string
	cfg  Config
}

func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	s := &Store{path: filepath.Join(dir, "config.json"), cfg: defaultConfig()}
	b, err := os.ReadFile(s.path)
	switch {
	case err == nil:
		if err := json.Unmarshal(b, &s.cfg); err != nil {
			return nil, fmt.Errorf("%s: %w", s.path, err)
		}
		s.cfg.normalize()
	case errors.Is(err, os.ErrNotExist):
		if err := s.save(); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	return s, nil
}

func (c *Config) normalize() {
	d := defaultConfig()
	if c.GatewayID == "" {
		c.GatewayID = d.GatewayID
	}
	if c.SIP.LocalPort == 0 {
		c.SIP.LocalPort = d.SIP.LocalPort
	}
	if c.SIP.RTPMin == 0 || c.SIP.RTPMax == 0 {
		c.SIP.RTPMin, c.SIP.RTPMax = d.SIP.RTPMin, d.SIP.RTPMax
	}
	if c.SIP.RingTimeout <= 0 {
		c.SIP.RingTimeout = d.SIP.RingTimeout
	}
	c.IntercomKey = strings.TrimSpace(c.IntercomKey)
	c.IntercomKeySet = false
	for i := range c.Bridges {
		b := &c.Bridges[i]
		if b.ID == "" {
			b.ID = randHex(4)
		}
		if b.Mode != "announce" {
			b.Mode = "ring"
		}
		b.PasswordSet = false
		b.User = strings.TrimSpace(b.User)
		for j := range b.Kiosks {
			k := &b.Kiosks[j]
			k.Host = strings.TrimSpace(k.Host)
			if k.Port == 0 {
				k.Port = defaultAdmin
			}
			if k.Name == "" {
				k.Name = k.Host
			}
		}
	}
}

func (c Config) validate() error {
	if c.SIP.RTPMin >= c.SIP.RTPMax {
		return errors.New("invalid RTP port range")
	}
	users := map[string]bool{}
	for _, b := range c.Bridges {
		if !b.Enabled {
			continue
		}
		if c.SIP.Server == "" {
			return errors.New("SIP server is missing")
		}
		if b.User == "" {
			return fmt.Errorf("bridge %q: SIP user is missing", b.Name)
		}
		if users[b.User] {
			return fmt.Errorf("SIP user %q is used twice", b.User)
		}
		users[b.User] = true
		if len(b.Kiosks) == 0 {
			return fmt.Errorf("bridge %q: no kiosk", b.Name)
		}
		for _, k := range b.Kiosks {
			if k.Host == "" {
				return fmt.Errorf("bridge %q: kiosk without host", b.Name)
			}
		}
	}
	return nil
}

// Get returns a deep copy.
func (s *Store) Get() Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return clone(s.cfg)
}

func clone(c Config) Config {
	b, _ := json.Marshal(c)
	var out Config
	_ = json.Unmarshal(b, &out)
	return out
}

// Public hides the secrets, as the UI sees them.
func (c Config) Public() Config {
	out := clone(c)
	out.IntercomKeySet = out.IntercomKey != ""
	out.IntercomKey = ""
	for i := range out.Bridges {
		out.Bridges[i].PasswordSet = out.Bridges[i].Password != ""
		out.Bridges[i].Password = ""
	}
	return out
}

// Update takes the UI's config. Empty secrets keep the stored ones.
func (s *Store) Update(in Config) (Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	in.GatewayID = s.cfg.GatewayID
	in.normalize()
	if in.IntercomKey == "" {
		in.IntercomKey = s.cfg.IntercomKey
	}
	old := map[string]string{}
	for _, b := range s.cfg.Bridges {
		old[b.ID] = b.Password
	}
	for i := range in.Bridges {
		if in.Bridges[i].Password == "" {
			in.Bridges[i].Password = old[in.Bridges[i].ID]
		}
	}
	if err := in.validate(); err != nil {
		return Config{}, err
	}
	prev := s.cfg
	s.cfg = in
	if err := s.save(); err != nil {
		s.cfg = prev
		return Config{}, err
	}
	return clone(s.cfg), nil
}

func (s *Store) save() error {
	c := clone(s.cfg)
	c.IntercomKeySet = false
	for i := range c.Bridges {
		c.Bridges[i].PasswordSet = false
	}
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
