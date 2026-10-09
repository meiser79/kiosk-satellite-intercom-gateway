package gateway

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"
	"time"
)

// Kiosk Satellite's intercom tokens (app/lib/managers/remote/auth.dart):
//
//	payload = base64Url(JSON{intercom, from, n, exp(ms)})   (with '=' padding)
//	token   = payload + "." + base64Url(HMAC-SHA256("intercom:"+KEY, payload))
//
// A token is good for 60 s, for one call id, and once.

const tokenTTL = 60 * time.Second

// KeyFingerprint is what the identity endpoint reports: the first eight
// hex digits of SHA-256(key).
func KeyFingerprint(key string) string {
	if key == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])[:8]
}

func signData(key, data string) string {
	m := hmac.New(sha256.New, []byte("intercom:"+key))
	m.Write([]byte(data))
	return base64.URLEncoding.EncodeToString(m.Sum(nil))
}

// IssueToken builds a call token the way Kiosk Satellite does.
func IssueToken(key, callID, from string) string {
	claims := map[string]any{
		"intercom": callID,
		"from":     from,
		"n":        randHex(4),
		"exp":      time.Now().Add(tokenTTL).UnixMilli(),
	}
	b, _ := json.Marshal(claims)
	payload := base64.URLEncoding.EncodeToString(b)
	return payload + "." + signData(key, payload)
}

// Verifier checks incoming tokens: signature, call id, expiry, single use.
type Verifier struct {
	mu   sync.Mutex
	seen map[string]int64
}

// Verify checks a token for a call id and burns it.
func (v *Verifier) Verify(key, token, callID string) bool {
	if key == "" || token == "" {
		return false
	}
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(parts[1]), []byte(signData(key, parts[0]))) != 1 {
		return false
	}
	raw, err := base64.URLEncoding.DecodeString(parts[0])
	if err != nil {
		raw, err = base64.RawURLEncoding.DecodeString(parts[0])
		if err != nil {
			return false
		}
	}
	var claims map[string]any
	if json.Unmarshal(raw, &claims) != nil {
		return false
	}
	if id, _ := claims["intercom"].(string); id != callID {
		return false
	}
	expF, ok := claims["exp"].(float64)
	if !ok {
		return false
	}
	exp := int64(expF)
	now := time.Now().UnixMilli()
	if exp <= now {
		return false
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.seen == nil {
		v.seen = map[string]int64{}
	}
	for t, e := range v.seen {
		if e < now {
			delete(v.seen, t)
		}
	}
	if _, dup := v.seen[token]; dup {
		return false
	}
	v.seen[token] = exp
	return true
}
