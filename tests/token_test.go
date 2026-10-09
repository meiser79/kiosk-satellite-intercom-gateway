package tests

import (
	"testing"

	"ks-intercom-gateway/src/gateway"
)

// Computed with Python's hmac/hashlib/base64 from the algorithm in auth.dart:
// key "vector-key", call "call-x", valid until the year 2100.
const vectorToken = "eyJpbnRlcmNvbSI6ImNhbGwteCIsImZyb20iOiJraW9zayIsIm4iOiJhYjEyIiwiZXhwIjo0MTAyNDQ0ODAwMDAwfQ==." +
	"uSE5LYLVzTFgYrms0yXNERxKaYOs3cVH6W6aWYWOTnQ="

func TestGatewayAcceptsReferenceToken(t *testing.T) {
	var v gateway.Verifier
	if !v.Verify("vector-key", vectorToken, "call-x") {
		t.Fatal("reference token refused")
	}
	if v.Verify("vector-key", vectorToken, "call-x") {
		t.Fatal("replayed token accepted")
	}
	var w gateway.Verifier
	if w.Verify("other-key", vectorToken, "call-x") || w.Verify("vector-key", vectorToken, "call-y") {
		t.Fatal("token accepted for the wrong key or call")
	}
}

func TestTokensInterworkBothWays(t *testing.T) {
	var chk tokenChecker
	if !chk.ok("k", gateway.IssueToken("k", "c1", "gw"), "c1") {
		t.Fatal("a token issued by the gateway fails an independent check")
	}
	var v gateway.Verifier
	if !v.Verify("k", makeToken("k", "c2", "kiosk"), "c2") {
		t.Fatal("an independently built token fails the gateway's check")
	}
	if v.Verify("k", "", "c2") || v.Verify("", makeToken("k", "c3", "kiosk"), "c3") {
		t.Fatal("empty token or key accepted")
	}
}

func TestKeyFingerprint(t *testing.T) {
	if got := gateway.KeyFingerprint("abc"); got != "ba7816bf" { // sha256("abc") = ba7816bf...
		t.Fatalf("got %s", got)
	}
	if gateway.KeyFingerprint("some key") != fingerprint("some key") || gateway.KeyFingerprint("") != "" {
		t.Fatal("fingerprint mismatch")
	}
}
