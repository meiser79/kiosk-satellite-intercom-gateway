package tests

import (
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"net/http"
	"testing"
	"time"

	"ks-intercom-gateway/src/audio"
	"ks-intercom-gateway/src/gateway"
)

const testKey = "test-intercom-key"

// setup starts a gateway against the fake PBX and the given kiosks and waits
// until its account is registered.
func setup(t *testing.T, key string, kiosks ...*fakeKiosk) (*gateway.Manager, *fakePBX) {
	t.Helper()
	pbx := newFakePBX(t)
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sigPort := ln.Addr().(*net.TCPAddr).Port
	store, err := gateway.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mgr := gateway.NewManager(store, sigPort, sigPort+1)
	go http.Serve(ln, mgr.SignalHandler())
	t.Cleanup(func() { ln.Close(); mgr.Close() })

	var ks []gateway.Kiosk
	for _, k := range kiosks {
		ks = append(ks, gateway.Kiosk{Name: k.mode, Host: "127.0.0.1", Port: k.srv.Listener.Addr().(*net.TCPAddr).Port})
	}
	cfg, err := store.Update(gateway.Config{
		IntercomKey: key,
		SIP: gateway.SIPConfig{Server: fmt.Sprintf("127.0.0.1:%d", pbx.port()), LocalIP: "127.0.0.1",
			LocalPort: freeUDP(t), RTPMin: 21000, RTPMax: 21100, RingTimeout: 10},
		Bridges: []gateway.Bridge{{ID: "b1", Name: "Test", Enabled: true, User: pbxUser, Password: pbxPass, Mode: "ring", Kiosks: ks}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.Reload(cfg); err != nil {
		t.Fatal(err)
	}
	select {
	case <-pbx.regd:
	case <-time.After(5 * time.Second):
		t.Fatalf("gateway did not register (digest rejected: %v)", pbx.authBad.Load())
	}
	return mgr, pbx
}

func TestCallThroughMultipleKiosks(t *testing.T) {
	decl := newFakeKiosk(t, testKey, "decline")
	ans := newFakeKiosk(t, testKey, "answer")
	mgr, pbx := setup(t, testKey, decl, ans)
	pbx.fromHdr = `"Anna Muster" <sip:0301234@pbx>;tag=pbxtag`

	pbx.invite("call-1@pbx")
	pbx.wait(180, 5*time.Second)
	ok := pbx.wait(200, 8*time.Second)
	toTag := param(ok.get("to"), "tag")
	pbx.send("ACK", "call-1@pbx", 1, toTag, nil)

	// Both kiosks were rung and both show the SIP caller; the answerer won.
	for _, k := range []*fakeKiosk{decl, ans} {
		select {
		case n := <-k.names:
			if n != "Anna Muster (0301234)" {
				t.Fatalf("kiosk %s shows caller %q", k.mode, n)
			}
		case <-time.After(time.Second):
			t.Fatalf("kiosk %s was not rung", k.mode)
		}
	}

	// SIP -> kiosk: 1.2 s of a 300 Hz tone in 20 ms PCMU packets.
	heard := make(chan bool, 1)
	go func() { // kiosk -> SIP: the gateway must send the kiosk's 440 Hz tone as RTP
		buf := make([]byte, 2048)
		pbx.rtp.SetReadDeadline(time.Now().Add(5 * time.Second))
		peak := 0
		for peak <= 2000 {
			n, _, err := pbx.rtp.ReadFromUDP(buf)
			if err != nil {
				break
			}
			for _, b := range buf[12:n] {
				if v := int(math.Abs(float64(audio.UlawDecode(b)))); v > peak {
					peak = v
				}
			}
		}
		heard <- peak > 2000
	}()
	gw := mediaAddr(ok)
	seq, ts := uint16(100), uint32(0)
	for i := 0; i < 60; i++ {
		pkt := make([]byte, 12, 172)
		pkt[0], pkt[1] = 0x80, 0
		binary.BigEndian.PutUint16(pkt[2:], seq)
		binary.BigEndian.PutUint32(pkt[4:], ts)
		binary.BigEndian.PutUint32(pkt[8:], 0xABCDEF)
		for j := 0; j < 160; j++ {
			pkt = append(pkt, audio.UlawEncode(int16(6000*math.Sin(2*math.Pi*300*float64(int(ts)+j)/8000))))
		}
		pbx.rtp.WriteToUDP(pkt, gw)
		seq++
		ts += 160
		time.Sleep(20 * time.Millisecond)
	}

	select {
	case f := <-ans.frames:
		if len(f) != 2*kioskFrame {
			t.Fatalf("frame is %d bytes, want %d", len(f), 2*kioskFrame)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the kiosk got no audio from the SIP side")
	}
	var peak int16
	for len(ans.frames) > 0 {
		for _, v := range samples(<-ans.frames) {
			if v > peak {
				peak = v
			}
		}
	}
	if peak < 3000 {
		t.Fatalf("tone too quiet at the kiosk: %d", peak)
	}
	if !<-heard {
		t.Fatal("the SIP side never heard the kiosk's tone")
	}

	st := mgr.Status()
	if len(st.Calls) != 1 || st.Calls[0].State != "in_call" {
		t.Fatalf("status: %+v", st)
	}
	if len(st.Accounts) != 1 || st.Accounts[0].State != "registered" {
		t.Fatalf("accounts: %+v", st.Accounts)
	}

	pbx.send("BYE", "call-1@pbx", 2, toTag, nil)
	pbx.wait(200, 3*time.Second)
	select {
	case <-ans.ended:
	case <-time.After(3 * time.Second):
		t.Fatal("the kiosk was not told to end the call")
	}
	select {
	case a := <-ans.signals:
		if a != "hangup" {
			t.Fatalf("signal %q", a)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no hangup signal to the kiosk")
	}
}

func TestAllDecline(t *testing.T) {
	_, pbx := setup(t, testKey, newFakeKiosk(t, testKey, "decline"))
	pbx.invite("call-2@pbx")
	pbx.wait(603, 6*time.Second)
}

func TestDoNotDisturbGivesBusy(t *testing.T) {
	_, pbx := setup(t, testKey, newFakeKiosk(t, testKey, "dnd"))
	pbx.invite("call-3@pbx")
	pbx.wait(486, 6*time.Second)
}

func TestWrongKeyIsRefused(t *testing.T) {
	_, pbx := setup(t, testKey, newFakeKiosk(t, "another-key", "answer"))
	pbx.invite("call-4@pbx")
	pbx.wait(503, 6*time.Second)
}

func TestCallerCancels(t *testing.T) {
	// Rings, then declines after 150 ms; the CANCEL comes first.
	_, pbx := setup(t, testKey, newFakeKiosk(t, testKey, "decline"))
	pbx.invite("call-5@pbx")
	pbx.wait(180, 5*time.Second)
	pbx.send("CANCEL", "call-5@pbx", 1, "", nil)
	pbx.wait(487, 3*time.Second)
}

func TestPBXKeepAliveIsAnswered(t *testing.T) {
	_, pbx := setup(t, testKey, newFakeKiosk(t, testKey, "answer"))
	pbx.send("OPTIONS", "opt-1@pbx", 1, "", nil)
	pbx.wait(200, 2*time.Second)
}
