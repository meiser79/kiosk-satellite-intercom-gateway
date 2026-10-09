// Command ks-intercom-gateway rings Kiosk Satellite intercoms when a SIP
// account on an Asterisk PBX is called.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"ks-intercom-gateway/src/gateway"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if n, err := strconv.Atoi(os.Getenv(k)); err == nil && n > 0 {
		return n
	}
	return def
}

func selfSigned() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "ks-intercom-gateway"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func main() {
	logs := &gateway.LogBuffer{}
	log.SetOutput(io.MultiWriter(os.Stderr, logs))
	log.SetFlags(log.Ltime)

	_, errOpt := os.Stat("/data/options.json")
	addon := errOpt == nil // running as a Home Assistant add-on

	dir := env("CONFIG_DIR", "/config")
	uiAddr := env("UI_ADDR", ":8099")
	allow := env("UI_ALLOW", "")
	if addon && allow == "" {
		allow = "172.30.32.2,127.0.0.1" // the ingress gateway only
	}
	sigPort, sigTLSPort := envInt("SIGNAL_PORT", 2325), envInt("SIGNAL_TLS_PORT", 2326)

	store, err := gateway.OpenStore(dir)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	mgr := gateway.NewManager(store, sigPort, sigTLSPort)
	if err := mgr.Reload(store.Get()); err != nil {
		log.Printf("start: %v", err)
	}

	// Callback listeners for the kiosks' answers, plain and TLS.
	sig := mgr.SignalHandler()
	go func() {
		log.Printf("signal listener on :%d", sigPort)
		log.Fatal(http.ListenAndServe(":"+strconv.Itoa(sigPort), sig))
	}()
	if cert, err := selfSigned(); err == nil {
		go func() {
			srv := &http.Server{Addr: ":" + strconv.Itoa(sigTLSPort), Handler: sig,
				TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}}}
			log.Printf("signal listener (TLS) on :%d", sigTLSPort)
			log.Fatal(srv.ListenAndServeTLS("", ""))
		}()
	}

	ui := gateway.NewUI(store, mgr, logs, allow, os.Getenv("UI_USER"), os.Getenv("UI_PASS"))
	srv := &http.Server{Addr: uiAddr, Handler: ui}
	go func() {
		log.Printf("ks-intercom-gateway %s, UI on %s, config in %s", gateway.Version, uiAddr, dir)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Printf("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	mgr.Close()
}
