package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"github.com/quic-go/quic-go"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	if os.Getenv("LISTENER_ENABLED") != "true" {
		log.Print("QUIC listener disabled")
		select {}
	}
	var cert tls.Certificate
	var err error
	for i := 0; i < 60; i++ {
		cert, err = tls.LoadX509KeyPair(env("TLS_CERT_FILE", "/identity/tls.crt"), env("TLS_KEY_FILE", "/identity/tls.key"))
		if err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		log.Fatal(err)
	}
	bundle, err := os.ReadFile(env("PEER_BUNDLE_FILE", "/peer-bundles/ca.crt"))
	if err != nil {
		log.Fatalf("trusted peer bundle is required when the listener is enabled: %v", err)
	}
	peerRoots := x509.NewCertPool()
	if !peerRoots.AppendCertsFromPEM(bundle) {
		log.Fatal("trusted peer bundle does not contain a PEM certificate")
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    peerRoots,
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"among-clusters/1"},
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 || len(state.PeerCertificates[0].URIs) != 1 {
				return errors.New("peer certificate must contain exactly one SPIFFE identity")
			}
			identity := state.PeerCertificates[0].URIs[0]
			if identity.Scheme != "spiffe" || identity.Host == "" {
				return errors.New("peer certificate identity is not SPIFFE-compatible")
			}
			return nil
		},
	}
	listener, err := quic.ListenAddr(env("LISTEN_ADDRESS", ":8443"), config, &quic.Config{KeepAlivePeriod: 15 * time.Second})
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	for {
		connection, err := listener.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("accept: %v", err)
			continue
		}
		go func(c *quic.Conn) { defer c.CloseWithError(0, "closed"); <-ctx.Done() }(connection)
	}
}
func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
