package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"
)

type exportRoute struct {
	ServiceIdentity string   `json:"serviceIdentity"`
	Target          string   `json:"target"`
	TargetPeers     []string `json:"targetPeers"`
}
type importRoute struct {
	Listen           string `json:"listen"`
	Endpoint         string `json:"endpoint"`
	ServiceIdentity  string `json:"serviceIdentity"`
	ExpectedSPIFFEID string `json:"expectedSPIFFEID"`
	SessionOnly      bool   `json:"sessionOnly"`
}
type peerSession struct {
	Endpoint         string `json:"endpoint"`
	ExpectedSPIFFEID string `json:"expectedSPIFFEID"`
}
type sessionRegistry struct {
	mu       sync.RWMutex
	sessions map[string][]*quic.Conn
}

const sessionHeartbeatIdentity = "among-clusters.internal/session-heartbeat"

func newSessionRegistry() *sessionRegistry {
	return &sessionRegistry{sessions: map[string][]*quic.Conn{}}
}
func canonicalIdentity(identity string) string { return strings.TrimSuffix(identity, "/") }
func (r *sessionRegistry) put(identity string, connection *quic.Conn) {
	r.mu.Lock()
	key := canonicalIdentity(identity)
	r.sessions[key] = append(r.sessions[key], connection)
	r.mu.Unlock()
}
func (r *sessionRegistry) get(identity string) *quic.Conn {
	r.mu.RLock()
	defer r.mu.RUnlock()
	connections := r.sessions[canonicalIdentity(identity)]
	if len(connections) > 0 {
		return connections[0]
	}
	return nil
}
func (r *sessionRegistry) remove(identity string, connection *quic.Conn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := canonicalIdentity(identity)
	connections := r.sessions[key]
	for i, candidate := range connections {
		if candidate == connection {
			connections = append(connections[:i], connections[i+1:]...)
			break
		}
	}
	if len(connections) == 0 {
		delete(r.sessions, key)
	} else {
		r.sessions[key] = connections
	}
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	cert, roots := credentials()
	var exports []exportRoute
	var imports []importRoute
	var sessions []peerSession
	peerIdentities := map[string][]string{}
	if json.Unmarshal([]byte(env("EXPORTS_JSON", "[]")), &exports) != nil || json.Unmarshal([]byte(env("IMPORTS_JSON", "[]")), &imports) != nil || json.Unmarshal([]byte(env("PEER_SESSIONS_JSON", "[]")), &sessions) != nil || json.Unmarshal([]byte(env("PEER_IDENTITIES_JSON", "{}")), &peerIdentities) != nil {
		log.Fatal("invalid service routing configuration")
	}
	routes := map[string]exportRoute{}
	for _, route := range exports {
		if route.ServiceIdentity == "" || route.Target == "" {
			log.Fatal("invalid export route")
		}
		routes[route.ServiceIdentity] = route
	}
	registry := newSessionRegistry()
	if os.Getenv("LISTENER_ENABLED") == "true" {
		go serveQUIC(ctx, cert, roots, routes, peerIdentities, registry)
	}
	for _, session := range sessions {
		if session.Endpoint == "" || session.ExpectedSPIFFEID == "" {
			log.Fatal("peer session requires endpoint and expectedSPIFFEID")
		}
		session := session
		go maintainSession(ctx, cert, roots, routes, peerIdentities, registry, session)
	}
	for _, route := range imports {
		route := route
		go serveImport(ctx, cert, roots, registry, route)
	}
	<-ctx.Done()
}

func credentials() (tls.Certificate, *x509.CertPool) {
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
		log.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(bundle) {
		log.Fatal("invalid peer bundle")
	}
	return cert, roots
}
func tlsConfig(cert tls.Certificate, roots *x509.CertPool, expected string, server bool) *tls.Config {
	c := &tls.Config{MinVersion: tls.VersionTLS13, NextProtos: []string{"among-clusters/1"}}
	if server {
		c.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return currentCertificate(cert) }
		c.ClientAuth = tls.RequireAndVerifyClientCert
		c.ClientCAs = roots
		return c
	}
	c.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return currentCertificate(cert) }
	c.InsecureSkipVerify = true
	c.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return errors.New("peer certificate missing")
		}
		inter := x509.NewCertPool()
		for _, certificate := range state.PeerCertificates[1:] {
			inter.AddCert(certificate)
		}
		if _, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			return err
		}
		if len(state.PeerCertificates[0].URIs) != 1 || strings.TrimSuffix(state.PeerCertificates[0].URIs[0].String(), "/") != strings.TrimSuffix(expected, "/") {
			return errors.New("peer SPIFFE identity mismatch")
		}
		return nil
	}
	return c
}
func currentCertificate(fallback tls.Certificate) (*tls.Certificate, error) {
	certificate, err := tls.LoadX509KeyPair(env("TLS_CERT_FILE", "/identity/tls.crt"), env("TLS_KEY_FILE", "/identity/tls.key"))
	if err != nil {
		return &fallback, nil
	}
	return &certificate, nil
}
func serveQUIC(ctx context.Context, cert tls.Certificate, roots *x509.CertPool, routes map[string]exportRoute, peerIdentities map[string][]string, registry *sessionRegistry) {
	listener, err := quic.ListenAddr(env("LISTEN_ADDRESS", ":8443"), tlsConfig(cert, roots, "", true), &quic.Config{KeepAlivePeriod: 15 * time.Second})
	if err != nil {
		log.Fatal(err)
	}
	for {
		connection, err := listener.Accept(ctx)
		if err != nil {
			return
		}
		go func() {
			defer connection.CloseWithError(0, "closed")
			certificates := connection.ConnectionState().TLS.PeerCertificates
			if len(certificates) == 0 || len(certificates[0].URIs) != 1 {
				return
			}
			peerIdentity := canonicalIdentity(certificates[0].URIs[0].String())
			handleConnection(ctx, connection, peerIdentity, routes, peerIdentities, registry)
		}()
	}
}

func handleConnection(ctx context.Context, connection *quic.Conn, peerIdentity string, routes map[string]exportRoute, peerIdentities map[string][]string, registry *sessionRegistry) {
	registry.put(peerIdentity, connection)
	defer registry.remove(peerIdentity, connection)
	heartbeatCtx, cancelHeartbeat := context.WithCancel(ctx)
	defer cancelHeartbeat()
	go maintainConnectionHeartbeat(heartbeatCtx, connection)
	for {
		stream, err := connection.AcceptStream(ctx)
		if err != nil {
			log.Printf("peer session %s closed: %v", peerIdentity, err)
			return
		}
		go handleExport(stream, routes, peerIdentities, peerIdentity)
	}
}

func maintainConnectionHeartbeat(ctx context.Context, connection *quic.Conn) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			stream, err := connection.OpenStreamSync(ctx)
			if err != nil {
				connection.CloseWithError(1, "session heartbeat failed")
				return
			}
			identity := []byte(sessionHeartbeatIdentity)
			deadline := time.Now().Add(5 * time.Second)
			_ = stream.SetDeadline(deadline)
			if binary.Write(stream, binary.BigEndian, uint16(len(identity))) != nil {
				stream.CancelWrite(1)
				connection.CloseWithError(1, "session heartbeat failed")
				return
			}
			if _, err = stream.Write(identity); err != nil {
				stream.CancelWrite(1)
				connection.CloseWithError(1, "session heartbeat failed")
				return
			}
			ack := []byte{0}
			if _, err = io.ReadFull(stream, ack); err != nil || ack[0] != 1 {
				stream.CancelRead(1)
				connection.CloseWithError(1, "session heartbeat unacknowledged")
				return
			}
			stream.Close()
		}
	}
}

func maintainSession(ctx context.Context, cert tls.Certificate, roots *x509.CertPool, routes map[string]exportRoute, peerIdentities map[string][]string, registry *sessionRegistry, session peerSession) {
	for ctx.Err() == nil {
		connection, err := quic.DialAddr(ctx, strings.TrimPrefix(session.Endpoint, "quic://"), tlsConfig(cert, roots, session.ExpectedSPIFFEID, false), &quic.Config{KeepAlivePeriod: 15 * time.Second, HandshakeIdleTimeout: 5 * time.Second})
		if err != nil {
			log.Printf("peer session %s: %v", session.ExpectedSPIFFEID, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(3 * time.Second):
			}
			continue
		}
		handleConnection(ctx, connection, session.ExpectedSPIFFEID, routes, peerIdentities, registry)
		connection.CloseWithError(0, "reconnecting")
	}
}

type readWriteCloser interface {
	io.Reader
	io.Writer
	io.Closer
}

func handleExport(stream readWriteCloser, routes map[string]exportRoute, peerIdentities map[string][]string, peerIdentity string) {
	defer stream.Close()
	var size uint16
	if binary.Read(stream, binary.BigEndian, &size) != nil || size == 0 || size > 2048 {
		return
	}
	identity := make([]byte, size)
	if _, err := io.ReadFull(stream, identity); err != nil {
		return
	}
	if string(identity) == sessionHeartbeatIdentity {
		_, _ = stream.Write([]byte{1})
		return
	}
	resolved := make(map[string]exportRoute, len(routes))
	for key, value := range routes {
		resolved[key] = value
	}
	for _, route := range readExportFile(env("EXPORTS_FILE", "/routes/exports.json")) {
		resolved[route.ServiceIdentity] = route
	}
	route, ok := resolved[string(identity)]
	if !ok || !routeAllowsIdentity(route, peerIdentities, peerIdentity) {
		return
	}
	upstream, err := net.DialTimeout("tcp", route.Target, 5*time.Second)
	if err != nil {
		return
	}
	defer upstream.Close()
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(upstream, stream)
		if tcp, ok := upstream.(*net.TCPConn); ok {
			tcp.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() { io.Copy(stream, upstream); stream.Close(); done <- struct{}{} }()
	<-done
}
func routeAllowsIdentity(route exportRoute, peerIdentities map[string][]string, identity string) bool {
	identity = strings.TrimSuffix(identity, "/")
	for _, peer := range route.TargetPeers {
		for _, allowed := range peerIdentities[peer] {
			if strings.TrimSuffix(allowed, "/") == identity {
				return true
			}
		}
	}
	return false
}
func readExportFile(path string) []exportRoute {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var routes []exportRoute
	if json.Unmarshal(data, &routes) != nil {
		return nil
	}
	return routes
}
func serveImport(ctx context.Context, cert tls.Certificate, roots *x509.CertPool, registry *sessionRegistry, route importRoute) {
	listener, err := net.Listen("tcp", route.Listen)
	if err != nil {
		log.Printf("import %s: %v", route.ServiceIdentity, err)
		return
	}
	go func() { <-ctx.Done(); listener.Close() }()
	for {
		client, err := listener.Accept()
		if err != nil {
			return
		}
		go proxyImport(ctx, client, cert, roots, registry, route)
	}
}
func proxyImport(ctx context.Context, client net.Conn, cert tls.Certificate, roots *x509.CertPool, registry *sessionRegistry, route importRoute) {
	defer client.Close()
	connection := registry.get(route.ExpectedSPIFFEID)
	owned := false
	if connection == nil {
		if route.SessionOnly {
			log.Printf("import %s: authenticated peer session unavailable", route.ServiceIdentity)
			return
		}
		if route.Endpoint == "" {
			log.Printf("import %s: no authenticated session or fallback endpoint", route.ServiceIdentity)
			return
		}
		var err error
		connection, err = quic.DialAddr(ctx, strings.TrimPrefix(route.Endpoint, "quic://"), tlsConfig(cert, roots, route.ExpectedSPIFFEID, false), &quic.Config{HandshakeIdleTimeout: 5 * time.Second})
		if err != nil {
			log.Printf("import %s dial: %v", route.ServiceIdentity, err)
			return
		}
		owned = true
	}
	if owned {
		defer connection.CloseWithError(0, "closed")
	}
	stream, err := connection.OpenStreamSync(ctx)
	if err != nil {
		log.Printf("import %s stream: %v", route.ServiceIdentity, err)
		return
	}
	identity := []byte(route.ServiceIdentity)
	if binary.Write(stream, binary.BigEndian, uint16(len(identity))) != nil {
		return
	}
	if _, err = stream.Write(identity); err != nil {
		return
	}
	done := make(chan struct{}, 2)
	go func() { io.Copy(stream, client); stream.Close(); done <- struct{}{} }()
	go func() { io.Copy(client, stream); done <- struct{}{} }()
	<-done
}
func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
