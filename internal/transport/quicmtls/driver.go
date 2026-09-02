package quicmtls

import (
	"context"
	"crypto/tls"
	"errors"
	"github.com/quic-go/quic-go"
	"github.com/re8ch/among-clusters/internal/transport"
	"net/url"
	"sync"
	"time"
)

type Driver struct {
	TLS      *tls.Config
	mu       sync.Mutex
	sessions map[string]*quic.Conn
}

func New(config *tls.Config) *Driver { return &Driver{TLS: config, sessions: map[string]*quic.Conn{}} }
func (d *Driver) Name() string       { return "quic-mtls" }
func (d *Driver) Capabilities() []transport.Capability {
	return []transport.Capability{transport.CapabilityService}
}
func (d *Driver) endpoint(peer transport.Peer) (string, error) {
	if len(peer.Endpoints) == 0 {
		return "", errors.New("NATUnreachable")
	}
	u, err := url.Parse(peer.Endpoints[0])
	if err != nil || u.Scheme != "quic" || u.Host == "" {
		return "", errors.New("invalid QUIC endpoint")
	}
	return u.Host, nil
}
func (d *Driver) Probe(ctx context.Context, peer transport.Peer) (transport.Observation, error) {
	start := time.Now()
	address, err := d.endpoint(peer)
	if err != nil {
		return transport.Observation{Reason: err.Error(), ObservedAt: time.Now()}, err
	}
	session, err := quic.DialAddr(ctx, address, d.TLS, &quic.Config{HandshakeIdleTimeout: 5 * time.Second})
	if err != nil {
		return transport.Observation{Reason: "TransportError", ObservedAt: time.Now()}, err
	}
	_ = session.CloseWithError(0, "probe")
	return transport.Observation{Ready: true, Latency: time.Since(start), ObservedAt: time.Now()}, nil
}
func (d *Driver) Establish(ctx context.Context, peer transport.Peer) error {
	address, err := d.endpoint(peer)
	if err != nil {
		return err
	}
	session, err := quic.DialAddr(ctx, address, d.TLS, &quic.Config{KeepAlivePeriod: 15 * time.Second})
	if err != nil {
		return err
	}
	d.mu.Lock()
	d.sessions[peer.ID] = session
	d.mu.Unlock()
	return nil
}
func (d *Driver) Close(_ context.Context, id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if s := d.sessions[id]; s != nil {
		delete(d.sessions, id)
		return s.CloseWithError(0, "peer closed")
	}
	return nil
}
func (d *Driver) PublishService(context.Context, transport.Service) error { return nil }
func (d *Driver) WithdrawService(context.Context, string) error           { return nil }
func (d *Driver) Observe(_ context.Context, id string) (transport.Observation, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	_, ok := d.sessions[id]
	return transport.Observation{Ready: ok, ObservedAt: time.Now()}, nil
}
