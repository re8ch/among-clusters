package transport

import (
	"context"
	"time"
)

type Capability string

const (
	CapabilityService Capability = "service"
	CapabilityRoute   Capability = "route"
)

type Peer struct {
	ID, SPIFFEID, BundleDigest string
	Endpoints                  []string
}
type Service struct {
	Identity, Protocol, Target string
	Port                       int
}
type Observation struct {
	Ready      bool
	Latency    time.Duration
	Reason     string
	ObservedAt time.Time
}
type Driver interface {
	Name() string
	Capabilities() []Capability
	Probe(context.Context, Peer) (Observation, error)
	Establish(context.Context, Peer) error
	Close(context.Context, string) error
	PublishService(context.Context, Service) error
	WithdrawService(context.Context, string) error
	Observe(context.Context, string) (Observation, error)
}
