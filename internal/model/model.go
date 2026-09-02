package model

import (
	"encoding/json"
	"time"
)

type ControlMessage struct {
	Issuer     string          `json:"issuer"`
	Audience   string          `json:"audience"`
	Generation uint64          `json:"generation"`
	IssuedAt   time.Time       `json:"issuedAt"`
	ExpiresAt  time.Time       `json:"expiresAt"`
	Nonce      string          `json:"nonce"`
	Type       string          `json:"type"`
	Payload    json.RawMessage `json:"payload"`
	Signature  string          `json:"signature"`
}

type IdentityRegistration struct {
	ClusterID        string   `json:"clusterID"`
	Tenant           string   `json:"tenant"`
	TrustDomain      string   `json:"trustDomain"`
	SPIFFEID         string   `json:"spiffeID"`
	BundleDigest     string   `json:"bundleDigest"`
	PublicKey        string   `json:"publicKey"`
	Capabilities     []string `json:"capabilities,omitempty"`
	GatewayEndpoints []string `json:"gatewayEndpoints,omitempty"`
}

type Invitation struct {
	ID           string    `json:"id"`
	Tenant       string    `json:"tenant"`
	ExpiresAt    time.Time `json:"expiresAt"`
	Capabilities []string  `json:"capabilities,omitempty"`
	TokenHash    string    `json:"-"`
	UsedAt       time.Time `json:"-"`
}
type InvitationAcceptance struct {
	Token    string               `json:"token"`
	Identity IdentityRegistration `json:"identity"`
	Proof    string               `json:"proof"`
}

type BundleConfirmation struct {
	PeerRef      string `json:"peerRef"`
	BundleDigest string `json:"bundleDigest"`
}

type Counts struct {
	NodesReady  int `json:"nodesReady"`
	NodesTotal  int `json:"nodesTotal"`
	PodsRunning int `json:"podsRunning"`
	PodsTotal   int `json:"podsTotal"`
	Namespaces  int `json:"namespaces"`
	Services    int `json:"services"`
}

type ServiceObservation struct {
	Name          string    `json:"name"`
	Healthy       bool      `json:"healthy"`
	LatencyMillis int64     `json:"latencyMillis,omitempty"`
	ObservedAt    time.Time `json:"observedAt"`
}

type Heartbeat struct {
	ClusterID         string               `json:"clusterID"`
	Sequence          uint64               `json:"sequence"`
	ObservedAt        time.Time            `json:"observedAt"`
	KubernetesVersion string               `json:"kubernetesVersion"`
	Counts            Counts               `json:"counts"`
	Services          []ServiceObservation `json:"services,omitempty"`
}

type Event struct {
	ClusterID  string            `json:"clusterID"`
	Sequence   uint64            `json:"sequence"`
	OccurredAt time.Time         `json:"occurredAt"`
	Type       string            `json:"type"`
	Subject    string            `json:"subject,omitempty"`
	Details    map[string]string `json:"details,omitempty"`
}

type Envelope struct {
	Timestamp time.Time `json:"timestamp"`
	Sequence  uint64    `json:"sequence"`
	Body      []byte    `json:"body"`
	Signature string    `json:"signature"`
}
