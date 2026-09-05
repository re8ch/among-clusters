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

type AdvertisedService struct {
	Name          string   `json:"name"`
	Namespace     string   `json:"namespace"`
	ServiceClass  string   `json:"serviceClass"`
	Protocol      string   `json:"protocol"`
	Port          int32    `json:"port"`
	TargetPeers   []string `json:"targetPeers"`
	TTLSeconds    int64    `json:"ttlSeconds"`
	PolicyRef     string   `json:"policyRef"`
	Generation    int64    `json:"generation"`
	GatewayTarget string   `json:"-"`
}

type ServiceSnapshot struct {
	Services []AdvertisedService `json:"services"`
}

type AccessRule struct {
	APIGroups []string `json:"apiGroups"`
	Resources []string `json:"resources"`
	Verbs     []string `json:"verbs"`
}
type GrantInstruction struct {
	Name             string       `json:"name"`
	Tenant           string       `json:"tenant"`
	PeerRef          string       `json:"peerRef"`
	AdvertisementRef string       `json:"advertisementRef"`
	Generation       int64        `json:"generation"`
	Scope            string       `json:"scope"`
	Namespaces       []string     `json:"namespaces"`
	Rules            []AccessRule `json:"rules"`
	ExpiresAt        time.Time    `json:"expiresAt"`
	Revoked          bool         `json:"revoked"`
	ProxyURL         string       `json:"proxyURL"`
}
type CredentialPayload struct {
	Token                string    `json:"token"`
	CertificateAuthority string    `json:"certificateAuthority"`
	Server               string    `json:"server"`
	TLSServerName        string    `json:"tlsServerName"`
	ExpiresAt            time.Time `json:"expiresAt"`
}
type GrantSnapshot struct {
	Grants []GrantInstruction `json:"grants"`
}
type GrantFulfillment struct {
	GrantRef      string    `json:"grantRef"`
	CredentialRef string    `json:"credentialRef"`
	RenewedAt     time.Time `json:"renewedAt"`
}

type LinkObservation struct {
	LinkRef         string    `json:"linkRef"`
	PeerRef         string    `json:"peerRef"`
	Ready           bool      `json:"ready"`
	LatencyMillis   int64     `json:"latencyMillis,omitempty"`
	Reason          string    `json:"reason,omitempty"`
	LastHandshakeAt time.Time `json:"lastHandshakeAt,omitempty"`
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
