package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/re8ch/among-clusters/internal/model"
	"testing"
	"time"
)

func identity(t *testing.T) model.IdentityRegistration {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	return model.IdentityRegistration{ClusterID: "customer-a", Tenant: "tenant-a", TrustDomain: "customer.example", SPIFFEID: "spiffe://customer.example/cluster/customer-a", BundleDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", PublicKey: base64.RawStdEncoding.EncodeToString(pub), GatewayEndpoints: []string{"quic://gateway.customer.example:8443"}}
}
func TestValidateIdentity(t *testing.T) {
	if err := ValidateIdentity(identity(t)); err != nil {
		t.Fatal(err)
	}
	v := identity(t)
	v.SPIFFEID = "spiffe://evil/cluster/customer-a"
	if ValidateIdentity(v) == nil {
		t.Fatal("mismatched trust domain accepted")
	}
}
func TestControlMessageRejectsReplayAndExpiry(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	now := time.Now().UTC()
	m := model.ControlMessage{Issuer: "spiffe://a/cluster/a", Audience: "hub", Generation: 2, IssuedAt: now, ExpiresAt: now.Add(time.Minute), Nonce: "n1", Type: "service.publish", Payload: json.RawMessage(`{}`)}
	if err := Sign(&m, priv); err != nil {
		t.Fatal(err)
	}
	if err := Verify(m, pub, "hub", now, 1, nil); err != nil {
		t.Fatal(err)
	}
	if Verify(m, pub, "hub", now, 2, nil) == nil {
		t.Fatal("replayed generation accepted")
	}
	if Verify(m, pub, "hub", now.Add(2*time.Minute), 1, nil) == nil {
		t.Fatal("expired message accepted")
	}
}
