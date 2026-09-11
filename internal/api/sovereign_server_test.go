package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/re8ch/among-clusters/internal/model"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestInvitationIsOneTimeAndTenantBound(t *testing.T) {
	store := NewMemorySovereignStore()
	now := time.Now().UTC()
	server := &SovereignServer{Store: store, AdminToken: "admin", Now: func() time.Time { return now }}
	body := bytes.NewBufferString(`{"tenant":"tenant-a","ttlSeconds":300}`)
	request := httptest.NewRequest(http.MethodPost, "/v1/invitations", body)
	request.Header.Set("Authorization", "Bearer admin")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != 201 {
		t.Fatalf("create: %d %s", response.Code, response.Body.String())
	}
	var invitation map[string]any
	_ = json.Unmarshal(response.Body.Bytes(), &invitation)
	pub, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	accept := model.InvitationAcceptance{Token: invitation["token"].(string), Identity: model.IdentityRegistration{ClusterID: "c1", Tenant: "tenant-a", TrustDomain: "customer.example", SPIFFEID: "spiffe://customer.example/cluster/c1", BundleDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", PublicKey: base64.RawStdEncoding.EncodeToString(pub)}}
	identityBody, _ := json.Marshal(accept.Identity)
	accept.Proof = base64.RawStdEncoding.EncodeToString(ed25519.Sign(privateKey, identityBody))
	payload, _ := json.Marshal(accept)
	path := "/v1/invitations/" + invitation["invitationID"].(string) + "/accept"
	first := httptest.NewRecorder()
	server.Handler().ServeHTTP(first, httptest.NewRequest(http.MethodPost, path, bytes.NewReader(payload)))
	if first.Code != 201 {
		t.Fatalf("accept: %d %s", first.Code, first.Body.String())
	}
	second := httptest.NewRecorder()
	server.Handler().ServeHTTP(second, httptest.NewRequest(http.MethodPost, path, bytes.NewReader(payload)))
	if second.Code != 401 {
		t.Fatalf("reused invitation returned %d", second.Code)
	}
}
func TestInvitationRequiresAdmin(t *testing.T) {
	server := &SovereignServer{Store: NewMemorySovereignStore(), AdminToken: "admin"}
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/invitations", bytes.NewBufferString(`{"tenant":"x"}`)))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("got %d", response.Code)
	}
}

func TestCapabilityRejectionDoesNotConsumeInvitation(t *testing.T) {
	store := NewMemorySovereignStore()
	now := time.Now().UTC()
	invitation := model.Invitation{ID: "invite", Tenant: "tenant-a", TokenHash: "hash", Capabilities: []string{"quic-mtls"}, ExpiresAt: now.Add(time.Minute)}
	if err := store.CreateInvitation(context.Background(), invitation); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeInvitation(context.Background(), "invite", "hash", "tenant-a", "c1", []string{"service"}, now); err == nil {
		t.Fatal("uninvited capability was accepted")
	}
	if _, err := store.ConsumeInvitation(context.Background(), "invite", "hash", "tenant-a", "c1", []string{"quic-mtls"}, now); err != nil {
		t.Fatalf("valid retry was consumed by rejected attempt: %v", err)
	}
}

func TestOnboardingLinkNeedsOnlyRegionAndClusterAndConsumesOnce(t *testing.T) {
	store := NewMemorySovereignStore()
	now := time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC)
	server := &SovereignServer{Store: store, AdminToken: "admin", Now: func() time.Time { return now }, Onboarding: OnboardingConfig{PublicEndpoint: "https://among.example", Tenant: "byoc-pilot", ProviderSPIFFEID: "spiffe://provider/cluster/re8ch", ProviderBundleDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ProviderQUICEndpoint: "quic://203.0.113.8:8443", ImageDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", ChartVersion: "0.3.24"}}
	request := httptest.NewRequest(http.MethodPost, "/v1/onboarding-links", bytes.NewBufferString(`{"clusterID":"sijie","region":"cn-east"}`))
	request.Header.Set("Authorization", "Bearer admin")
	created := httptest.NewRecorder()
	server.Handler().ServeHTTP(created, request)
	if created.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", created.Code, created.Body.String())
	}
	var result map[string]any
	_ = json.Unmarshal(created.Body.Bytes(), &result)
	claimURL := result["claimURL"].(string)
	path := strings.TrimPrefix(claimURL, "https://among.example")
	first := httptest.NewRecorder()
	server.Handler().ServeHTTP(first, httptest.NewRequest(http.MethodPost, path, nil))
	if first.Code != http.StatusOK || !strings.Contains(first.Body.String(), "CLUSTER_ID='sijie'") {
		t.Fatalf("consume: %d %s", first.Code, first.Body.String())
	}
	second := httptest.NewRecorder()
	server.Handler().ServeHTTP(second, httptest.NewRequest(http.MethodPost, path, nil))
	if second.Code != http.StatusGone {
		t.Fatalf("reuse returned %d", second.Code)
	}
}

func TestClusterBoundInvitationRejectsDifferentIdentity(t *testing.T) {
	store := NewMemorySovereignStore()
	now := time.Now().UTC()
	invitation := model.Invitation{ID: "bound", Tenant: "byoc-pilot", ClusterID: "sijie", TokenHash: "hash", ExpiresAt: now.Add(time.Minute)}
	if err := store.CreateInvitation(context.Background(), invitation); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ConsumeInvitation(context.Background(), "bound", "hash", "byoc-pilot", "attacker", nil, now); err == nil || err.Error() != "cluster mismatch" {
		t.Fatalf("unexpected error: %v", err)
	}
}
