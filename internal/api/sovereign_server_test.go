package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"github.com/re8ch/among-clusters/internal/model"
	"net/http"
	"net/http/httptest"
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
