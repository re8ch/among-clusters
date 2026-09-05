package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/re8ch/among-clusters/internal/credential"
	"github.com/re8ch/among-clusters/internal/model"
	"github.com/re8ch/among-clusters/internal/protocol"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestSignedEncryptedCredentialIsStoredBehindOpaqueReference(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	identity := model.IdentityRegistration{ClusterID: "qwen", Tenant: "pilot", SPIFFEID: "spiffe://qwen.test/cluster/qwen", PublicKey: base64.RawStdEncoding.EncodeToString(public)}
	hub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { json.NewEncoder(w).Encode(identity) }))
	defer hub.Close()
	xkey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	client := fake.NewSimpleClientset()
	b := &broker{client: client, namespace: "broker", hub: hub.URL, private: xkey, generations: map[string]uint64{}, http: hub.Client()}
	payload := model.CredentialPayload{Token: "sensitive-token", CertificateAuthority: "ca", Server: "https://import", ExpiresAt: time.Now().Add(time.Hour)}
	sealed, _ := credential.Encrypt(xkey.PublicKey().Bytes(), payload)
	raw, _ := json.Marshal(map[string]any{"tenant": "pilot", "clusterID": "qwen", "grantRef": "admin", "envelope": sealed})
	now := time.Now().UTC()
	message := model.ControlMessage{Issuer: identity.SPIFFEID, Audience: "credential-broker", Generation: 1, IssuedAt: now, ExpiresAt: now.Add(time.Minute), Nonce: "one", Type: "credential.store", Payload: raw}
	protocol.Sign(&message, private)
	body, _ := json.Marshal(message)
	request := httptest.NewRequest(http.MethodPost, "/v1/credentials", bytes.NewReader(body))
	response := httptest.NewRecorder()
	b.store(response, request)
	if response.Code != 201 {
		t.Fatalf("%d %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "sensitive-token") {
		t.Fatal("credential leaked in response")
	}
	secret, err := client.CoreV1().Secrets("broker").Get(request.Context(), "pilot-admin", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(secret.Data["envelope.json"], []byte("sensitive-token")) {
		t.Fatal("plaintext credential stored")
	}
}

func TestKubernetesProxyRequiresMatchingOpaqueReference(t *testing.T) {
	xkey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	b := &broker{client: fake.NewSimpleClientset(), namespace: "broker", private: xkey}
	for _, test := range []struct {
		name, authorization string
		want                int
	}{
		{name: "missing", want: http.StatusUnauthorized},
		{name: "wrong grant", authorization: "Bearer credential://among-clusters/pilot/other", want: http.StatusUnauthorized},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/k8s/pilot/admin/api", nil)
			request.Header.Set("Authorization", test.authorization)
			response := httptest.NewRecorder()
			b.proxy(response, request)
			if response.Code != test.want {
				t.Fatalf("status=%d, want %d", response.Code, test.want)
			}
		})
	}
}
