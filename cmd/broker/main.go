package main

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/re8ch/among-clusters/internal/credential"
	"github.com/re8ch/among-clusters/internal/model"
	"github.com/re8ch/among-clusters/internal/protocol"
	"io"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type broker struct {
	client         kubernetes.Interface
	namespace, hub string
	private        *ecdh.PrivateKey
	mu             sync.Mutex
	generations    map[string]uint64
	http           *http.Client
}

func main() {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		log.Fatal(err)
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Fatal(err)
	}
	b := &broker{client: client, namespace: env("CREDENTIAL_NAMESPACE", "credential-broker"), hub: strings.TrimSuffix(must("HUB_ENDPOINT"), "/"), generations: map[string]uint64{}, http: &http.Client{Timeout: 10 * time.Second}}
	if err = b.loadKey(context.Background()); err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	mux.HandleFunc("GET /v1/public-key", b.publicKey)
	mux.HandleFunc("POST /v1/credentials", b.store)
	mux.HandleFunc("POST /v1/credentials/revoke", b.revoke)
	mux.HandleFunc("/k8s/", b.proxy)
	log.Fatal(http.ListenAndServe(":8080", mux))
}
func (b *broker) revoke(w http.ResponseWriter, r *http.Request) {
	var message model.ControlMessage
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&message) != nil {
		http.Error(w, "invalid message", 400)
		return
	}
	var meta struct{ Tenant, ClusterID, GrantRef string }
	if json.Unmarshal(message.Payload, &meta) != nil {
		http.Error(w, "invalid payload", 400)
		return
	}
	identity, err := b.identity(r.Context(), meta.Tenant, meta.ClusterID)
	if err != nil {
		http.Error(w, "unknown identity", 401)
		return
	}
	key, err := base64.RawStdEncoding.DecodeString(identity.PublicKey)
	if err != nil || message.Issuer != identity.SPIFFEID || message.Type != "credential.revoke" || protocol.Verify(message, ed25519.PublicKey(key), "credential-broker", time.Now().UTC(), 0, nil) != nil {
		http.Error(w, "unauthorized", 401)
		return
	}
	err = b.client.CoreV1().Secrets(b.namespace).Delete(r.Context(), resourceName(meta.Tenant+"-"+meta.GrantRef), metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "revoke failed", 500)
		return
	}
	w.WriteHeader(204)
}
func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func must(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("%s required", k)
	}
	return v
}
func (b *broker) loadKey(ctx context.Context) error {
	s, err := b.client.CoreV1().Secrets(b.namespace).Get(ctx, "among-clusters-broker-key", metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		key, e := ecdh.X25519().GenerateKey(rand.Reader)
		if e != nil {
			return e
		}
		s = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "among-clusters-broker-key", Namespace: b.namespace, Labels: map[string]string{"app.kubernetes.io/managed-by": "among-clusters"}}, Data: map[string][]byte{"private-key": key.Bytes()}}
		s, err = b.client.CoreV1().Secrets(b.namespace).Create(ctx, s, metav1.CreateOptions{})
	}
	if err != nil {
		return err
	}
	b.private, err = ecdh.X25519().NewPrivateKey(s.Data["private-key"])
	return err
}
func (b *broker) publicKey(w http.ResponseWriter, _ *http.Request) {
	write(w, 200, map[string]string{"publicKey": base64.RawStdEncoding.EncodeToString(b.private.PublicKey().Bytes())})
}
func (b *broker) identity(ctx context.Context, tenant, id string) (model.IdentityRegistration, error) {
	r, err := b.http.Get(b.hub + "/v1/identities/" + url.PathEscape(tenant) + "/" + url.PathEscape(id))
	if err != nil {
		return model.IdentityRegistration{}, err
	}
	defer r.Body.Close()
	var v model.IdentityRegistration
	if r.StatusCode != 200 {
		return v, fmt.Errorf("identity lookup returned %s", r.Status)
	}
	err = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&v)
	return v, err
}
func (b *broker) store(w http.ResponseWriter, r *http.Request) {
	var m model.ControlMessage
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&m) != nil {
		http.Error(w, "invalid message", 400)
		return
	}
	var meta struct {
		Tenant, ClusterID, GrantRef string
		Envelope                    credential.Envelope
	}
	if json.Unmarshal(m.Payload, &meta) != nil || meta.Tenant == "" || meta.ClusterID == "" || meta.GrantRef == "" {
		http.Error(w, "invalid payload", 400)
		return
	}
	identity, err := b.identity(r.Context(), meta.Tenant, meta.ClusterID)
	if err != nil {
		http.Error(w, "unknown identity", 401)
		return
	}
	key, err := base64.RawStdEncoding.DecodeString(identity.PublicKey)
	if err != nil {
		http.Error(w, "invalid identity", 401)
		return
	}
	b.mu.Lock()
	last := b.generations[identity.SPIFFEID]
	b.mu.Unlock()
	if m.Issuer != identity.SPIFFEID || m.Type != "credential.store" || protocol.Verify(m, ed25519.PublicKey(key), "credential-broker", time.Now().UTC(), last, nil) != nil {
		http.Error(w, "unauthorized", 401)
		return
	}
	var payload model.CredentialPayload
	if credential.Decrypt(b.private.Bytes(), meta.Envelope, &payload) != nil || payload.Token == "" || !time.Now().Before(payload.ExpiresAt) {
		http.Error(w, "invalid credential", 400)
		return
	}
	data, _ := json.Marshal(meta.Envelope)
	name := resourceName(meta.Tenant + "-" + meta.GrantRef)
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: b.namespace, Labels: map[string]string{"app.kubernetes.io/managed-by": "among-clusters"}, Annotations: map[string]string{"peering.re8ch.com/expires-at": payload.ExpiresAt.UTC().Format(time.RFC3339)}}, Data: map[string][]byte{"envelope.json": data}}
	existing, getErr := b.client.CoreV1().Secrets(b.namespace).Get(r.Context(), name, metav1.GetOptions{})
	if getErr == nil {
		secret.ResourceVersion = existing.ResourceVersion
		_, err = b.client.CoreV1().Secrets(b.namespace).Update(r.Context(), secret, metav1.UpdateOptions{})
	} else {
		_, err = b.client.CoreV1().Secrets(b.namespace).Create(r.Context(), secret, metav1.CreateOptions{})
	}
	if err != nil {
		http.Error(w, "store failed", 500)
		return
	}
	b.mu.Lock()
	b.generations[identity.SPIFFEID] = m.Generation
	b.mu.Unlock()
	write(w, 201, map[string]string{"credentialRef": "credential://among-clusters/" + meta.Tenant + "/" + meta.GrantRef})
}
func (b *broker) proxy(w http.ResponseWriter, r *http.Request) {
	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/k8s/"), "/", 3)
	if len(parts) < 2 {
		http.NotFound(w, r)
		return
	}
	name := resourceName(parts[0] + "-" + parts[1])
	secret, err := b.client.CoreV1().Secrets(b.namespace).Get(r.Context(), name, metav1.GetOptions{})
	if err != nil {
		http.Error(w, "credential unavailable", 403)
		return
	}
	var envelope credential.Envelope
	var payload model.CredentialPayload
	if json.Unmarshal(secret.Data["envelope.json"], &envelope) != nil || credential.Decrypt(b.private.Bytes(), envelope, &payload) != nil || !time.Now().Before(payload.ExpiresAt) {
		http.Error(w, "credential expired", 403)
		return
	}
	target, err := url.Parse(payload.Server)
	if err != nil {
		http.Error(w, "invalid target", 500)
		return
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(payload.CertificateAuthority))
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: payload.TLSServerName, MinVersion: tls.VersionTLS12}}
	original := proxy.Director
	proxy.Director = func(req *http.Request) {
		original(req)
		if len(parts) == 3 {
			req.URL.Path = "/" + parts[2]
		} else {
			req.URL.Path = "/"
		}
		req.Header.Set("Authorization", "Bearer "+payload.Token)
	}
	proxy.ServeHTTP(w, r)
}
func resourceName(v string) string {
	v = strings.ToLower(strings.NewReplacer("_", "-", ".", "-").Replace(v))
	if len(v) > 63 {
		v = v[:63]
	}
	return strings.Trim(v, "-")
}
func write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
