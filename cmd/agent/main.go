package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/re8ch/among-clusters/internal/identity"
	"github.com/re8ch/among-clusters/internal/model"
	"github.com/re8ch/among-clusters/internal/protocol"
	"github.com/re8ch/among-clusters/internal/transport"
	"github.com/re8ch/among-clusters/internal/transport/quicmtls"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type agent struct {
	client                                                                           kubernetes.Interface
	clusterID, tenant, trustDomain, endpoint, namespace, secretName, gatewayEndpoint string
	key                                                                              ed25519.PrivateKey
	sequence                                                                         uint64
	http                                                                             *http.Client
	confirmations                                                                    []model.BundleConfirmation
	links                                                                            []linkTarget
}

type linkTarget struct {
	LinkRef          string `json:"linkRef"`
	PeerRef          string `json:"peerRef"`
	Endpoint         string `json:"endpoint"`
	ExpectedSPIFFEID string `json:"expectedSPIFFEID"`
}

func main() {
	ctx := context.Background()
	cfg, err := rest.InClusterConfig()
	if err != nil {
		log.Fatal(err)
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Fatal(err)
	}
	a := &agent{client: client, clusterID: must("CLUSTER_ID"), tenant: must("TENANT"), trustDomain: must("TRUST_DOMAIN"), endpoint: must("HUB_ENDPOINT"), namespace: env("POD_NAMESPACE", "among-clusters"), secretName: env("IDENTITY_SECRET", "among-clusters-agent-identity"), gatewayEndpoint: os.Getenv("GATEWAY_ENDPOINT"), http: &http.Client{Timeout: 10 * time.Second}}
	if err = json.Unmarshal([]byte(env("PEER_CONFIRMATIONS", "[]")), &a.confirmations); err != nil {
		log.Fatalf("PEER_CONFIRMATIONS: %v", err)
	}
	if err = json.Unmarshal([]byte(env("LINK_OBSERVATIONS", "[]")), &a.links); err != nil {
		log.Fatalf("LINK_OBSERVATIONS: %v", err)
	}
	if err = a.loadIdentity(ctx); err != nil {
		log.Fatal(err)
	}
	if token := os.Getenv("INVITATION_TOKEN"); token != "" {
		if err = a.register(ctx, os.Getenv("INVITATION_ID"), token); err != nil {
			log.Printf("registration: %v", err)
		}
	}
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		if err = a.heartbeat(ctx); err != nil {
			log.Printf("heartbeat: %v", err)
		}
		for _, confirmation := range a.confirmations {
			if err = a.sendControl(ctx, "peer.bundle.confirm", confirmation); err != nil {
				log.Printf("confirm %s: %v", confirmation.PeerRef, err)
			}
		}
		for _, target := range a.links {
			if err = a.observeLink(ctx, target); err != nil {
				log.Printf("observe %s: %v", target.LinkRef, err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func must(name string) string {
	v := os.Getenv(name)
	if v == "" {
		log.Fatalf("%s is required", name)
	}
	return v
}
func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
func (a *agent) spiffeID() string { return "spiffe://" + a.trustDomain + "/cluster/" + a.clusterID }
func (a *agent) loadIdentity(ctx context.Context) error {
	s, err := a.client.CoreV1().Secrets(a.namespace).Get(ctx, a.secretName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		m, genErr := identity.Generate(a.spiffeID(), time.Now().UTC())
		if genErr != nil {
			return genErr
		}
		s = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: a.secretName, Labels: map[string]string{"app.kubernetes.io/managed-by": "among-clusters"}, Annotations: map[string]string{"peering.re8ch.com/generation": "0", "peering.re8ch.com/bundle-digest": m.BundleDigest}}, Type: corev1.SecretTypeTLS, Data: map[string][]byte{"tls.crt": m.CertificatePEM, "tls.key": m.PrivateKeyPEM, "bundle.pem": m.BundlePEM, "private-key": m.PrivateKey, "public-key": m.PublicKey}}
		s, err = a.client.CoreV1().Secrets(a.namespace).Create(ctx, s, metav1.CreateOptions{})
	}
	if err != nil {
		return err
	}
	if len(s.Data["private-key"]) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid identity key")
	}
	a.key = ed25519.PrivateKey(s.Data["private-key"])
	if len(s.Data["tls.crt"]) == 0 || len(s.Data["tls.key"]) == 0 || len(s.Data["bundle.pem"]) == 0 || s.Annotations["peering.re8ch.com/bundle-digest"] == "" {
		material, migrateErr := identity.FromPrivateKey(a.spiffeID(), a.key, time.Now().UTC())
		if migrateErr != nil {
			return migrateErr
		}
		if s.Data == nil {
			s.Data = map[string][]byte{}
		}
		if s.Annotations == nil {
			s.Annotations = map[string]string{}
		}
		s.Type = corev1.SecretTypeTLS
		s.Data["tls.crt"] = material.CertificatePEM
		s.Data["tls.key"] = material.PrivateKeyPEM
		s.Data["bundle.pem"] = material.BundlePEM
		s.Data["public-key"] = material.PublicKey
		s.Annotations["peering.re8ch.com/bundle-digest"] = material.BundleDigest
		if s.Annotations["peering.re8ch.com/generation"] == "" {
			s.Annotations["peering.re8ch.com/generation"] = "0"
		}
		s, err = a.client.CoreV1().Secrets(a.namespace).Update(ctx, s, metav1.UpdateOptions{})
		if err != nil {
			return err
		}
	}
	a.sequence, _ = strconv.ParseUint(s.Annotations["peering.re8ch.com/generation"], 10, 64)
	return nil
}
func (a *agent) registration(ctx context.Context) (model.IdentityRegistration, error) {
	s, err := a.client.CoreV1().Secrets(a.namespace).Get(ctx, a.secretName, metav1.GetOptions{})
	if err != nil {
		return model.IdentityRegistration{}, err
	}
	endpoints := []string{}
	if a.gatewayEndpoint != "" {
		endpoints = []string{a.gatewayEndpoint}
	}
	return model.IdentityRegistration{ClusterID: a.clusterID, Tenant: a.tenant, TrustDomain: a.trustDomain, SPIFFEID: a.spiffeID(), BundleDigest: s.Annotations["peering.re8ch.com/bundle-digest"], PublicKey: base64.RawStdEncoding.EncodeToString(a.key.Public().(ed25519.PublicKey)), Capabilities: []string{"service", "quic-mtls"}, GatewayEndpoints: endpoints}, nil
}
func (a *agent) register(ctx context.Context, id, token string) error {
	if id == "" {
		return fmt.Errorf("invitation ID required")
	}
	registration, err := a.registration(ctx)
	if err != nil {
		return err
	}
	identityBody, _ := json.Marshal(registration)
	proof := ed25519.Sign(a.key, identityBody)
	body, _ := json.Marshal(model.InvitationAcceptance{Token: token, Identity: registration, Proof: base64.RawStdEncoding.EncodeToString(proof)})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint+"/v1/invitations/"+id+"/accept", bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := a.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != 201 && response.StatusCode != 409 {
		return fmt.Errorf("hub returned %s", response.Status)
	}
	return nil
}
func (a *agent) heartbeat(ctx context.Context) error {
	services, err := a.client.CoreV1().Services(a.namespace).List(ctx, metav1.ListOptions{LabelSelector: "peering.re8ch.com/advertise=true"})
	if err != nil {
		return err
	}
	return a.sendControl(ctx, "identity.heartbeat", map[string]any{"services": len(services.Items), "observedAt": time.Now().UTC()})
}

func (a *agent) sendControl(ctx context.Context, messageType string, payloadValue any) error {
	payload, _ := json.Marshal(payloadValue)
	a.sequence++
	now := time.Now().UTC()
	message := model.ControlMessage{Issuer: a.spiffeID(), Audience: "hub", Generation: a.sequence, IssuedAt: now, ExpiresAt: now.Add(time.Minute), Nonce: fmt.Sprintf("%s-%d", a.clusterID, a.sequence), Type: messageType, Payload: payload}
	if err := protocol.Sign(&message, a.key); err != nil {
		return err
	}
	body, _ := json.Marshal(message)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/v1/peers/%s/%s/messages", a.endpoint, a.tenant, a.clusterID), bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := a.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != 202 {
		return fmt.Errorf("hub returned %s", response.Status)
	}
	secret, err := a.client.CoreV1().Secrets(a.namespace).Get(ctx, a.secretName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	secret.Annotations["peering.re8ch.com/generation"] = strconv.FormatUint(a.sequence, 10)
	_, err = a.client.CoreV1().Secrets(a.namespace).Update(ctx, secret, metav1.UpdateOptions{})
	return err
}

func (a *agent) observeLink(ctx context.Context, target linkTarget) error {
	observation := model.LinkObservation{LinkRef: target.LinkRef, PeerRef: target.PeerRef, LastHandshakeAt: time.Now().UTC()}
	start := time.Now()
	driver, err := a.driver(target.ExpectedSPIFFEID)
	if err == nil {
		var result transport.Observation
		result, err = driver.Probe(ctx, transport.Peer{ID: target.PeerRef, Endpoints: []string{target.Endpoint}})
		observation.Ready = result.Ready
		observation.LatencyMillis = result.Latency.Milliseconds()
		observation.LastHandshakeAt = result.ObservedAt.UTC()
	}
	if err != nil {
		observation.Ready = false
		observation.Reason = "TransportError"
		observation.LatencyMillis = time.Since(start).Milliseconds()
	}
	return a.sendControl(ctx, "link.observe", observation)
}

func (a *agent) driver(expectedSPIFFEID string) (*quicmtls.Driver, error) {
	secret, err := a.client.CoreV1().Secrets(a.namespace).Get(context.Background(), a.secretName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	certificate, err := tls.X509KeyPair(secret.Data["tls.crt"], secret.Data["tls.key"])
	if err != nil {
		return nil, err
	}
	bundle, err := os.ReadFile(env("PEER_BUNDLE_FILE", "/peer-bundles/ca.crt"))
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(bundle) {
		return nil, fmt.Errorf("peer bundle is invalid")
	}
	config := &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13, NextProtos: []string{"among-clusters/1"}, InsecureSkipVerify: true} //nolint:gosec -- URI SAN and private root are verified below.
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return fmt.Errorf("peer certificate missing")
		}
		intermediates := x509.NewCertPool()
		for _, certificate := range state.PeerCertificates[1:] {
			intermediates.AddCert(certificate)
		}
		if _, verifyErr := state.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); verifyErr != nil {
			return verifyErr
		}
		if len(state.PeerCertificates[0].URIs) != 1 || strings.TrimSuffix(state.PeerCertificates[0].URIs[0].String(), "/") != strings.TrimSuffix(expectedSPIFFEID, "/") {
			return fmt.Errorf("unexpected peer SPIFFE identity")
		}
		return nil
	}
	return quicmtls.New(config), nil
}
