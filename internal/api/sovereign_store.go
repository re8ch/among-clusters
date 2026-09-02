package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/re8ch/among-clusters/internal/model"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

var identitiesGVR = schema.GroupVersionResource{Group: "peering.re8ch.com", Version: "v1alpha1", Resource: "clusteridentities"}

type SovereignStore interface {
	CreateInvitation(context.Context, model.Invitation) error
	ConsumeInvitation(context.Context, string, string, string, time.Time) (model.Invitation, error)
	RegisterIdentity(context.Context, model.IdentityRegistration) error
	Identity(context.Context, string, string) (model.IdentityRegistration, error)
	LastGeneration(context.Context, string, string) (uint64, error)
	RecordGeneration(context.Context, string, string, uint64, string) error
	ConfirmPeerBundle(context.Context, string, string, model.BundleConfirmation) error
	ObserveLink(context.Context, string, string, model.LinkObservation) error
}

type MemorySovereignStore struct {
	mu          sync.Mutex
	Invitations map[string]model.Invitation
	Identities  map[string]model.IdentityRegistration
	Generations map[string]uint64
	Nonces      map[string]map[string]struct{}
	Links       map[string]model.LinkObservation
}

func NewMemorySovereignStore() *MemorySovereignStore {
	return &MemorySovereignStore{Invitations: map[string]model.Invitation{}, Identities: map[string]model.IdentityRegistration{}, Generations: map[string]uint64{}, Nonces: map[string]map[string]struct{}{}, Links: map[string]model.LinkObservation{}}
}
func (s *MemorySovereignStore) CreateInvitation(_ context.Context, v model.Invitation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.Invitations[v.ID]; ok {
		return errors.New("invitation exists")
	}
	s.Invitations[v.ID] = v
	return nil
}
func (s *MemorySovereignStore) ConsumeInvitation(_ context.Context, id, hash, tenant string, now time.Time) (model.Invitation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.Invitations[id]
	if !ok || v.TokenHash != hash {
		return v, errors.New("invalid invitation")
	}
	if v.Tenant != tenant {
		return v, errors.New("tenant mismatch")
	}
	if !v.UsedAt.IsZero() {
		return v, errors.New("invitation already used")
	}
	if !now.Before(v.ExpiresAt) {
		return v, errors.New("invitation expired")
	}
	v.UsedAt = now
	s.Invitations[id] = v
	return v, nil
}
func (s *MemorySovereignStore) RegisterIdentity(_ context.Context, v model.IdentityRegistration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := v.Tenant + "/" + v.ClusterID
	if _, ok := s.Identities[key]; ok {
		return errors.New("identity exists")
	}
	s.Identities[key] = v
	return nil
}
func (s *MemorySovereignStore) Identity(_ context.Context, tenant, id string) (model.IdentityRegistration, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.Identities[tenant+"/"+id]
	if !ok {
		return v, errors.New("identity not found")
	}
	return v, nil
}
func (s *MemorySovereignStore) LastGeneration(_ context.Context, tenant, id string) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Generations[tenant+"/"+id], nil
}
func (s *MemorySovereignStore) RecordGeneration(_ context.Context, tenant, id string, g uint64, nonce string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := tenant + "/" + id
	if g <= s.Generations[key] {
		return errors.New("replayed generation")
	}
	if s.Nonces[key] == nil {
		s.Nonces[key] = map[string]struct{}{}
	}
	if _, ok := s.Nonces[key][nonce]; ok {
		return errors.New("replayed nonce")
	}
	s.Generations[key] = g
	s.Nonces[key][nonce] = struct{}{}
	return nil
}
func (s *MemorySovereignStore) ConfirmPeerBundle(_ context.Context, _, _ string, confirmation model.BundleConfirmation) error {
	if confirmation.PeerRef == "" || confirmation.BundleDigest == "" {
		return errors.New("invalid bundle confirmation")
	}
	return nil
}
func (s *MemorySovereignStore) ObserveLink(_ context.Context, tenant, _ string, observation model.LinkObservation) error {
	if observation.LinkRef == "" || observation.PeerRef == "" {
		return errors.New("invalid link observation")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Links[tenant+"/"+observation.LinkRef] = observation
	return nil
}

type KubernetesSovereignStore struct {
	Dynamic dynamic.Interface
	Core    kubernetes.Interface
}

func (s *KubernetesSovereignStore) CreateInvitation(ctx context.Context, v model.Invitation) error {
	capabilities, _ := json.Marshal(v.Capabilities)
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "among-clusters-invite-" + v.ID, Namespace: v.Tenant, Labels: map[string]string{"app.kubernetes.io/managed-by": "among-clusters"}, Annotations: map[string]string{"peering.re8ch.com/expires-at": v.ExpiresAt.Format(time.RFC3339)}}, Data: map[string][]byte{"token-hash": []byte(v.TokenHash), "capabilities": capabilities}}
	_, err := s.Core.CoreV1().Secrets(v.Tenant).Create(ctx, secret, metav1.CreateOptions{})
	return err
}
func (s *KubernetesSovereignStore) ConsumeInvitation(ctx context.Context, id, hash, tenant string, now time.Time) (model.Invitation, error) {
	name := "among-clusters-invite-" + id
	secret, err := s.Core.CoreV1().Secrets(tenant).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return model.Invitation{}, errors.New("invitation not found")
	}
	expires, _ := time.Parse(time.RFC3339, secret.Annotations["peering.re8ch.com/expires-at"])
	v := model.Invitation{ID: id, Tenant: tenant, ExpiresAt: expires, TokenHash: string(secret.Data["token-hash"])}
	_ = json.Unmarshal(secret.Data["capabilities"], &v.Capabilities)
	if v.TokenHash != hash {
		return v, errors.New("invalid invitation")
	}
	if secret.Annotations["peering.re8ch.com/used-at"] != "" {
		return v, errors.New("invitation already used")
	}
	if !now.Before(expires) {
		return v, errors.New("invitation expired")
	}
	secret.Annotations["peering.re8ch.com/used-at"] = now.Format(time.RFC3339Nano)
	_, err = s.Core.CoreV1().Secrets(tenant).Update(ctx, secret, metav1.UpdateOptions{})
	return v, err
}
func (s *KubernetesSovereignStore) RegisterIdentity(ctx context.Context, v model.IdentityRegistration) error {
	obj := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "peering.re8ch.com/v1alpha1", "kind": "ClusterIdentity", "metadata": map[string]any{"name": v.ClusterID, "namespace": v.Tenant}, "spec": map[string]any{"clusterID": v.ClusterID, "trustDomain": v.TrustDomain, "spiffeID": v.SPIFFEID, "bundleDigest": v.BundleDigest, "publicKey": v.PublicKey, "capabilities": v.Capabilities, "gatewayEndpoints": v.GatewayEndpoints}}}
	_, err := s.Dynamic.Resource(identitiesGVR).Namespace(v.Tenant).Create(ctx, obj, metav1.CreateOptions{})
	return err
}
func (s *KubernetesSovereignStore) Identity(ctx context.Context, tenant, id string) (model.IdentityRegistration, error) {
	obj, err := s.Dynamic.Resource(identitiesGVR).Namespace(tenant).Get(ctx, id, metav1.GetOptions{})
	if err != nil {
		return model.IdentityRegistration{}, err
	}
	spec, _, _ := unstructured.NestedMap(obj.Object, "spec")
	v := model.IdentityRegistration{Tenant: tenant, ClusterID: id}
	v.TrustDomain, _ = spec["trustDomain"].(string)
	v.SPIFFEID, _ = spec["spiffeID"].(string)
	v.BundleDigest, _ = spec["bundleDigest"].(string)
	v.PublicKey, _ = spec["publicKey"].(string)
	return v, nil
}
func (s *KubernetesSovereignStore) LastGeneration(ctx context.Context, tenant, id string) (uint64, error) {
	obj, err := s.Dynamic.Resource(identitiesGVR).Namespace(tenant).Get(ctx, id, metav1.GetOptions{})
	if err != nil {
		return 0, err
	}
	v, _, _ := unstructured.NestedInt64(obj.Object, "status", "lastGeneration")
	return uint64(v), nil
}
func (s *KubernetesSovereignStore) RecordGeneration(ctx context.Context, tenant, id string, g uint64, nonce string) error {
	obj, err := s.Dynamic.Resource(identitiesGVR).Namespace(tenant).Get(ctx, id, metav1.GetOptions{})
	if err != nil {
		return err
	}
	last, _, _ := unstructured.NestedInt64(obj.Object, "status", "lastGeneration")
	if g <= uint64(last) {
		return errors.New("replayed generation")
	}
	_ = unstructured.SetNestedField(obj.Object, int64(g), "status", "lastGeneration")
	_ = unstructured.SetNestedField(obj.Object, nonce, "status", "lastNonce")
	_, err = s.Dynamic.Resource(identitiesGVR).Namespace(tenant).UpdateStatus(ctx, obj, metav1.UpdateOptions{})
	return err
}
func (s *KubernetesSovereignStore) ConfirmPeerBundle(ctx context.Context, tenant, issuerID string, confirmation model.BundleConfirmation) error {
	peer, err := s.Dynamic.Resource(peersGVR).Namespace(tenant).Get(ctx, confirmation.PeerRef, metav1.GetOptions{})
	if err != nil {
		return err
	}
	localRef, _, _ := unstructured.NestedString(peer.Object, "spec", "localIdentityRef")
	remoteRef, _, _ := unstructured.NestedString(peer.Object, "spec", "remoteIdentityRef")
	var field, expectedRef string
	switch issuerID {
	case localRef:
		field, expectedRef = "localBundleConfirmed", remoteRef
	case remoteRef:
		field, expectedRef = "remoteBundleConfirmed", localRef
	default:
		return errors.New("issuer is not a member of the peer")
	}
	expected, err := s.Identity(ctx, tenant, expectedRef)
	if err != nil {
		return err
	}
	if expected.BundleDigest != confirmation.BundleDigest {
		return errors.New("bundle digest mismatch")
	}
	_ = unstructured.SetNestedField(peer.Object, true, "status", field)
	_, err = s.Dynamic.Resource(peersGVR).Namespace(tenant).UpdateStatus(ctx, peer, metav1.UpdateOptions{})
	return err
}

func (s *KubernetesSovereignStore) ObserveLink(ctx context.Context, tenant, issuerID string, observation model.LinkObservation) error {
	link, err := s.Dynamic.Resource(linksGVR).Namespace(tenant).Get(ctx, observation.LinkRef, metav1.GetOptions{})
	if err != nil {
		return err
	}
	peerRef, _, _ := unstructured.NestedString(link.Object, "spec", "peerRef")
	if peerRef != observation.PeerRef {
		return errors.New("link does not reference peer")
	}
	peer, err := s.Dynamic.Resource(peersGVR).Namespace(tenant).Get(ctx, peerRef, metav1.GetOptions{})
	if err != nil {
		return err
	}
	localRef, _, _ := unstructured.NestedString(peer.Object, "spec", "localIdentityRef")
	remoteRef, _, _ := unstructured.NestedString(peer.Object, "spec", "remoteIdentityRef")
	if issuerID != localRef && issuerID != remoteRef {
		return errors.New("issuer is not a member of the peer")
	}
	state := "Disconnected"
	if observation.Ready {
		state = "Ready"
	}
	_ = unstructured.SetNestedField(link.Object, state, "status", "state")
	_ = unstructured.SetNestedField(link.Object, observation.Reason, "status", "reason")
	_ = unstructured.SetNestedField(link.Object, observation.LatencyMillis, "status", "latencyMillis")
	_ = unstructured.SetNestedField(link.Object, observation.LastHandshakeAt.UTC().Format(time.RFC3339), "status", "lastHandshakeAt")
	_ = unstructured.SetNestedField(link.Object, time.Now().UTC().Format(time.RFC3339), "status", "lastObservedAt")
	_, err = s.Dynamic.Resource(linksGVR).Namespace(tenant).UpdateStatus(ctx, link, metav1.UpdateOptions{})
	return err
}
func decodeIdentityKey(v model.IdentityRegistration) ([]byte, error) {
	return base64.RawStdEncoding.DecodeString(v.PublicKey)
}
