package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/re8ch/among-clusters/internal/model"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

var identitiesGVR = schema.GroupVersionResource{Group: "peering.re8ch.com", Version: "v1alpha1", Resource: "clusteridentities"}

type SovereignStore interface {
	CreateOnboardingClaim(context.Context, model.OnboardingClaim) error
	ConsumeOnboardingClaim(context.Context, string, string, string, time.Time) (model.OnboardingClaim, error)
	CreateInvitation(context.Context, model.Invitation) error
	ConsumeInvitation(context.Context, string, string, string, string, []string, time.Time) (model.Invitation, error)
	RegisterIdentity(context.Context, model.IdentityRegistration) error
	Identity(context.Context, string, string) (model.IdentityRegistration, error)
	LastGeneration(context.Context, string, string) (uint64, error)
	RecordGeneration(context.Context, string, string, uint64, string) error
	ConfirmPeerBundle(context.Context, string, string, model.BundleConfirmation) error
	ObserveLink(context.Context, string, string, model.LinkObservation) error
	SyncAdvertisements(context.Context, string, string, []model.AdvertisedService, time.Time) error
	PendingGrants(context.Context, string, string, time.Time) ([]model.GrantInstruction, error)
	FulfillGrant(context.Context, string, string, model.GrantFulfillment) error
}

type MemorySovereignStore struct {
	mu               sync.Mutex
	Invitations      map[string]model.Invitation
	Identities       map[string]model.IdentityRegistration
	Generations      map[string]uint64
	Nonces           map[string]map[string]struct{}
	Links            map[string]model.LinkObservation
	Advertisements   map[string][]model.AdvertisedService
	OnboardingClaims map[string]model.OnboardingClaim
}

func NewMemorySovereignStore() *MemorySovereignStore {
	return &MemorySovereignStore{Invitations: map[string]model.Invitation{}, Identities: map[string]model.IdentityRegistration{}, Generations: map[string]uint64{}, Nonces: map[string]map[string]struct{}{}, Links: map[string]model.LinkObservation{}, Advertisements: map[string][]model.AdvertisedService{}, OnboardingClaims: map[string]model.OnboardingClaim{}}
}
func (s *MemorySovereignStore) CreateOnboardingClaim(_ context.Context, v model.OnboardingClaim) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.OnboardingClaims[v.ID]; exists {
		return errors.New("claim exists")
	}
	s.OnboardingClaims[v.ID] = v
	return nil
}
func (s *MemorySovereignStore) ConsumeOnboardingClaim(_ context.Context, tenant, id, hash string, now time.Time) (model.OnboardingClaim, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, exists := s.OnboardingClaims[id]
	if !exists || v.TokenHash != hash {
		return v, errors.New("invalid claim")
	}
	if v.Tenant != tenant {
		return v, errors.New("invalid claim")
	}
	if !v.UsedAt.IsZero() {
		return v, errors.New("claim already used")
	}
	if !now.Before(v.ExpiresAt) {
		return v, errors.New("claim expired")
	}
	v.UsedAt = now
	s.OnboardingClaims[id] = v
	return v, nil
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
func (s *MemorySovereignStore) ConsumeInvitation(_ context.Context, id, hash, tenant, clusterID string, requested []string, now time.Time) (model.Invitation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.Invitations[id]
	if !ok || v.TokenHash != hash {
		return v, errors.New("invalid invitation")
	}
	if v.Tenant != tenant {
		return v, errors.New("tenant mismatch")
	}
	if v.ClusterID != "" && v.ClusterID != clusterID {
		return v, errors.New("cluster mismatch")
	}
	if !v.UsedAt.IsZero() {
		return v, errors.New("invitation already used")
	}
	if !now.Before(v.ExpiresAt) {
		return v, errors.New("invitation expired")
	}
	if !capabilitiesAllowed(v.Capabilities, requested) {
		return v, errors.New("capability not invited")
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
func (s *MemorySovereignStore) SyncAdvertisements(_ context.Context, tenant, issuer string, services []model.AdvertisedService, _ time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Advertisements[tenant+"/"+issuer] = append([]model.AdvertisedService(nil), services...)
	return nil
}
func (s *MemorySovereignStore) PendingGrants(context.Context, string, string, time.Time) ([]model.GrantInstruction, error) {
	return nil, nil
}
func (s *MemorySovereignStore) FulfillGrant(context.Context, string, string, model.GrantFulfillment) error {
	return nil
}

type KubernetesSovereignStore struct {
	Dynamic dynamic.Interface
	Core    kubernetes.Interface
}

func (s *KubernetesSovereignStore) CreateOnboardingClaim(ctx context.Context, v model.OnboardingClaim) error {
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "among-clusters-claim-" + v.ID, Namespace: v.Tenant, Labels: map[string]string{"app.kubernetes.io/managed-by": "among-clusters", "peering.re8ch.com/purpose": "onboarding-claim"}, Annotations: map[string]string{"peering.re8ch.com/expires-at": v.ExpiresAt.Format(time.RFC3339)}}, Data: map[string][]byte{"token-hash": []byte(v.TokenHash), "cluster-id": []byte(v.ClusterID), "region": []byte(v.Region)}}
	_, err := s.Core.CoreV1().Secrets(v.Tenant).Create(ctx, secret, metav1.CreateOptions{})
	return err
}
func (s *KubernetesSovereignStore) ConsumeOnboardingClaim(ctx context.Context, tenant, id, hash string, now time.Time) (model.OnboardingClaim, error) {
	name := "among-clusters-claim-" + id
	for attempts := 0; attempts < 3; attempts++ {
		secret, err := s.Core.CoreV1().Secrets(tenant).Get(ctx, name, metav1.GetOptions{})
		if err != nil || string(secret.Data["token-hash"]) != hash {
			return model.OnboardingClaim{}, errors.New("invalid claim")
		}
		expires, _ := time.Parse(time.RFC3339, secret.Annotations["peering.re8ch.com/expires-at"])
		v := model.OnboardingClaim{ID: id, ClusterID: string(secret.Data["cluster-id"]), Region: string(secret.Data["region"]), Tenant: tenant, TokenHash: hash, ExpiresAt: expires}
		if secret.Annotations["peering.re8ch.com/used-at"] != "" {
			return v, errors.New("claim already used")
		}
		if !now.Before(expires) {
			return v, errors.New("claim expired")
		}
		secret.Annotations["peering.re8ch.com/used-at"] = now.Format(time.RFC3339Nano)
		if _, err = s.Core.CoreV1().Secrets(secret.Namespace).Update(ctx, secret, metav1.UpdateOptions{}); err == nil {
			v.UsedAt = now
			return v, nil
		}
		if !apierrors.IsConflict(err) {
			return v, err
		}
	}
	return model.OnboardingClaim{}, errors.New("claim update conflict")
}

func (s *KubernetesSovereignStore) CreateInvitation(ctx context.Context, v model.Invitation) error {
	capabilities, _ := json.Marshal(v.Capabilities)
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "among-clusters-invite-" + v.ID, Namespace: v.Tenant, Labels: map[string]string{"app.kubernetes.io/managed-by": "among-clusters"}, Annotations: map[string]string{"peering.re8ch.com/expires-at": v.ExpiresAt.Format(time.RFC3339)}}, Data: map[string][]byte{"token-hash": []byte(v.TokenHash), "capabilities": capabilities, "cluster-id": []byte(v.ClusterID), "region": []byte(v.Region)}}
	_, err := s.Core.CoreV1().Secrets(v.Tenant).Create(ctx, secret, metav1.CreateOptions{})
	return err
}
func (s *KubernetesSovereignStore) ConsumeInvitation(ctx context.Context, id, hash, tenant, clusterID string, requested []string, now time.Time) (model.Invitation, error) {
	name := "among-clusters-invite-" + id
	secret, err := s.Core.CoreV1().Secrets(tenant).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return model.Invitation{}, errors.New("invitation not found")
	}
	expires, _ := time.Parse(time.RFC3339, secret.Annotations["peering.re8ch.com/expires-at"])
	v := model.Invitation{ID: id, Tenant: tenant, ClusterID: string(secret.Data["cluster-id"]), Region: string(secret.Data["region"]), ExpiresAt: expires, TokenHash: string(secret.Data["token-hash"])}
	_ = json.Unmarshal(secret.Data["capabilities"], &v.Capabilities)
	if v.TokenHash != hash {
		return v, errors.New("invalid invitation")
	}
	if v.ClusterID != "" && v.ClusterID != clusterID {
		return v, errors.New("cluster mismatch")
	}
	if secret.Annotations["peering.re8ch.com/used-at"] != "" {
		return v, errors.New("invitation already used")
	}
	if !now.Before(expires) {
		return v, errors.New("invitation expired")
	}
	if !capabilitiesAllowed(v.Capabilities, requested) {
		return v, errors.New("capability not invited")
	}
	secret.Annotations["peering.re8ch.com/used-at"] = now.Format(time.RFC3339Nano)
	_, err = s.Core.CoreV1().Secrets(tenant).Update(ctx, secret, metav1.UpdateOptions{})
	return v, err
}

func capabilitiesAllowed(invited, requested []string) bool {
	allowed := make(map[string]struct{}, len(invited))
	for _, capability := range invited {
		allowed[capability] = struct{}{}
	}
	for _, capability := range requested {
		if _, ok := allowed[capability]; !ok {
			return false
		}
	}
	return true
}
func (s *KubernetesSovereignStore) RegisterIdentity(ctx context.Context, v model.IdentityRegistration) error {
	obj := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "peering.re8ch.com/v1alpha1", "kind": "ClusterIdentity", "metadata": map[string]any{"name": v.ClusterID, "namespace": v.Tenant}, "spec": map[string]any{"clusterID": v.ClusterID, "region": v.Region, "trustDomain": v.TrustDomain, "spiffeID": v.SPIFFEID, "bundleDigest": v.BundleDigest, "publicKey": v.PublicKey, "capabilities": stringValues(v.Capabilities), "gatewayEndpoints": stringValues(v.GatewayEndpoints)}}}
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
	v.Region, _ = spec["region"].(string)
	v.SPIFFEID, _ = spec["spiffeID"].(string)
	v.BundleDigest, _ = spec["bundleDigest"].(string)
	v.PublicKey, _ = spec["publicKey"].(string)
	v.GatewayEndpoints = stringSlice(obj.Object, "spec", "gatewayEndpoints")
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
	_ = unstructured.SetNestedField(obj.Object, "Ready", "status", "state")
	_ = unstructured.SetNestedField(obj.Object, time.Now().UTC().Format(time.RFC3339), "status", "lastSeenAt")
	_ = unstructured.SetNestedField(obj.Object, obj.GetGeneration(), "status", "observedGeneration")
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

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func stringSlice(object map[string]any, fields ...string) []string {
	values, _, _ := unstructured.NestedStringSlice(object, fields...)
	return values
}
func stringValues(values []string) []any {
	result := make([]any, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}

func advertisementName(issuer string, service model.AdvertisedService) string {
	name := strings.ToLower(issuer + "-" + service.Namespace + "-" + service.Name)
	name = strings.NewReplacer("_", "-", ".", "-").Replace(name)
	if len(name) > 63 {
		name = name[:63]
	}
	return strings.Trim(name, "-")
}
func importPort(name string) int64 {
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(name))
	return int64(20000 + hash.Sum32()%10000)
}

func (s *KubernetesSovereignStore) SyncAdvertisements(ctx context.Context, tenant, issuer string, services []model.AdvertisedService, now time.Time) error {
	identity, err := s.Identity(ctx, tenant, issuer)
	if err != nil {
		return err
	}
	seen := map[string]struct{}{}
	for _, service := range services {
		if service.Name == "" || service.Namespace == "" || service.PolicyRef == "" || service.Port < 1 || len(service.TargetPeers) == 0 {
			return errors.New("invalid service advertisement")
		}
		policy, getErr := s.Dynamic.Resource(schema.GroupVersionResource{Group: "peering.re8ch.com", Version: "v1alpha1", Resource: "peerpolicies"}).Namespace(tenant).Get(ctx, service.PolicyRef, metav1.GetOptions{})
		if getErr != nil {
			return fmt.Errorf("policy %s unavailable: %w", service.PolicyRef, getErr)
		}
		classes := stringSlice(policy.Object, "spec", "serviceClasses")
		protocols := stringSlice(policy.Object, "spec", "protocols")
		portValues, _, _ := unstructured.NestedSlice(policy.Object, "spec", "ports")
		directions := stringSlice(policy.Object, "spec", "directions")
		maximum, found, _ := unstructured.NestedInt64(policy.Object, "spec", "maxAdvertisements")
		if found && maximum >= 0 && int64(len(services)) > maximum {
			return fmt.Errorf("policy %s advertisement quota exceeded", service.PolicyRef)
		}
		selector := stringSlice(policy.Object, "spec", "peerSelector", "matchNames")
		matchAllReady, _, _ := unstructured.NestedBool(policy.Object, "spec", "peerSelector", "matchAllReady")
		targetPeers := append([]string(nil), service.TargetPeers...)
		if len(targetPeers) == 1 && targetPeers[0] == "*" {
			if !matchAllReady {
				return fmt.Errorf("policy %s does not allow all Ready peers", service.PolicyRef)
			}
			peerList, listErr := s.Dynamic.Resource(peersGVR).Namespace(tenant).List(ctx, metav1.ListOptions{})
			if listErr != nil {
				return listErr
			}
			targetPeers = targetPeers[:0]
			for i := range peerList.Items {
				peer := &peerList.Items[i]
				state, _, _ := unstructured.NestedString(peer.Object, "status", "state")
				suspended, _, _ := unstructured.NestedBool(peer.Object, "spec", "suspended")
				local, _, _ := unstructured.NestedString(peer.Object, "spec", "localIdentityRef")
				remote, _, _ := unstructured.NestedString(peer.Object, "spec", "remoteIdentityRef")
				if state == "Ready" && !suspended && (issuer == local || issuer == remote) {
					targetPeers = append(targetPeers, peer.GetName())
				}
			}
			sort.Strings(targetPeers)
			if len(targetPeers) == 0 {
				return fmt.Errorf("policy %s matches no Ready peers", service.PolicyRef)
			}
		}
		portAllowed := len(portValues) == 0
		for _, value := range portValues {
			port, ok := value.(int64)
			if ok && port == int64(service.Port) {
				portAllowed = true
			}
		}
		if !containsString(classes, service.ServiceClass) || !containsString(protocols, service.Protocol) || !containsString(directions, "export") || !portAllowed {
			return fmt.Errorf("policy %s denies service contract", service.PolicyRef)
		}
		for _, peerRef := range targetPeers {
			if !matchAllReady && !containsString(selector, peerRef) {
				return fmt.Errorf("policy %s denies peer %s", service.PolicyRef, peerRef)
			}
			peer, peerErr := s.Dynamic.Resource(peersGVR).Namespace(tenant).Get(ctx, peerRef, metav1.GetOptions{})
			if peerErr != nil {
				return peerErr
			}
			local, _, _ := unstructured.NestedString(peer.Object, "spec", "localIdentityRef")
			remote, _, _ := unstructured.NestedString(peer.Object, "spec", "remoteIdentityRef")
			if issuer != local && issuer != remote {
				return errors.New("publisher is not a member of target peer")
			}
		}
		name := advertisementName(issuer, service)
		seen[name] = struct{}{}
		spec := map[string]any{"publisherRef": issuer, "serviceIdentity": fmt.Sprintf("spiffe://%s/ns/%s/service/%s", identity.TrustDomain, service.Namespace, service.Name), "serviceClass": service.ServiceClass, "protocol": service.Protocol, "port": int64(service.Port), "localServiceRef": map[string]any{"name": service.Name}, "gatewayEndpoints": stringValues(identity.GatewayEndpoints), "targetPeers": stringValues(targetPeers), "ttlSeconds": service.TTLSeconds, "generation": service.Generation, "policyRef": service.PolicyRef, "revoked": false}
		object := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "peering.re8ch.com/v1alpha1", "kind": "ServiceAdvertisement", "metadata": map[string]any{"name": name, "namespace": tenant, "labels": map[string]any{"peering.re8ch.com/publisher": issuer}, "annotations": map[string]any{"peering.re8ch.com/last-published-at": now.UTC().Format(time.RFC3339)}}, "spec": spec}}
		existing, getErr := s.Dynamic.Resource(advertisementsGVR).Namespace(tenant).Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(getErr) {
			_, err = s.Dynamic.Resource(advertisementsGVR).Namespace(tenant).Create(ctx, object, metav1.CreateOptions{})
		} else if getErr == nil {
			object.SetResourceVersion(existing.GetResourceVersion())
			_, err = s.Dynamic.Resource(advertisementsGVR).Namespace(tenant).Update(ctx, object, metav1.UpdateOptions{})
		} else {
			err = getErr
		}
		if err != nil {
			return err
		}
		for _, peerRef := range targetPeers {
			importName := name + "-" + peerRef
			if len(importName) > 63 {
				importName = importName[:63]
			}
			imp := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "peering.re8ch.com/v1alpha1", "kind": "ImportedService", "metadata": map[string]any{"name": importName, "namespace": tenant}, "spec": map[string]any{"advertisementRef": name, "peerRef": peerRef, "localServiceName": importName, "localPort": importPort(importName), "suspended": false}}}
			if _, createErr := s.Dynamic.Resource(importsGVR).Namespace(tenant).Create(ctx, imp, metav1.CreateOptions{}); createErr != nil && !apierrors.IsAlreadyExists(createErr) {
				return createErr
			}
		}
	}
	list, err := s.Dynamic.Resource(advertisementsGVR).Namespace(tenant).List(ctx, metav1.ListOptions{LabelSelector: "peering.re8ch.com/publisher=" + issuer})
	if err != nil {
		return err
	}
	for i := range list.Items {
		if _, ok := seen[list.Items[i].GetName()]; !ok {
			item := &list.Items[i]
			_ = unstructured.SetNestedField(item.Object, true, "spec", "revoked")
			_, _ = s.Dynamic.Resource(advertisementsGVR).Namespace(tenant).Update(ctx, item, metav1.UpdateOptions{})
		}
	}
	return nil
}

func (s *KubernetesSovereignStore) PendingGrants(ctx context.Context, tenant, issuer string, now time.Time) ([]model.GrantInstruction, error) {
	list, err := s.Dynamic.Resource(grantsGVR).Namespace(tenant).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	result := []model.GrantInstruction{}
	for i := range list.Items {
		o := &list.Items[i]
		approved, _, _ := unstructured.NestedBool(o.Object, "spec", "approved")
		revoked, _, _ := unstructured.NestedBool(o.Object, "spec", "revoked")
		exp, _, _ := unstructured.NestedString(o.Object, "spec", "expiresAt")
		expires, parseErr := time.Parse(time.RFC3339, exp)
		if !approved || parseErr != nil {
			continue
		}
		adRef, _, _ := unstructured.NestedString(o.Object, "spec", "advertisementRef")
		ad, getErr := s.Dynamic.Resource(advertisementsGVR).Namespace(tenant).Get(ctx, adRef, metav1.GetOptions{})
		if getErr != nil {
			continue
		}
		publisher, _, _ := unstructured.NestedString(ad.Object, "spec", "publisherRef")
		protocolName, _, _ := unstructured.NestedString(ad.Object, "spec", "protocol")
		if publisher != issuer || protocolName != "kubernetes-api" {
			continue
		}
		peerRef, _, _ := unstructured.NestedString(o.Object, "spec", "peerRef")
		scope, _, _ := unstructured.NestedString(o.Object, "spec", "scope")
		if scope == "" {
			scope = "Namespaced"
		}
		namespaces := stringSlice(o.Object, "spec", "namespaces")
		rawRules, _, _ := unstructured.NestedSlice(o.Object, "spec", "rules")
		rules := []model.AccessRule{}
		for _, raw := range rawRules {
			m, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			rules = append(rules, model.AccessRule{APIGroups: stringSlice(m, "apiGroups"), Resources: stringSlice(m, "resources"), Verbs: stringSlice(m, "verbs")})
		}
		result = append(result, model.GrantInstruction{Name: o.GetName(), Tenant: tenant, PeerRef: peerRef, AdvertisementRef: adRef, Generation: o.GetGeneration(), Scope: scope, Namespaces: namespaces, Rules: rules, ExpiresAt: expires, Revoked: revoked, ProxyURL: "https://" + adRef + "-" + peerRef + "." + tenant + ".svc.cluster.local:6443"})
	}
	return result, nil
}

func (s *KubernetesSovereignStore) FulfillGrant(ctx context.Context, tenant, issuer string, value model.GrantFulfillment) error {
	o, err := s.Dynamic.Resource(grantsGVR).Namespace(tenant).Get(ctx, value.GrantRef, metav1.GetOptions{})
	if err != nil {
		return err
	}
	adRef, _, _ := unstructured.NestedString(o.Object, "spec", "advertisementRef")
	ad, err := s.Dynamic.Resource(advertisementsGVR).Namespace(tenant).Get(ctx, adRef, metav1.GetOptions{})
	if err != nil {
		return err
	}
	publisher, _, _ := unstructured.NestedString(ad.Object, "spec", "publisherRef")
	if publisher != issuer {
		return errors.New("issuer does not own grant advertisement")
	}
	if !strings.HasPrefix(value.CredentialRef, "credential://among-clusters/") {
		return errors.New("invalid opaque credential reference")
	}
	_ = unstructured.SetNestedField(o.Object, value.CredentialRef, "status", "credentialRef")
	_ = unstructured.SetNestedField(o.Object, value.RenewedAt.UTC().Format(time.RFC3339), "status", "lastRenewedAt")
	_ = unstructured.SetNestedField(o.Object, "Active", "status", "state")
	_, err = s.Dynamic.Resource(grantsGVR).Namespace(tenant).UpdateStatus(ctx, o, metav1.UpdateOptions{})
	return err
}
func decodeIdentityKey(v model.IdentityRegistration) ([]byte, error) {
	return base64.RawStdEncoding.DecodeString(v.PublicKey)
}
