package api

import (
	"context"
	"testing"
	"time"

	"github.com/re8ch/among-clusters/internal/model"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
)

func TestRecordGenerationMarksIdentityReady(t *testing.T) {
	identity := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "peering.re8ch.com/v1alpha1",
		"kind":       "ClusterIdentity",
		"metadata":   map[string]any{"name": "qwen", "namespace": "byoc-pilot", "generation": int64(1)},
		"spec":       map[string]any{"clusterID": "qwen"},
	}}
	client := fake.NewSimpleDynamicClient(runtime.NewScheme(), identity)
	store := &KubernetesSovereignStore{Dynamic: client}

	if err := store.RecordGeneration(context.Background(), "byoc-pilot", "qwen", 1, "nonce-1"); err != nil {
		t.Fatal(err)
	}
	got, err := client.Resource(identitiesGVR).Namespace("byoc-pilot").Get(context.Background(), "qwen", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if state, _, _ := unstructured.NestedString(got.Object, "status", "state"); state != "Ready" {
		t.Fatalf("identity state = %q, want Ready", state)
	}
	if lastSeenAt, _, _ := unstructured.NestedString(got.Object, "status", "lastSeenAt"); lastSeenAt == "" {
		t.Fatal("identity lastSeenAt was not recorded")
	}
}

func TestSignedSnapshotMaterializesOnlyPolicyAllowedService(t *testing.T) {
	identity := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "peering.re8ch.com/v1alpha1", "kind": "ClusterIdentity", "metadata": map[string]any{"name": "qwen", "namespace": "pilot"}, "spec": map[string]any{"clusterID": "qwen", "trustDomain": "qwen.test", "gatewayEndpoints": []any{"quic://qwen:8443"}}}}
	peer := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "peering.re8ch.com/v1alpha1", "kind": "Peer", "metadata": map[string]any{"name": "qwen-re8ch", "namespace": "pilot"}, "spec": map[string]any{"localIdentityRef": "qwen", "remoteIdentityRef": "re8ch"}}}
	policy := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "peering.re8ch.com/v1alpha1", "kind": "PeerPolicy", "metadata": map[string]any{"name": "api-export", "namespace": "pilot"}, "spec": map[string]any{"peerSelector": map[string]any{"matchNames": []any{"qwen-re8ch"}}, "serviceClasses": []any{"kubernetes.control-plane"}, "protocols": []any{"kubernetes-api"}, "ports": []any{int64(443)}, "directions": []any{"export"}, "maxAdvertisements": int64(1)}}}
	lists := map[schema.GroupVersionResource]string{advertisementsGVR: "ServiceAdvertisementList", importsGVR: "ImportedServiceList", peersGVR: "PeerList", schema.GroupVersionResource{Group: "peering.re8ch.com", Version: "v1alpha1", Resource: "peerpolicies"}: "PeerPolicyList"}
	client := fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), lists, identity, peer, policy)
	store := &KubernetesSovereignStore{Dynamic: client}
	service := model.AdvertisedService{Name: "kubernetes", Namespace: "default", ServiceClass: "kubernetes.control-plane", Protocol: "kubernetes-api", Port: 443, TargetPeers: []string{"qwen-re8ch"}, TTLSeconds: 60, PolicyRef: "api-export", Generation: 1}
	if err := store.SyncAdvertisements(context.Background(), "pilot", "qwen", []model.AdvertisedService{service}, time.Now()); err != nil {
		t.Fatal(err)
	}
	ads, err := client.Resource(advertisementsGVR).Namespace("pilot").List(context.Background(), metav1.ListOptions{})
	if err != nil || len(ads.Items) != 1 {
		t.Fatalf("ads=%d err=%v", len(ads.Items), err)
	}
	imports, err := client.Resource(importsGVR).Namespace("pilot").List(context.Background(), metav1.ListOptions{})
	if err != nil || len(imports.Items) != 1 {
		t.Fatalf("imports=%d err=%v", len(imports.Items), err)
	}
}

func TestPendingGrantCarriesExplicitClusterScope(t *testing.T) {
	now := time.Now().UTC()
	advertisement := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "peering.re8ch.com/v1alpha1", "kind": "ServiceAdvertisement", "metadata": map[string]any{"name": "qwen-kubernetes", "namespace": "pilot"}, "spec": map[string]any{"publisherRef": "qwen", "protocol": "kubernetes-api"}}}
	grant := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "peering.re8ch.com/v1alpha1",
		"kind":       "ManagedAccessGrant",
		"metadata":   map[string]any{"name": "qwen-admin", "namespace": "pilot", "generation": int64(7)},
		"spec": map[string]any{
			"peerRef": "qwen-re8ch", "advertisementRef": "qwen-kubernetes", "scope": "Cluster",
			"expiresAt": now.Add(time.Hour).Format(time.RFC3339), "approved": true, "revoked": false,
			"rules": []any{map[string]any{"apiGroups": []any{"*"}, "resources": []any{"*"}, "verbs": []any{"get", "list", "watch"}}},
		},
	}}
	lists := map[schema.GroupVersionResource]string{grantsGVR: "ManagedAccessGrantList", advertisementsGVR: "ServiceAdvertisementList"}
	client := fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), lists, advertisement, grant)
	store := &KubernetesSovereignStore{Dynamic: client}
	grants, err := store.PendingGrants(context.Background(), "pilot", "qwen", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 1 || grants[0].Scope != "Cluster" || grants[0].Generation != 7 {
		t.Fatalf("grants=%+v, want one generation-bound cluster-scoped grant", grants)
	}
}
