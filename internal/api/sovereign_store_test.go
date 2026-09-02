package api

import (
	"context"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
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
