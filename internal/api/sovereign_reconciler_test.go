package api

import (
	"context"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic/fake"
)

func TestOneSidedPublicGatewayIsConnectable(t *testing.T) {
	scheme := runtime.NewScheme()
	link := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "peering.re8ch.com/v1alpha1",
		"kind":       "AuthenticatedLink",
		"metadata":   map[string]any{"name": "provider-byoc", "namespace": "tenant"},
		"spec": map[string]any{
			"peerRef":      "provider-byoc",
			"transport":    "quic-mtls",
			"localGateway": "quic://203.0.113.10:8443",
		},
	}}
	client := fake.NewSimpleDynamicClientWithCustomListKinds(scheme, map[schema.GroupVersionResource]string{linksGVR: "AuthenticatedLinkList"}, link)
	reconciler := &SovereignReconciler{Client: client, Now: func() time.Time { return time.Unix(1_000, 0).UTC() }}
	reconciler.reconcileLinks(context.Background())
	result, err := client.Resource(linksGVR).Namespace("tenant").Get(context.Background(), "provider-byoc", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	state, _, _ := unstructured.NestedString(result.Object, "status", "state")
	reason, _, _ := unstructured.NestedString(result.Object, "status", "reason")
	if state != "Connecting" || reason != "" {
		t.Fatalf("state=%q reason=%q, want one-sided provider endpoint to remain connectable", state, reason)
	}
}
