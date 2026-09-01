package api

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/re8ch/among-clusters/internal/model"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

var clustersGVR = schema.GroupVersionResource{Group: "collaboration.re8ch.com", Version: "v1alpha1", Resource: "collaborationclusters"}
var eventsGVR = schema.GroupVersionResource{Group: "collaboration.re8ch.com", Version: "v1alpha1", Resource: "collaborationevents"}

type KubernetesStore struct{ Client dynamic.Interface }

func (s *KubernetesStore) cluster(ctx context.Context, id string) (*unstructured.Unstructured, error) {
	return s.Client.Resource(clustersGVR).Get(ctx, id, metav1.GetOptions{})
}
func (s *KubernetesStore) PublicKey(ctx context.Context, id string) ([]byte, bool, error) {
	obj, err := s.cluster(ctx, id)
	if err != nil {
		return nil, false, err
	}
	value, ok, err := unstructured.NestedString(obj.Object, "spec", "identity", "ed25519PublicKey")
	if err != nil || !ok {
		return nil, false, err
	}
	key, err := base64.RawStdEncoding.DecodeString(value)
	return key, err == nil, err
}
func (s *KubernetesStore) LastSequence(ctx context.Context, id string) (uint64, error) {
	obj, err := s.cluster(ctx, id)
	if err != nil {
		return 0, err
	}
	n, _, err := unstructured.NestedInt64(obj.Object, "status", "lastSequence")
	return uint64(n), err
}
func (s *KubernetesStore) RecordHeartbeat(ctx context.Context, h model.Heartbeat) error {
	obj, err := s.cluster(ctx, h.ClusterID)
	if err != nil {
		return err
	}
	last, _, _ := unstructured.NestedInt64(obj.Object, "status", "lastSequence")
	if h.Sequence <= uint64(last) {
		return fmt.Errorf("replayed sequence")
	}
	status := map[string]any{"lastSequence": int64(h.Sequence), "lastHeartbeatTime": h.ObservedAt.UTC().Format(time.RFC3339), "kubernetesVersion": h.KubernetesVersion, "state": "Alive", "summary": map[string]any{"nodesReady": int64(h.Counts.NodesReady), "nodesTotal": int64(h.Counts.NodesTotal), "podsRunning": int64(h.Counts.PodsRunning), "podsTotal": int64(h.Counts.PodsTotal), "namespaces": int64(h.Counts.Namespaces), "services": int64(h.Counts.Services)}}
	obj.Object["status"] = status
	_, err = s.Client.Resource(clustersGVR).UpdateStatus(ctx, obj, metav1.UpdateOptions{})
	return err
}
func (s *KubernetesStore) RecordEvent(ctx context.Context, e model.Event) error {
	last, err := s.LastSequence(ctx, e.ClusterID)
	if err != nil {
		return err
	}
	if e.Sequence <= last {
		return fmt.Errorf("replayed sequence")
	}
	name := fmt.Sprintf("%s-%020d", e.ClusterID, e.Sequence)
	obj := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "collaboration.re8ch.com/v1alpha1", "kind": "CollaborationEvent", "metadata": map[string]any{"name": name}, "spec": map[string]any{"clusterID": e.ClusterID, "sequence": int64(e.Sequence), "occurredAt": e.OccurredAt.UTC().Format(time.RFC3339), "type": e.Type, "subject": e.Subject, "details": e.Details}}}
	_, err = s.Client.Resource(eventsGVR).Create(ctx, obj, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	cluster, err := s.cluster(ctx, e.ClusterID)
	if err != nil {
		return err
	}
	_ = unstructured.SetNestedField(cluster.Object, int64(e.Sequence), "status", "lastSequence")
	_, err = s.Client.Resource(clustersGVR).UpdateStatus(ctx, cluster, metav1.UpdateOptions{})
	return err
}
