package api

import (
	"context"
	"sort"
	"time"

	"github.com/re8ch/among-clusters/internal/health"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

var relationshipsGVR = schema.GroupVersionResource{Group: "collaboration.re8ch.com", Version: "v1alpha1", Resource: "collaborationrelationships"}
var servicesGVR = schema.GroupVersionResource{Group: "collaboration.re8ch.com", Version: "v1alpha1", Resource: "publishedservices"}

type Reconciler struct {
	Client         dynamic.Interface
	Now            func() time.Time
	EventRetention time.Duration
	MaxEvents      int
}

func (r *Reconciler) Run(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		r.Once(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func (r *Reconciler) Once(ctx context.Context) {
	now := time.Now()
	if r.Now != nil {
		now = r.Now()
	}
	r.reconcileClusters(ctx, now)
	r.reconcileRelationships(ctx)
	r.reconcileServices(ctx)
	r.pruneEvents(ctx, now)
}
func (r *Reconciler) reconcileClusters(ctx context.Context, now time.Time) {
	list, err := r.Client.Resource(clustersGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return
	}
	for i := range list.Items {
		obj := &list.Items[i]
		suspended, _, _ := unstructured.NestedBool(obj.Object, "spec", "suspended")
		value, _, _ := unstructured.NestedString(obj.Object, "status", "lastHeartbeatTime")
		last, _ := time.Parse(time.RFC3339, value)
		state := health.Evaluate(last, now, suspended)
		_ = unstructured.SetNestedField(obj.Object, string(state), "status", "state")
		_, _ = r.Client.Resource(clustersGVR).UpdateStatus(ctx, obj, metav1.UpdateOptions{})
	}
}
func (r *Reconciler) reconcileRelationships(ctx context.Context) {
	list, err := r.Client.Resource(relationshipsGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return
	}
	for i := range list.Items {
		obj := &list.Items[i]
		suspended, _, _ := unstructured.NestedBool(obj.Object, "spec", "suspended")
		proposer, _, _ := unstructured.NestedString(obj.Object, "spec", "declarations", "proposerEventRef")
		accepter, _, _ := unstructured.NestedString(obj.Object, "spec", "declarations", "accepterEventRef")
		state := "Proposed"
		if suspended {
			state = "Suspended"
		} else if r.eventExists(ctx, proposer) && r.eventExists(ctx, accepter) {
			state = "Active"
		}
		_ = unstructured.SetNestedField(obj.Object, state, "status", "state")
		_ = unstructured.SetNestedField(obj.Object, obj.GetGeneration(), "status", "observedGeneration")
		_, _ = r.Client.Resource(relationshipsGVR).UpdateStatus(ctx, obj, metav1.UpdateOptions{})
	}
}
func (r *Reconciler) reconcileServices(ctx context.Context) {
	list, err := r.Client.Resource(servicesGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return
	}
	for i := range list.Items {
		obj := &list.Items[i]
		revoked, _, _ := unstructured.NestedBool(obj.Object, "spec", "revoked")
		publisher, _, _ := unstructured.NestedString(obj.Object, "spec", "declarations", "publisherEventRef")
		consumers, _, _ := unstructured.NestedStringSlice(obj.Object, "spec", "consumers")
		accepted, _, _ := unstructured.NestedStringMap(obj.Object, "spec", "declarations", "consumerEventRefs")
		state := "Proposed"
		if revoked {
			state = "Revoked"
		} else if r.eventExists(ctx, publisher) && r.allConsumerEventsExist(ctx, accepted, consumers) {
			state = "Active"
		}
		_ = unstructured.SetNestedField(obj.Object, state, "status", "state")
		_, _ = r.Client.Resource(servicesGVR).UpdateStatus(ctx, obj, metav1.UpdateOptions{})
	}
}
func (r *Reconciler) eventExists(ctx context.Context, name string) bool {
	if name == "" {
		return false
	}
	_, err := r.Client.Resource(eventsGVR).Get(ctx, name, metav1.GetOptions{})
	return err == nil
}
func (r *Reconciler) allConsumerEventsExist(ctx context.Context, refs map[string]string, consumers []string) bool {
	for _, consumer := range consumers {
		if !r.eventExists(ctx, refs[consumer]) {
			return false
		}
	}
	return true
}
func (r *Reconciler) pruneEvents(ctx context.Context, now time.Time) {
	list, err := r.Client.Resource(eventsGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return
	}
	retention := r.EventRetention
	if retention == 0 {
		retention = 30 * 24 * time.Hour
	}
	max := r.MaxEvents
	if max == 0 {
		max = 10000
	}
	sort.Slice(list.Items, func(i, j int) bool {
		return list.Items[i].GetCreationTimestamp().Time.Before(list.Items[j].GetCreationTimestamp().Time)
	})
	remove := len(list.Items) - max
	for i := range list.Items {
		expired := list.Items[i].GetCreationTimestamp().Time.Before(now.Add(-retention))
		if i < remove || expired {
			_ = r.Client.Resource(eventsGVR).Delete(ctx, list.Items[i].GetName(), metav1.DeleteOptions{})
		}
	}
}
