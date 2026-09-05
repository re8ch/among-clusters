package api

import (
	"context"
	"os"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

var peersGVR = schema.GroupVersionResource{Group: "peering.re8ch.com", Version: "v1alpha1", Resource: "peers"}
var linksGVR = schema.GroupVersionResource{Group: "peering.re8ch.com", Version: "v1alpha1", Resource: "authenticatedlinks"}
var advertisementsGVR = schema.GroupVersionResource{Group: "peering.re8ch.com", Version: "v1alpha1", Resource: "serviceadvertisements"}
var importsGVR = schema.GroupVersionResource{Group: "peering.re8ch.com", Version: "v1alpha1", Resource: "importedservices"}
var grantsGVR = schema.GroupVersionResource{Group: "peering.re8ch.com", Version: "v1alpha1", Resource: "managedaccessgrants"}

type SovereignReconciler struct {
	Client               dynamic.Interface
	Core                 kubernetes.Interface
	Now                  func() time.Time
	ManagedAccessEnabled bool
}

func (r *SovereignReconciler) Run(ctx context.Context) {
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
func (r *SovereignReconciler) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now().UTC()
}
func (r *SovereignReconciler) Once(ctx context.Context) {
	r.reconcilePeers(ctx)
	r.reconcileAdvertisements(ctx)
	r.reconcileLinks(ctx)
	r.reconcileImports(ctx)
	r.reconcileGrants(ctx)
}
func (r *SovereignReconciler) reconcilePeers(ctx context.Context) {
	list, err := r.Client.Resource(peersGVR).Namespace(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return
	}
	for i := range list.Items {
		o := &list.Items[i]
		suspended, _, _ := unstructured.NestedBool(o.Object, "spec", "suspended")
		local, _, _ := unstructured.NestedBool(o.Object, "status", "localBundleConfirmed")
		remote, _, _ := unstructured.NestedBool(o.Object, "status", "remoteBundleConfirmed")
		state := "PendingConfirmation"
		if suspended {
			state = "Suspended"
		} else if local && remote {
			state = "Ready"
		}
		_ = unstructured.SetNestedField(o.Object, state, "status", "state")
		_ = unstructured.SetNestedField(o.Object, o.GetGeneration(), "status", "observedGeneration")
		_, _ = r.Client.Resource(peersGVR).Namespace(o.GetNamespace()).UpdateStatus(ctx, o, metav1.UpdateOptions{})
	}
}
func (r *SovereignReconciler) reconcileAdvertisements(ctx context.Context) {
	now := r.now()
	list, err := r.Client.Resource(advertisementsGVR).Namespace(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return
	}
	for i := range list.Items {
		o := &list.Items[i]
		revoked, _, _ := unstructured.NestedBool(o.Object, "spec", "revoked")
		ttl, _, _ := unstructured.NestedInt64(o.Object, "spec", "ttlSeconds")
		publishedAt := o.GetCreationTimestamp().Time
		if value := o.GetAnnotations()["peering.re8ch.com/last-published-at"]; value != "" {
			if parsed, parseErr := time.Parse(time.RFC3339, value); parseErr == nil {
				publishedAt = parsed
			}
		}
		expires := publishedAt.Add(time.Duration(ttl) * time.Second)
		state := "Active"
		if revoked {
			state = "Revoked"
		} else if !now.Before(expires) {
			state = "Expired"
		}
		_ = unstructured.SetNestedField(o.Object, state, "status", "state")
		_ = unstructured.SetNestedField(o.Object, expires.UTC().Format(time.RFC3339), "status", "expiresAt")
		_, _ = r.Client.Resource(advertisementsGVR).Namespace(o.GetNamespace()).UpdateStatus(ctx, o, metav1.UpdateOptions{})
	}
}
func (r *SovereignReconciler) reconcileLinks(ctx context.Context) {
	list, err := r.Client.Resource(linksGVR).Namespace(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return
	}
	for i := range list.Items {
		o := &list.Items[i]
		local, _, _ := unstructured.NestedString(o.Object, "spec", "localGateway")
		remote, _, _ := unstructured.NestedString(o.Object, "spec", "remoteGateway")
		state, reason := "Connecting", ""
		if local == "" && remote == "" {
			state, reason = "Blocked", "NATUnreachable"
		} else if observedValue, found, _ := unstructured.NestedString(o.Object, "status", "lastObservedAt"); found {
			if observed, parseErr := time.Parse(time.RFC3339, observedValue); parseErr == nil && r.now().Sub(observed) <= 45*time.Second {
				continue
			}
			state, reason = "Disconnected", "ObservationStale"
		}
		_ = unstructured.SetNestedField(o.Object, state, "status", "state")
		_ = unstructured.SetNestedField(o.Object, reason, "status", "reason")
		_ = unstructured.SetNestedField(o.Object, o.GetGeneration(), "status", "observedGeneration")
		_, _ = r.Client.Resource(linksGVR).Namespace(o.GetNamespace()).UpdateStatus(ctx, o, metav1.UpdateOptions{})
	}
}
func (r *SovereignReconciler) reconcileImports(ctx context.Context) {
	if r.Core == nil {
		return
	}
	list, err := r.Client.Resource(importsGVR).Namespace(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return
	}
	for i := range list.Items {
		o := &list.Items[i]
		suspended, _, _ := unstructured.NestedBool(o.Object, "spec", "suspended")
		name, _, _ := unstructured.NestedString(o.Object, "spec", "localServiceName")
		localPort, found, _ := unstructured.NestedInt64(o.Object, "spec", "localPort")
		if !found {
			localPort = 8443
		}
		state := "Ready"
		if suspended {
			state = "Suspended"
		} else {
			svc := &corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: o.GetNamespace(), Labels: map[string]string{"app.kubernetes.io/managed-by": "among-clusters", "peering.re8ch.com/import": o.GetName()}}, Spec: corev1.ServiceSpec{Selector: map[string]string{"app.kubernetes.io/name": "among-clusters-gateway"}, Ports: []corev1.ServicePort{{Name: "service", Port: 6443, TargetPort: intstr.FromInt32(int32(localPort)), Protocol: corev1.ProtocolTCP}}}}
			if _, err = r.Core.CoreV1().Services(o.GetNamespace()).Create(ctx, svc, metav1.CreateOptions{}); err != nil {
				if existing, getErr := r.Core.CoreV1().Services(o.GetNamespace()).Get(ctx, name, metav1.GetOptions{}); getErr == nil && existing.Labels["peering.re8ch.com/import"] != o.GetName() {
					state = "Failed"
				}
			}
		}
		_ = unstructured.SetNestedField(o.Object, state, "status", "state")
		_ = unstructured.SetNestedField(o.Object, o.GetNamespace()+"/"+name, "status", "serviceRef")
		_, _ = r.Client.Resource(importsGVR).Namespace(o.GetNamespace()).UpdateStatus(ctx, o, metav1.UpdateOptions{})
	}
}
func (r *SovereignReconciler) reconcileGrants(ctx context.Context) {
	list, err := r.Client.Resource(grantsGVR).Namespace(metav1.NamespaceAll).List(ctx, metav1.ListOptions{})
	if err != nil {
		return
	}
	now := r.now()
	for i := range list.Items {
		o := &list.Items[i]
		expiresValue, _, _ := unstructured.NestedString(o.Object, "spec", "expiresAt")
		expires, _ := time.Parse(time.RFC3339, expiresValue)
		approved, _, _ := unstructured.NestedBool(o.Object, "spec", "approved")
		revoked, _, _ := unstructured.NestedBool(o.Object, "spec", "revoked")
		state, reason := "Pending", ""
		if !r.ManagedAccessEnabled {
			reason = "ManagedAccessDisabled"
		} else if revoked {
			state = "Revoked"
		} else if !now.Before(expires) {
			state = "Expired"
		} else if approved {
			credentialRef, _, _ := unstructured.NestedString(o.Object, "status", "credentialRef")
			if credentialRef == "" {
				state = "AwaitingLocalApproval"
			} else {
				state = "Active"
			}
		}
		_ = unstructured.SetNestedField(o.Object, state, "status", "state")
		_ = unstructured.SetNestedField(o.Object, reason, "status", "reason")
		_, _ = r.Client.Resource(grantsGVR).Namespace(o.GetNamespace()).UpdateStatus(ctx, o, metav1.UpdateOptions{})
	}
}
func ManagedAccessFromEnv() bool { return os.Getenv("MANAGED_ACCESS_ENABLED") == "true" }
