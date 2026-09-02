package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestLoadIdentityPreservesLegacySecretType(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	legacy := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "identity", Namespace: "among-clusters"},
		Type:       corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"private-key": privateKey,
			"public-key":  publicKey,
		},
	}
	client := fake.NewSimpleClientset(legacy)
	a := &agent{client: client, clusterID: "qwen", trustDomain: "qwen.byoc", namespace: "among-clusters", secretName: "identity"}
	if err := a.loadIdentity(context.Background()); err != nil {
		t.Fatal(err)
	}
	updated, err := client.CoreV1().Secrets("among-clusters").Get(context.Background(), "identity", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Type != corev1.SecretTypeOpaque {
		t.Fatalf("secret type changed: got %q", updated.Type)
	}
	for _, key := range []string{"tls.crt", "tls.key", "bundle.pem"} {
		if len(updated.Data[key]) == 0 {
			t.Fatalf("missing migrated key %q", key)
		}
	}
}
