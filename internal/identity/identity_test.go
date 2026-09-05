package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"
)

func TestFromPrivateKeyPreservesRootOfTrust(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	material, err := FromPrivateKey("spiffe://qwen.byoc/cluster/qwen", privateKey, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(material.PublicKey, publicKey) {
		t.Fatal("public key changed during identity migration")
	}
	block, _ := pem.Decode(material.CertificatePEM)
	if block == nil {
		t.Fatal("certificate PEM missing")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(certificate.URIs) != 1 || certificate.URIs[0].String() != "spiffe://qwen.byoc/cluster/qwen" {
		t.Fatalf("unexpected URI SAN: %v", certificate.URIs)
	}
	if certificate.IsCA {
		t.Fatal("workload SVID must not be the trust-domain root")
	}
	rootBlock, _ := pem.Decode(material.BundlePEM)
	root, err := x509.ParseCertificate(rootBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !root.IsCA || root.NotAfter.Before(time.Now().AddDate(9, 0, 0)) {
		t.Fatalf("root is not a long-lived CA: %+v", root)
	}
	rotated, err := Rotate("spiffe://qwen.byoc/cluster/qwen", privateKey, material.BundlePEM, time.Now().Add(23*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if rotated.BundleDigest != material.BundleDigest || !bytes.Equal(rotated.BundlePEM, material.BundlePEM) {
		t.Fatal("SVID rotation changed the trust-domain root")
	}
	if bytes.Equal(rotated.CertificatePEM, material.CertificatePEM) {
		t.Fatal("SVID rotation did not issue a new certificate")
	}
}
