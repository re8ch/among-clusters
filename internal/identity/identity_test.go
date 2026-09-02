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
}
