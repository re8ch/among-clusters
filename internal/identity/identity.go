package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"time"
)

type Material struct {
	PrivateKey                               ed25519.PrivateKey
	PublicKey                                ed25519.PublicKey
	CertificatePEM, PrivateKeyPEM, BundlePEM []byte
	BundleDigest                             string
}

func Generate(spiffeID string, now time.Time) (Material, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Material{}, err
	}
	return FromPrivateKey(spiffeID, priv, now)
}

func FromPrivateKey(spiffeID string, priv ed25519.PrivateKey, now time.Time) (Material, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return Material{}, fmt.Errorf("invalid Ed25519 private key")
	}
	pub := priv.Public().(ed25519.PublicKey)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return Material{}, err
	}
	rootTemplate := x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: spiffeID + " root"}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(10, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign, IsCA: true, BasicConstraintsValid: true}
	rootDER, err := x509.CreateCertificate(rand.Reader, &rootTemplate, &rootTemplate, pub, priv)
	if err != nil {
		return Material{}, err
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return Material{}, err
	}
	bundle := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	return issueLeaf(spiffeID, priv, root, bundle, now)
}

func Rotate(spiffeID string, rootPrivateKey ed25519.PrivateKey, bundlePEM []byte, now time.Time) (Material, error) {
	block, _ := pem.Decode(bundlePEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return Material{}, fmt.Errorf("invalid trust bundle")
	}
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !root.IsCA {
		return Material{}, fmt.Errorf("invalid root certificate")
	}
	rootPublic, ok := root.PublicKey.(ed25519.PublicKey)
	if !ok || !rootPublic.Equal(rootPrivateKey.Public()) {
		return Material{}, fmt.Errorf("root key does not match trust bundle")
	}
	return issueLeaf(spiffeID, rootPrivateKey, root, bundlePEM, now)
}

func issueLeaf(spiffeID string, rootPrivateKey ed25519.PrivateKey, root *x509.Certificate, bundlePEM []byte, now time.Time) (Material, error) {
	uri, err := url.Parse(spiffeID)
	if err != nil {
		return Material{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return Material{}, err
	}
	leafPublic, leafPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Material{}, err
	}
	template := x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: spiffeID}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), URIs: []*url.URL{uri}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, &template, root, leafPublic, rootPrivateKey)
	if err != nil {
		return Material{}, err
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(leafPrivate)
	if err != nil {
		return Material{}, err
	}
	certificatePEM := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), bundlePEM...)
	sum := sha256.Sum256(bundlePEM)
	return Material{PrivateKey: rootPrivateKey, PublicKey: rootPrivateKey.Public().(ed25519.PublicKey), CertificatePEM: certificatePEM, PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes}), BundlePEM: bundlePEM, BundleDigest: "sha256:" + hex.EncodeToString(sum[:])}, nil
}
