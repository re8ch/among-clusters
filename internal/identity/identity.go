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
	uri, err := url.Parse(spiffeID)
	if err != nil {
		return Material{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return Material{}, err
	}
	template := x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: spiffeID}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(24 * time.Hour), URIs: []*url.URL{uri}, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, pub, priv)
	if err != nil {
		return Material{}, err
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return Material{}, err
	}
	key := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	sum := sha256.Sum256(cert)
	return Material{PrivateKey: priv, PublicKey: pub, CertificatePEM: cert, PrivateKeyPEM: key, BundlePEM: cert, BundleDigest: "sha256:" + hex.EncodeToString(sum[:])}, nil
}
