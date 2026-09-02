package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/re8ch/among-clusters/internal/model"
)

var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

func RandomToken(bytes int) (string, error) {
	value := make([]byte, bytes)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}
func RandomID(bytes int) (string, error) {
	value := make([]byte, bytes)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}
func TokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "sha256:" + hex.EncodeToString(sum[:])
}
func ValidateIdentity(v model.IdentityRegistration) error {
	if v.ClusterID == "" || v.Tenant == "" || v.TrustDomain == "" {
		return errors.New("clusterID, tenant and trustDomain are required")
	}
	if v.SPIFFEID != "spiffe://"+v.TrustDomain+"/cluster/"+v.ClusterID {
		return errors.New("spiffeID must match trust domain and cluster ID")
	}
	if !digestPattern.MatchString(v.BundleDigest) {
		return errors.New("invalid bundle digest")
	}
	key, err := base64.RawStdEncoding.DecodeString(v.PublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return errors.New("invalid Ed25519 public key")
	}
	for _, endpoint := range v.GatewayEndpoints {
		if !strings.HasPrefix(endpoint, "quic://") {
			return errors.New("only quic endpoints are accepted in v1")
		}
	}
	return nil
}
func canonical(message model.ControlMessage) ([]byte, error) {
	copy := message
	copy.Signature = ""
	return json.Marshal(copy)
}
func Sign(message *model.ControlMessage, key ed25519.PrivateKey) error {
	body, err := canonical(*message)
	if err != nil {
		return err
	}
	message.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(key, body))
	return nil
}
func Verify(message model.ControlMessage, key ed25519.PublicKey, audience string, now time.Time, lastGeneration uint64, seenNonce func(string) bool) error {
	if message.Audience != audience {
		return errors.New("wrong audience")
	}
	if message.Issuer == "" || message.Nonce == "" || message.Type == "" {
		return errors.New("missing envelope identity")
	}
	if message.Generation <= lastGeneration {
		return errors.New("replayed generation")
	}
	if !message.IssuedAt.Before(message.ExpiresAt) || now.Before(message.IssuedAt.Add(-2*time.Minute)) || !now.Before(message.ExpiresAt) {
		return errors.New("expired or future message")
	}
	if seenNonce != nil && seenNonce(message.Nonce) {
		return errors.New("replayed nonce")
	}
	signature, err := base64.RawStdEncoding.DecodeString(message.Signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	body, err := canonical(message)
	if err != nil {
		return err
	}
	if !ed25519.Verify(key, body, signature) {
		return errors.New("invalid signature")
	}
	return nil
}
