package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

var ErrClockSkew = errors.New("timestamp outside accepted clock skew")

func Generate() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

func canonical(timestamp time.Time, sequence uint64, body []byte) []byte {
	h := sha256.New()
	h.Write([]byte(timestamp.UTC().Format(time.RFC3339Nano)))
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], sequence)
	h.Write(seq[:])
	h.Write(body)
	return h.Sum(nil)
}

func Sign(privateKey ed25519.PrivateKey, timestamp time.Time, sequence uint64, body []byte) string {
	return base64.RawStdEncoding.EncodeToString(ed25519.Sign(privateKey, canonical(timestamp, sequence, body)))
}

func Verify(publicKey ed25519.PublicKey, timestamp time.Time, sequence uint64, body []byte, signature string, now time.Time, maxSkew time.Duration) error {
	if timestamp.Before(now.Add(-maxSkew)) || timestamp.After(now.Add(maxSkew)) {
		return ErrClockSkew
	}
	sig, err := base64.RawStdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(publicKey, canonical(timestamp, sequence, body), sig) {
		return errors.New("invalid signature")
	}
	return nil
}
