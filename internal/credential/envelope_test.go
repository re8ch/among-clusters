package credential

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestEnvelopeRoundTripAndTamperRejection(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	input := map[string]string{"token": "never-log-this"}
	envelope, err := Encrypt(key.PublicKey().Bytes(), input)
	if err != nil {
		t.Fatal(err)
	}
	var output map[string]string
	if err = Decrypt(key.Bytes(), envelope, &output); err != nil {
		t.Fatal(err)
	}
	if output["token"] != input["token"] {
		t.Fatal("payload mismatch")
	}
	tampered, _ := base64.RawStdEncoding.DecodeString(envelope.Ciphertext)
	tampered[0] ^= 0xff
	envelope.Ciphertext = base64.RawStdEncoding.EncodeToString(tampered)
	if err = Decrypt(key.Bytes(), envelope, &output); err == nil {
		t.Fatal("tampered envelope accepted")
	}
}
