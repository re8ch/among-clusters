package credential

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
)

type Envelope struct {
	EphemeralKey string `json:"ephemeralKey"`
	Nonce        string `json:"nonce"`
	Ciphertext   string `json:"ciphertext"`
}

func Encrypt(publicKey []byte, value any) (Envelope, error) {
	curve := ecdh.X25519()
	remote, err := curve.NewPublicKey(publicKey)
	if err != nil {
		return Envelope{}, err
	}
	private, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return Envelope{}, err
	}
	shared, err := private.ECDH(remote)
	if err != nil {
		return Envelope{}, err
	}
	block, err := aes.NewCipher(shared)
	if err != nil {
		return Envelope{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return Envelope{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return Envelope{}, err
	}
	clear, err := json.Marshal(value)
	if err != nil {
		return Envelope{}, err
	}
	sealed := aead.Seal(nil, nonce, clear, nil)
	return Envelope{EphemeralKey: base64.RawStdEncoding.EncodeToString(private.PublicKey().Bytes()), Nonce: base64.RawStdEncoding.EncodeToString(nonce), Ciphertext: base64.RawStdEncoding.EncodeToString(sealed)}, nil
}
func Decrypt(privateKey []byte, envelope Envelope, target any) error {
	curve := ecdh.X25519()
	local, err := curve.NewPrivateKey(privateKey)
	if err != nil {
		return err
	}
	peerBytes, err := base64.RawStdEncoding.DecodeString(envelope.EphemeralKey)
	if err != nil {
		return err
	}
	peer, err := curve.NewPublicKey(peerBytes)
	if err != nil {
		return err
	}
	shared, err := local.ECDH(peer)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(shared)
	if err != nil {
		return err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce, err := base64.RawStdEncoding.DecodeString(envelope.Nonce)
	if err != nil {
		return err
	}
	sealed, err := base64.RawStdEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		return err
	}
	clear, err := aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		return errors.New("credential envelope authentication failed")
	}
	return json.Unmarshal(clear, target)
}
