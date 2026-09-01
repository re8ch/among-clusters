package signing

import (
	"testing"
	"time"
)

func TestSignVerifyAndClockSkew(t *testing.T) {
	pub, priv, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	body := []byte(`{"ok":true}`)
	sig := Sign(priv, now, 7, body)
	if err := Verify(pub, now, 7, body, sig, now, 2*time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := Verify(pub, now, 8, body, sig, now, 2*time.Minute); err == nil {
		t.Fatal("sequence must be signed")
	}
	if err := Verify(pub, now, 7, body, sig, now.Add(3*time.Minute), 2*time.Minute); err != ErrClockSkew {
		t.Fatalf("got %v", err)
	}
}
