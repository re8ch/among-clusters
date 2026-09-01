package api

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"github.com/re8ch/among-clusters/internal/model"
	"github.com/re8ch/among-clusters/internal/signing"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func request(t *testing.T, h http.Handler, key ed25519.PrivateKey, heartbeat model.Heartbeat, now time.Time) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(heartbeat)
	r := httptest.NewRequest(http.MethodPost, "/v1/agents/test/heartbeat", bytes.NewReader(body))
	r.Header.Set("X-AmongClusters-Timestamp", now.Format(time.RFC3339Nano))
	r.Header.Set("X-AmongClusters-Sequence", strconv.FormatUint(heartbeat.Sequence, 10))
	r.Header.Set("X-AmongClusters-Signature", signing.Sign(key, now, heartbeat.Sequence, body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestHeartbeatAndReplayProtection(t *testing.T) {
	pub, priv, _ := signing.Generate()
	store := NewMemoryStore()
	store.Keys["test"] = pub
	now := time.Now().UTC()
	server := (&Server{Store: store, Now: func() time.Time { return now }}).Handler()
	heartbeat := model.Heartbeat{ClusterID: "test", Sequence: 1, ObservedAt: now}
	if w := request(t, server, priv, heartbeat, now); w.Code != http.StatusAccepted {
		t.Fatalf("got %d", w.Code)
	}
	if w := request(t, server, priv, heartbeat, now); w.Code != http.StatusUnauthorized {
		t.Fatalf("replay got %d", w.Code)
	}
}
func TestRejectsUnknownIdentity(t *testing.T) {
	_, priv, _ := signing.Generate()
	store := NewMemoryStore()
	now := time.Now().UTC()
	server := (&Server{Store: store, Now: func() time.Time { return now }}).Handler()
	w := request(t, server, priv, model.Heartbeat{ClusterID: "test", Sequence: 1, ObservedAt: now}, now)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("got %d", w.Code)
	}
}
