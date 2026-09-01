package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/re8ch/among-clusters/internal/model"
	"github.com/re8ch/among-clusters/internal/signing"
)

type Server struct {
	Store   Store
	Now     func() time.Time
	MaxBody int64
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("POST /v1/agents/{clusterID}/heartbeat", s.heartbeat)
	mux.HandleFunc("POST /v1/agents/{clusterID}/events", s.event)
	return mux
}

func (s *Server) verify(r *http.Request, clusterID string) ([]byte, uint64, bool) {
	limit := s.MaxBody
	if limit == 0 {
		limit = 1 << 20
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil || int64(len(body)) > limit {
		return nil, 0, false
	}
	sequence, err := parseSequence(r.Header.Get("X-AmongClusters-Sequence"))
	if err != nil {
		return nil, 0, false
	}
	timestamp, err := time.Parse(time.RFC3339Nano, r.Header.Get("X-AmongClusters-Timestamp"))
	if err != nil {
		return nil, 0, false
	}
	key, ok, err := s.Store.PublicKey(r.Context(), clusterID)
	if err != nil || !ok || len(key) != ed25519.PublicKeySize {
		return nil, 0, false
	}
	sig := strings.TrimSpace(r.Header.Get("X-AmongClusters-Signature"))
	now := time.Now()
	if s.Now != nil {
		now = s.Now()
	}
	if signing.Verify(ed25519.PublicKey(key), timestamp, sequence, body, sig, now, 2*time.Minute) != nil {
		return nil, 0, false
	}
	last, err := s.Store.LastSequence(r.Context(), clusterID)
	if err != nil || sequence <= last {
		return nil, 0, false
	}
	return body, sequence, true
}
func parseSequence(v string) (uint64, error) { var n uint64; _, err := fmtSscan(v, &n); return n, err }

var fmtSscan = func(v string, n *uint64) (int, error) { return fmt.Sscan(v, n) }

func (s *Server) heartbeat(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("clusterID")
	body, seq, ok := s.verify(r, id)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var h model.Heartbeat
	if json.Unmarshal(body, &h) != nil || h.ClusterID != id || h.Sequence != seq {
		http.Error(w, "invalid heartbeat", 400)
		return
	}
	if s.Store.RecordHeartbeat(r.Context(), h) != nil {
		http.Error(w, "conflict", 409)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}
func (s *Server) event(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("clusterID")
	body, seq, ok := s.verify(r, id)
	if !ok {
		http.Error(w, "unauthorized", 401)
		return
	}
	var e model.Event
	if json.Unmarshal(body, &e) != nil || e.ClusterID != id || e.Sequence != seq {
		http.Error(w, "invalid event", 400)
		return
	}
	if s.Store.RecordEvent(r.Context(), e) != nil {
		http.Error(w, "conflict", 409)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

func DecodePublicKey(value string) ([]byte, error) { return base64.RawStdEncoding.DecodeString(value) }
