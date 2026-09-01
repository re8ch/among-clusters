package api

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/re8ch/among-clusters/internal/model"
)

type Store interface {
	PublicKey(context.Context, string) ([]byte, bool, error)
	LastSequence(context.Context, string) (uint64, error)
	RecordHeartbeat(context.Context, model.Heartbeat) error
	RecordEvent(context.Context, model.Event) error
}

// MemoryStore is used by tests and local development. The Kubernetes-backed
// implementation is selected by the hub command in-cluster.
type MemoryStore struct {
	mu         sync.Mutex
	Keys       map[string][]byte
	Sequences  map[string]uint64
	Heartbeats map[string]model.Heartbeat
	Events     map[string]model.Event
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{Keys: map[string][]byte{}, Sequences: map[string]uint64{}, Heartbeats: map[string]model.Heartbeat{}, Events: map[string]model.Event{}}
}
func (s *MemoryStore) PublicKey(_ context.Context, id string) ([]byte, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.Keys[id]
	return append([]byte(nil), k...), ok, nil
}
func (s *MemoryStore) LastSequence(_ context.Context, id string) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Sequences[id], nil
}
func (s *MemoryStore) RecordHeartbeat(_ context.Context, h model.Heartbeat) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if h.Sequence <= s.Sequences[h.ClusterID] {
		return fmt.Errorf("replayed sequence")
	}
	s.Sequences[h.ClusterID] = h.Sequence
	s.Heartbeats[h.ClusterID] = h
	return nil
}
func (s *MemoryStore) RecordEvent(_ context.Context, e model.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.Sequence <= s.Sequences[e.ClusterID] {
		return fmt.Errorf("replayed sequence")
	}
	s.Sequences[e.ClusterID] = e.Sequence
	b, _ := json.Marshal(e)
	var copy model.Event
	_ = json.Unmarshal(b, &copy)
	s.Events[fmt.Sprintf("%s-%020d", e.ClusterID, e.Sequence)] = copy
	return nil
}
