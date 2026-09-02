package api

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"github.com/re8ch/among-clusters/internal/model"
	"github.com/re8ch/among-clusters/internal/protocol"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type SovereignServer struct {
	Store      SovereignStore
	AdminToken string
	Now        func() time.Time
}

func (s *SovereignServer) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now().UTC()
}
func (s *SovereignServer) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })
	mux.HandleFunc("POST /v1/invitations", s.createInvitation)
	mux.HandleFunc("POST /v1/invitations/{id}/accept", s.acceptInvitation)
	mux.HandleFunc("POST /v1/peers/{tenant}/{clusterID}/messages", s.controlMessage)
	return mux
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func (s *SovereignServer) createInvitation(w http.ResponseWriter, r *http.Request) {
	if s.AdminToken == "" || r.Header.Get("Authorization") != "Bearer "+s.AdminToken {
		http.Error(w, "unauthorized", 401)
		return
	}
	var input struct {
		Tenant       string   `json:"tenant"`
		TTLSeconds   int      `json:"ttlSeconds"`
		Capabilities []string `json:"capabilities"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&input) != nil || input.Tenant == "" {
		http.Error(w, "invalid invitation", 400)
		return
	}
	if input.TTLSeconds == 0 {
		input.TTLSeconds = 900
	}
	if input.TTLSeconds < 60 || input.TTLSeconds > 86400 {
		http.Error(w, "invalid ttl", 400)
		return
	}
	id, _ := protocol.RandomToken(12)
	token, _ := protocol.RandomToken(32)
	v := model.Invitation{ID: id, Tenant: input.Tenant, ExpiresAt: s.now().Add(time.Duration(input.TTLSeconds) * time.Second), Capabilities: input.Capabilities, TokenHash: protocol.TokenHash(token)}
	if err := s.Store.CreateInvitation(r.Context(), v); err != nil {
		http.Error(w, "conflict", 409)
		return
	}
	writeJSON(w, 201, map[string]any{"invitationID": id, "token": token, "expiresAt": v.ExpiresAt})
}
func (s *SovereignServer) acceptInvitation(w http.ResponseWriter, r *http.Request) {
	var input model.InvitationAcceptance
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&input) != nil || protocol.ValidateIdentity(input.Identity) != nil {
		http.Error(w, "invalid identity", 400)
		return
	}
	publicKey, keyErr := decodeIdentityKey(input.Identity)
	proof, proofErr := base64.RawStdEncoding.DecodeString(input.Proof)
	identityBody, marshalErr := json.Marshal(input.Identity)
	if keyErr != nil || proofErr != nil || marshalErr != nil || !ed25519.Verify(ed25519.PublicKey(publicKey), identityBody, proof) {
		http.Error(w, "invalid ownership proof", 401)
		return
	}
	inv, err := s.Store.ConsumeInvitation(r.Context(), r.PathValue("id"), protocol.TokenHash(input.Token), input.Identity.Tenant, s.now())
	if err != nil {
		http.Error(w, err.Error(), 401)
		return
	}
	if inv.Tenant != input.Identity.Tenant {
		http.Error(w, "tenant mismatch", 403)
		return
	}
	allowed := map[string]bool{}
	for _, capability := range inv.Capabilities {
		allowed[capability] = true
	}
	for _, capability := range input.Identity.Capabilities {
		if !allowed[capability] {
			http.Error(w, "capability not invited", 403)
			return
		}
	}
	if err = s.Store.RegisterIdentity(r.Context(), input.Identity); err != nil {
		http.Error(w, "identity conflict", 409)
		return
	}
	writeJSON(w, 201, map[string]any{"clusterID": input.Identity.ClusterID, "tenant": inv.Tenant, "state": "PendingConfirmation"})
}
func (s *SovereignServer) controlMessage(w http.ResponseWriter, r *http.Request) {
	tenant, id := r.PathValue("tenant"), r.PathValue("clusterID")
	identity, err := s.Store.Identity(r.Context(), tenant, id)
	if err != nil {
		http.Error(w, "unknown identity", 401)
		return
	}
	var message model.ControlMessage
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&message) != nil {
		http.Error(w, "invalid message", 400)
		return
	}
	key, err := decodeIdentityKey(identity)
	if err != nil {
		http.Error(w, "invalid identity key", 500)
		return
	}
	last, err := s.Store.LastGeneration(r.Context(), tenant, id)
	if err != nil {
		http.Error(w, "state unavailable", 503)
		return
	}
	if err = protocol.Verify(message, ed25519.PublicKey(key), "hub", s.now(), last, nil); err != nil {
		http.Error(w, err.Error(), 401)
		return
	}
	if message.Issuer != identity.SPIFFEID || strings.HasPrefix(message.Type, "route.") {
		http.Error(w, "policy denied", 403)
		return
	}
	if message.Type == "peer.bundle.confirm" {
		var confirmation model.BundleConfirmation
		if json.Unmarshal(message.Payload, &confirmation) != nil || confirmation.PeerRef == "" || confirmation.BundleDigest == "" {
			http.Error(w, "invalid bundle confirmation", 400)
			return
		}
		if err = s.Store.ConfirmPeerBundle(r.Context(), tenant, id, confirmation); err != nil {
			http.Error(w, err.Error(), 403)
			return
		}
	}
	if err = s.Store.RecordGeneration(r.Context(), tenant, id, message.Generation, message.Nonce); err != nil {
		http.Error(w, "replay", 409)
		return
	}
	w.Header().Set("X-AmongClusters-Generation", strconv.FormatUint(message.Generation, 10))
	w.WriteHeader(202)
}
