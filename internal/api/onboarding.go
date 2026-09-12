package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/re8ch/among-clusters/internal/model"
	"github.com/re8ch/among-clusters/internal/protocol"
)

var onboardingName = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`)

type OnboardingConfig struct {
	PublicEndpoint       string
	Tenant               string
	ProviderSPIFFEID     string
	ProviderBundleDigest string
	ProviderQUICEndpoint string
	ImageDigest          string
	ChartVersion         string
	ProviderBundlePEM    []byte
}

func (s *SovereignServer) createOnboardingLink(w http.ResponseWriter, r *http.Request) {
	if s.AdminToken == "" || r.Header.Get("Authorization") != "Bearer "+s.AdminToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var input struct {
		ClusterID  string `json:"clusterID"`
		Region     string `json:"region"`
		TTLSeconds int    `json:"ttlSeconds"`
	}
	if decodeJSON(w, r, &input) != nil || !onboardingName.MatchString(input.ClusterID) || !onboardingName.MatchString(input.Region) || s.Onboarding.Tenant == "" || s.Onboarding.PublicEndpoint == "" {
		http.Error(w, "clusterID and region must be DNS-safe", http.StatusBadRequest)
		return
	}
	if input.TTLSeconds == 0 {
		input.TTLSeconds = 86400
	}
	if input.TTLSeconds < 60 || input.TTLSeconds > 86400 {
		http.Error(w, "invalid ttl", 400)
		return
	}
	id, err := protocol.RandomID(12)
	if err != nil {
		http.Error(w, "entropy unavailable", 503)
		return
	}
	token, err := protocol.RandomToken(32)
	if err != nil {
		http.Error(w, "entropy unavailable", 503)
		return
	}
	claim := model.OnboardingClaim{ID: id, ClusterID: input.ClusterID, Region: input.Region, Tenant: s.Onboarding.Tenant, TokenHash: protocol.TokenHash(token), ExpiresAt: s.now().Add(time.Duration(input.TTLSeconds) * time.Second)}
	if err = s.Store.CreateOnboardingClaim(r.Context(), claim); err != nil {
		http.Error(w, "conflict", 409)
		return
	}
	url := strings.TrimRight(s.Onboarding.PublicEndpoint, "/") + "/v1/onboarding/" + id + "?claim=" + token
	writeJSON(w, 201, map[string]any{"clusterID": input.ClusterID, "region": input.Region, "claimURL": url, "expiresAt": claim.ExpiresAt})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, value any) error {
	return json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(value)
}

func (s *SovereignServer) consumeOnboarding(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	claim, err := s.Store.ConsumeOnboardingClaim(r.Context(), s.Onboarding.Tenant, r.PathValue("id"), protocol.TokenHash(r.URL.Query().Get("claim")), s.now())
	if err != nil {
		if strings.Contains(err.Error(), "used") || strings.Contains(err.Error(), "expired") {
			http.Error(w, err.Error(), http.StatusGone)
		} else {
			http.Error(w, "invalid claim", http.StatusUnauthorized)
		}
		return
	}
	invitationID, err := protocol.RandomID(12)
	if err != nil {
		http.Error(w, "entropy unavailable", 503)
		return
	}
	invitationToken, err := protocol.RandomToken(32)
	if err != nil {
		http.Error(w, "entropy unavailable", 503)
		return
	}
	invitation := model.Invitation{ID: invitationID, Tenant: claim.Tenant, ClusterID: claim.ClusterID, Region: claim.Region, ExpiresAt: s.now().Add(15 * time.Minute), Capabilities: []string{"service", "quic-mtls"}, TokenHash: protocol.TokenHash(invitationToken)}
	if err = s.Store.CreateInvitation(r.Context(), invitation); err != nil {
		http.Error(w, "invitation creation failed; request a new link", 503)
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="among-clusters-%s.md"`, claim.ClusterID))
	_, _ = fmt.Fprint(w, s.installMarkdown(claim, invitationID, invitationToken))
}

func (s *SovereignServer) providerBundle(w http.ResponseWriter, _ *http.Request) {
	if len(s.Onboarding.ProviderBundlePEM) == 0 {
		http.Error(w, "provider bundle unavailable", 503)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = w.Write(s.Onboarding.ProviderBundlePEM)
}

func (s *SovereignServer) installMarkdown(c model.OnboardingClaim, invitationID, invitationToken string) string {
	o := s.Onboarding
	return fmt.Sprintf(`# AmongClusters installation for %s

Region: **%s**. This document contains a 15-minute, single-use invitation. Do not commit or forward it.

## Components

- **Agent** creates and retains this cluster's Ed25519/SPIFFE identity, accepts the invitation, and sends signed control-plane heartbeats.
- **Gateway** keeps an outbound mutual-TLS QUIC session to the provider; no public inbound port is required.
- **Invitation Secret** is bootstrap-only and becomes useless after the first accepted registration.
- **Peer bundle Secret** contains only the provider's public CA and is used to authenticate its Gateway.
- **Imported Mihomos service** exposes a cluster-local SOCKS5 endpoint on port 17891 after both sides confirm their CA digests and the Peer becomes Ready.

## Install

Prerequisites: kubectl, Helm 3, TCP/443 to %[3]s and UDP to %[4]s.

~~~bash
export CLUSTER_ID='%[1]s'
export REGION='%[2]s'
export INVITATION_ID='%[5]s'
export INVITATION_TOKEN='%[6]s'

kubectl create namespace among-clusters --dry-run=client -o yaml | kubectl apply -f -
curl -fsS '%[3]s/v1/provider-bundle' -o re8ch-peer-ca.crt
kubectl -n among-clusters create secret generic among-clusters-invitation --from-literal=invitation-id="$INVITATION_ID" --from-literal=token="$INVITATION_TOKEN"
kubectl -n among-clusters create secret generic among-clusters-peer-bundle --from-file=ca.crt=./re8ch-peer-ca.crt

helm upgrade --install among-clusters-agent oci://ghcr.io/among-clusters/charts/among-clusters-agent --version %[7]s --namespace among-clusters \
  --set-string clusterID="$CLUSTER_ID" --set-string tenant=%[8]s --set-string trustDomain="$CLUSTER_ID.byoc" \
  --set-string hubEndpoint=%[3]s --set-string image.repository=ghcr.io/among-clusters/among-clusters --set-string image.digest=%[9]s \
  --set-string gateway.peerBundleSecret=among-clusters-peer-bundle \
  --set-string "peerConfirmations[0].peerRef=re8ch-$CLUSTER_ID" --set-string "peerConfirmations[0].bundleDigest=%[10]s" \
  --set-string "gateway.sessions[0].endpoint=%[4]s" --set-string "gateway.sessions[0].expectedSPIFFEID=%[11]s" \
  --set-string "gateway.imports[0].name=mihomos-egress" --set "gateway.imports[0].port=17891" --set-string "gateway.imports[0].listen=:17891" \
  --set-string "gateway.imports[0].serviceIdentity=spiffe://re8ch.internal/ns/egress-fabric/service/mihomos-byoc-egress" \
  --set-string "gateway.imports[0].expectedSPIFFEID=%[11]s" --set "gateway.imports[0].sessionOnly=true"

kubectl -n among-clusters rollout status deployment/among-clusters-agent --timeout=120s
kubectl -n among-clusters get secret among-clusters-agent-identity -o jsonpath='{.data.bundle\.pem}' | base64 -d > "$CLUSTER_ID-ca.crt"
sha256sum "$CLUSTER_ID-ca.crt"
~~~

Return only the public CA file and digest to the provider. Never return tls.key, private-key, kubeconfig, or a ServiceAccount token.
`, c.ClusterID, c.Region, strings.TrimRight(o.PublicEndpoint, "/"), o.ProviderQUICEndpoint, invitationID, invitationToken, o.ChartVersion, o.Tenant, o.ImageDigest, o.ProviderBundleDigest, o.ProviderSPIFFEID)
}
