# AmongClusters

**Mesh clusters you don't control.**

AmongClusters is a Sovereign Cluster Peering control plane for BYOC services.
Each Kubernetes cluster remains an independent trust domain: it retains its API
server, CA, RBAC, scheduler and lifecycle authority. The hosted Hub distributes
signed identities, trust bundles, gateway endpoints and explicit service
advertisements; it does not receive Kubernetes credentials and is not in the
default application data path.

## Trust model

- An owner-side Agent creates and retains cluster identity material locally.
- Invitations are tenant-bound, short-lived and single-use; the Hub stores only
  their hashes.
- A Peer becomes eligible only after both owners confirm the other's bundle
  digest.
- Gateways use TLS 1.3 mutual authentication over QUIC and accept certificates
  only from explicitly installed peer bundles with SPIFFE-compatible identities.
- v1 advertises selected L4/L7 services only. It does not synchronize PodCIDRs,
  EndpointSlices, Pod addresses or remote API secrets.
- `ManagedAccessGrant` is an optional, separately gated contract. It is disabled
  by default and stores only an opaque Credential Broker reference.

The API group is `peering.re8ch.com/v1alpha1`. Its namespace-scoped resources are
`ClusterIdentity`, `Peer`, `AuthenticatedLink`, `PeerPolicy`,
`ServiceAdvertisement`, `ImportedService` and `ManagedAccessGrant`.

## Charts

Four OCI charts are released independently under `ghcr.io/re8ch/charts`:

- `among-clusters`: umbrella chart with role switches.
- `among-clusters-hub`: rendezvous API, controller, CRDs and audit control plane.
- `among-clusters-agent`: owner-side identity Agent and QUIC Gateway.
- `among-clusters-headlamp`: installer for the digest-checked read-only plugin.

Images must be configured by immutable `sha256:` digest. The Agent receives a
projected Kubernetes token and namespace-local read access to explicitly labelled
Services. The Gateway is a separate pod with no service-account token; its UDP
listener is off until a public endpoint and a confirmed peer-bundle Secret are
configured.

## Explicit service and managed access flow

A Service is exported only when it has `peering.re8ch.com/advertise=true` plus
the `protocol`, `service-class`, `policy-ref`, `target-peers` and `ttl-seconds`
annotations. The Agent sends the full contract in a signed `service.snapshot`;
the Hub accepts it only when the referenced `PeerPolicy` permits the publisher,
peer, class, protocol, port and export direction. Removed labels revoke the
advertisement. The QUIC Gateway routes streams by SPIFFE service identity and
never exposes Pod or EndpointSlice addresses. Each export also carries its
target Peer refs; `gateway.peerIdentities` binds those refs to allowed caller
SPIFFE IDs so trust-bundle membership alone never grants service access.

Managed Kubernetes access requires both `spec.approved=true` on the Hub grant
and an owner-created `among-clusters-approval-<grant>` ConfigMap in the BYOC
cluster. Only then does the Agent create namespace Roles, or a rule-defined
ClusterRole when the grant explicitly sets `scope: Cluster`, issue a short-lived
TokenRequest, encrypt it to the Broker X25519 public key and submit it directly
to the Broker. The Hub stores only
`credential://among-clusters/<tenant>/<grant>`. Headlamp uses the Broker's
internal Kubernetes proxy; browsers never receive the Kubernetes token.
The local approval records the grant's Kubernetes generation, so every change
to scope, rules, target or expiry requires a fresh owner approval.

## Breaking migration from 0.1

Version 0.2.0 replaces the experimental `Collaboration*` API. Helm never deletes
the old CRDs automatically. First export and review the old objects, then perform
the explicit destructive upgrade with `migration.replaceCollaborationCRDs=true`.
The migration Job emits sanitized object specifications before deleting the four
legacy CRDs. Secrets and status payloads are not exported. Keep the logs as the
review artifact before initializing new peering objects.

## Headlamp

`ui/headlamp-plugin` is an independent, read-only Headlamp package. It displays
trust domains, peers, authenticated links, advertisements, imported services,
certificate/bundle state and failure reasons. It has no mutations, Secret reads,
credential rendering or remote Kubernetes operations. The native Headlamp
Artifact Hub metadata lives under `artifacthub/headlamp`.

Release tags publish multi-architecture images with SBOM/provenance, all four
OCI charts, signatures, Artifact Hub repository metadata, and the versioned
Headlamp archive with its SHA-256 metadata.
