# AmongClusters

AmongClusters is an independent control plane for recording collaboration between
autonomous Kubernetes clusters. It is not a Headlamp authentication mechanism and
does not proxy user access to member clusters.

Each cluster runs an owner-controlled agent. The agent sends only signed health
summaries and collaboration events over outbound HTTPS. The Hub stores desired
relationships and published-service contracts in Kubernetes CRDs and owns only
their runtime status.

## Trust boundaries

- Agent Ed25519 private keys are generated and retained in the owner cluster.
- The Hub stores public keys only and rejects replayed, stale or invalid requests.
- No Kubernetes object bodies, Secrets, tenant data or implicit service networking
  are shared.
- Human Headlamp OIDC/RBAC access is separate from AmongClusters health.

## Components

- `cmd/hub`: signed ingest API and CRD reconciliation.
- `cmd/agent`: local summary collector and signed heartbeat sender.
- `charts/among-clusters-hub`: Hub CRDs, API, Gateway and policy.
- `charts/among-clusters-agent`: owner-side agent, minimal RBAC and identity Secret lifecycle.

The Headlamp plugin is a read-only view over the Hub CRDs. It must never probe a
remote cluster context to derive collaboration health.
