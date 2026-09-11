# AmongClusters Headlamp Plugin

View of `peering.re8ch.com/v1alpha1` trust domains, peers, authenticated links and explicit service advertisements. It also renders operator-created, one-time onboarding claim URLs from the `among-clusters-onboarding-links` ConfigMap. It never probes remote clusters, reads Secrets or mutates Kubernetes resources.

`links.json` is an array of `{clusterID, region, claimURL, expiresAt}`. The opaque URL is a short-lived bearer capability: restrict ConfigMap read access to the intended Headlamp operators. Copying does not consume it; the external operator's first HTTP POST does, and returns installation Markdown. Reuse returns HTTP 410.
