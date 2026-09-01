package model

import "time"

type Counts struct {
	NodesReady  int `json:"nodesReady"`
	NodesTotal  int `json:"nodesTotal"`
	PodsRunning int `json:"podsRunning"`
	PodsTotal   int `json:"podsTotal"`
	Namespaces  int `json:"namespaces"`
	Services    int `json:"services"`
}

type ServiceObservation struct {
	Name          string    `json:"name"`
	Healthy       bool      `json:"healthy"`
	LatencyMillis int64     `json:"latencyMillis,omitempty"`
	ObservedAt    time.Time `json:"observedAt"`
}

type Heartbeat struct {
	ClusterID         string               `json:"clusterID"`
	Sequence          uint64               `json:"sequence"`
	ObservedAt        time.Time            `json:"observedAt"`
	KubernetesVersion string               `json:"kubernetesVersion"`
	Counts            Counts               `json:"counts"`
	Services          []ServiceObservation `json:"services,omitempty"`
}

type Event struct {
	ClusterID  string            `json:"clusterID"`
	Sequence   uint64            `json:"sequence"`
	OccurredAt time.Time         `json:"occurredAt"`
	Type       string            `json:"type"`
	Subject    string            `json:"subject,omitempty"`
	Details    map[string]string `json:"details,omitempty"`
}

type Envelope struct {
	Timestamp time.Time `json:"timestamp"`
	Sequence  uint64    `json:"sequence"`
	Body      []byte    `json:"body"`
	Signature string    `json:"signature"`
}
