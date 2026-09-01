package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/re8ch/among-clusters/internal/model"
	"github.com/re8ch/among-clusters/internal/signing"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type agent struct {
	client                                     kubernetes.Interface
	clusterID, endpoint, namespace, secretName string
	key                                        ed25519.PrivateKey
	sequence                                   uint64
	http                                       *http.Client
}

func main() {
	ctx := context.Background()
	cfg, err := rest.InClusterConfig()
	if err != nil {
		log.Fatal(err)
	}
	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Fatal(err)
	}
	a := &agent{client: client, clusterID: mustEnv("CLUSTER_ID"), endpoint: mustEnv("HUB_ENDPOINT"), namespace: env("POD_NAMESPACE", "among-clusters"), secretName: env("IDENTITY_SECRET", "among-clusters-agent-identity"), http: &http.Client{Timeout: 10 * time.Second}}
	if err := a.loadIdentity(ctx); err != nil {
		log.Fatal(err)
	}
	interval := 15 * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := a.sendHeartbeat(ctx); err != nil {
			log.Printf("heartbeat failed: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func mustEnv(name string) string {
	v := os.Getenv(name)
	if v == "" {
		log.Fatalf("%s is required", name)
	}
	return v
}
func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func (a *agent) loadIdentity(ctx context.Context) error {
	s, err := a.client.CoreV1().Secrets(a.namespace).Get(ctx, a.secretName, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		pub, priv, err := signing.Generate()
		if err != nil {
			return err
		}
		s = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: a.secretName, Annotations: map[string]string{"collaboration.re8ch.com/sequence": "0"}}, Type: corev1.SecretTypeOpaque, Data: map[string][]byte{"private-key": priv, "public-key": pub}}
		s, err = a.client.CoreV1().Secrets(a.namespace).Create(ctx, s, metav1.CreateOptions{})
	}
	if err != nil {
		return err
	}
	if len(s.Data["private-key"]) != ed25519.PrivateKeySize {
		return fmt.Errorf("invalid private key")
	}
	a.key = ed25519.PrivateKey(s.Data["private-key"])
	a.sequence, _ = strconv.ParseUint(s.Annotations["collaboration.re8ch.com/sequence"], 10, 64)
	log.Printf("agent public key: %s", base64.RawStdEncoding.EncodeToString(s.Data["public-key"]))
	return nil
}

func (a *agent) collect(ctx context.Context) (model.Heartbeat, error) {
	version, err := a.client.Discovery().ServerVersion()
	if err != nil {
		return model.Heartbeat{}, err
	}
	nodes, err := a.client.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return model.Heartbeat{}, err
	}
	pods, err := a.client.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return model.Heartbeat{}, err
	}
	namespaces, err := a.client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return model.Heartbeat{}, err
	}
	services, err := a.client.CoreV1().Services("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return model.Heartbeat{}, err
	}
	counts := model.Counts{NodesTotal: len(nodes.Items), PodsTotal: len(pods.Items), Namespaces: len(namespaces.Items), Services: len(services.Items)}
	for _, n := range nodes.Items {
		for _, c := range n.Status.Conditions {
			if c.Type == corev1.NodeReady && c.Status == corev1.ConditionTrue {
				counts.NodesReady++
			}
		}
	}
	for _, p := range pods.Items {
		if p.Status.Phase == corev1.PodRunning {
			counts.PodsRunning++
		}
	}
	return model.Heartbeat{ClusterID: a.clusterID, ObservedAt: time.Now().UTC(), KubernetesVersion: version.GitVersion, Counts: counts}, nil
}
func (a *agent) sendHeartbeat(ctx context.Context) error {
	heartbeat, err := a.collect(ctx)
	if err != nil {
		return err
	}
	a.sequence++
	heartbeat.Sequence = a.sequence
	body, err := json.Marshal(heartbeat)
	if err != nil {
		return err
	}
	timestamp := time.Now().UTC()
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/v1/agents/%s/heartbeat", a.endpoint, a.clusterID), bytes.NewReader(body))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-AmongClusters-Timestamp", timestamp.Format(time.RFC3339Nano))
	request.Header.Set("X-AmongClusters-Sequence", strconv.FormatUint(a.sequence, 10))
	request.Header.Set("X-AmongClusters-Signature", signing.Sign(a.key, timestamp, a.sequence, body))
	response, err := a.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		return fmt.Errorf("hub returned %s", response.Status)
	}
	secret, err := a.client.CoreV1().Secrets(a.namespace).Get(ctx, a.secretName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if secret.Annotations == nil {
		secret.Annotations = map[string]string{}
	}
	secret.Annotations["collaboration.re8ch.com/sequence"] = strconv.FormatUint(a.sequence, 10)
	_, err = a.client.CoreV1().Secrets(a.namespace).Update(ctx, secret, metav1.UpdateOptions{})
	return err
}
