package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/re8ch/among-clusters/internal/api"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func main() {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		log.Fatal(err)
	}
	client, err := dynamic.NewForConfig(cfg)
	if err != nil {
		log.Fatal(err)
	}
	address := os.Getenv("LISTEN_ADDRESS")
	if address == "" {
		address = ":8080"
	}
	core, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Fatal(err)
	}
	server := &api.SovereignServer{Store: &api.KubernetesSovereignStore{Dynamic: client, Core: core}, AdminToken: os.Getenv("ADMIN_TOKEN")}
	go (&api.SovereignReconciler{Client: client, Core: core, ManagedAccessEnabled: api.ManagedAccessFromEnv()}).Run(context.Background())
	log.Printf("AmongClusters hub listening on %s", address)
	log.Fatal(http.ListenAndServe(address, server.Handler()))
}
