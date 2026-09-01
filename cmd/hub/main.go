package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/re8ch/among-clusters/internal/api"
	"k8s.io/client-go/dynamic"
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
	server := &api.Server{Store: &api.KubernetesStore{Client: client}}
	go (&api.Reconciler{Client: client}).Run(context.Background())
	log.Printf("AmongClusters hub listening on %s", address)
	log.Fatal(http.ListenAndServe(address, server.Handler()))
}
