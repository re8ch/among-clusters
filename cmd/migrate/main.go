package main

import (
	"context"
	"encoding/json"
	"fmt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"log"
	"os"
)

func main() {
	if os.Getenv("REPLACE_COLLABORATION_CRDS") != "true" {
		log.Fatal("destructive migration requires REPLACE_COLLABORATION_CRDS=true")
	}
	cfg, err := rest.InClusterConfig()
	if err != nil {
		log.Fatal(err)
	}
	client, err := dynamic.NewForConfig(cfg)
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	resources := []string{"collaborationclusters", "collaborationrelationships", "publishedservices", "collaborationevents"}
	for _, resource := range resources {
		gvr := schema.GroupVersionResource{Group: "collaboration.re8ch.com", Version: "v1alpha1", Resource: resource}
		list, err := client.Resource(gvr).List(ctx, metav1.ListOptions{})
		if err == nil {
			for _, item := range list.Items {
				record := map[string]any{"apiVersion": item.GetAPIVersion(), "kind": item.GetKind(), "name": item.GetName(), "spec": item.Object["spec"]}
				body, _ := json.Marshal(record)
				fmt.Printf("MIGRATION_EXPORT %s\n", body)
			}
		}
	}
	crds := client.Resource(schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"})
	for _, name := range []string{"collaborationclusters.collaboration.re8ch.com", "collaborationrelationships.collaboration.re8ch.com", "publishedservices.collaboration.re8ch.com", "collaborationevents.collaboration.re8ch.com"} {
		if err := crds.Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
			fmt.Printf("legacy CRD %s not deleted: %v\n", name, err)
		}
	}
}
