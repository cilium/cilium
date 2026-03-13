// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	defaultOutputPath = "/var/run/cilium/envoy-locality-config/service-zone"
	nodeZoneLabel     = corev1.LabelTopologyZone
)

func main() {
	var (
		outputPath     string
		nodeName       string
		retryInterval  time.Duration
		requestTimeout time.Duration
		maxAttempts    int
	)

	flag.StringVar(&outputPath, "output", defaultOutputPath, "Path to write the local node zone for Envoy --service-zone")
	flag.StringVar(&nodeName, "node-name", os.Getenv("K8S_NODE_NAME"), "Kubernetes node name (default: K8S_NODE_NAME env)")
	flag.DurationVar(&retryInterval, "retry-interval", time.Second, "Interval between node-zone lookup retries")
	flag.DurationVar(&requestTimeout, "request-timeout", 2*time.Second, "Timeout per node-zone lookup request")
	flag.IntVar(&maxAttempts, "max-attempts", 3, "Maximum node-zone lookup attempts")
	flag.Parse()

	if nodeName == "" {
		log.Fatalf("missing --node-name and K8S_NODE_NAME is empty")
	}

	cfg, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("build in-cluster config: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Fatalf("build kubernetes client: %v", err)
	}

	zone, err := lookupNodeZoneWithRetry(context.Background(), clientset, nodeName, maxAttempts, requestTimeout, retryInterval)
	if err != nil {
		log.Printf("warning: failed to resolve node zone for %q: %v", nodeName, err)
		zone = ""
	}

	if err := writeZoneOutput(outputPath, zone); err != nil {
		log.Fatalf("write service zone output: %v", err)
	}

	log.Printf("service-zone output written to %s (node=%s zone=%q)", outputPath, nodeName, zone)
}

func lookupNodeZoneWithRetry(ctx context.Context, client kubernetes.Interface, nodeName string, maxAttempts int, requestTimeout, retryInterval time.Duration) (string, error) {
	if maxAttempts <= 0 {
		maxAttempts = 1
	}

	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
		zone, err := lookupNodeZone(reqCtx, client, nodeName)
		cancel()
		if err == nil {
			return zone, nil
		}
		lastErr = err
		if attempt < maxAttempts {
			time.Sleep(retryInterval)
		}
	}

	return "", fmt.Errorf("lookup failed after %d attempts: %w", maxAttempts, lastErr)
}

func lookupNodeZone(ctx context.Context, client kubernetes.Interface, nodeName string) (string, error) {
	node, err := client.CoreV1().Nodes().Get(ctx, nodeName, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("get node %q: %w", nodeName, err)
	}

	zone := node.Labels[nodeZoneLabel]
	if zone == "" {
		return "", fmt.Errorf("node %q has no %q label", nodeName, nodeZoneLabel)
	}

	return zone, nil
}

func writeZoneOutput(outputPath, zone string) error {
	if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	if err := os.WriteFile(outputPath, []byte(zone), 0644); err != nil {
		return fmt.Errorf("write output file: %w", err)
	}
	return nil
}
