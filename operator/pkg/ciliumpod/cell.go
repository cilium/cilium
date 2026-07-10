// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package ciliumpod provides a shared configuration identifying the Cilium
// agent pods in the cluster (namespace and label selector).
package ciliumpod

import (
	"cmp"
	"fmt"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	"github.com/cilium/cilium/pkg/option"
)

// Cell registers the shared Cilium-pod configuration.
var Cell = cell.Module(
	"cilium-pod-config",
	"Configuration identifying the Cilium agent pods in the cluster",

	cell.Config(defaultConfig),
)

// Config identifies the Cilium agent pods in the cluster.
type Config struct {
	Namespace string `mapstructure:"cilium-pod-namespace"`
	Labels    string `mapstructure:"cilium-pod-labels"`
}

var defaultConfig = Config{
	Namespace: "",
	Labels:    "k8s-app=cilium",
}

func (c Config) Flags(flags *pflag.FlagSet) {
	flags.String("cilium-pod-namespace", defaultConfig.Namespace,
		fmt.Sprintf("Name of the Kubernetes namespace in which Cilium is deployed in. Defaults to the same namespace defined in %s", option.K8sNamespaceName))
	flags.String("cilium-pod-labels", defaultConfig.Labels,
		"Cilium Pod's labels selector. Used to detect if a Cilium pod is running to remove the node taints where its running and set NetworkUnavailable to false")
}

// ResolveNamespace returns the configured Namespace, falling back to the
// provided fallback namespace and then to metav1.NamespaceDefault when empty.
func (c Config) ResolveNamespace(fallback string) string {
	return cmp.Or(c.Namespace, fallback, metav1.NamespaceDefault)
}

// Selector parses Labels into a labels.Selector.
func (c Config) Selector() (labels.Selector, error) {
	return labels.Parse(c.Labels)
}
