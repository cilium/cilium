// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package unmanagedpods

import (
	"time"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/metrics"
)

// Cell is a cell that implements a controller for restarting pods without
// CiliumEndpoint CRDs. This is primarily used to restart kube-dns pods that
// may have started before Cilium was ready.
var Cell = cell.Module(
	"unmanaged-pods-gc",
	"Garbage collector for pods without CiliumEndpoints",

	cell.Config(defaultConfig),
	cell.Invoke(registerController),
	metrics.Metric(NewMetrics),
)

type Config struct {
	// UnmanagedPodWatcherInterval is the interval between checks for unmanaged pods (0 to disable)
	UnmanagedPodWatcherInterval time.Duration

	// PodRestartSelector is the label selector for pods that should be
	// restarted if not managed by Cilium.
	PodRestartSelector string
}

var defaultConfig = Config{
	UnmanagedPodWatcherInterval: 15 * time.Second,
	PodRestartSelector:          "k8s-app=kube-dns",
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Duration("unmanaged-pod-watcher-interval", def.UnmanagedPodWatcherInterval, "Interval to check for unmanaged kube-dns pods (0 to disable)")
	flags.String("pod-restart-selector", def.PodRestartSelector, "cilium-operator will delete/restart any pods with these labels if the pod is not managed by Cilium. If this option is empty, then all pods may be restarted")
}

// SharedConfig contains the configuration that is shared between this module and others.
type SharedConfig struct {
	// DisableCiliumEndpointCRD disables the use of CiliumEndpoint CRD
	DisableCiliumEndpointCRD bool

	// K8sEnabled indicates whether Kubernetes support is enabled
	K8sEnabled bool
}
