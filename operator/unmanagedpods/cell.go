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

const (
	// UnmanagedPodWatcherInterval is the interval to check for unmanaged kube-dns pods (0 to disable)
	UnmanagedPodWatcherInterval = "unmanaged-pod-watcher-interval"
)

type Config struct {
	// Interval is the interval between checks for unmanaged pods (0 to disable)
	Interval time.Duration `mapstructure:"unmanaged-pod-watcher-interval"`
}

var defaultConfig = Config{
	Interval: 15 * time.Second,
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Duration(UnmanagedPodWatcherInterval, def.Interval, "Interval to check for unmanaged kube-dns pods (0 to disable)")
}

// SharedConfig contains the configuration that is shared between this module and others.
type SharedConfig struct {
	// DisableCiliumEndpointCRD disables the use of CiliumEndpoint CRD
	DisableCiliumEndpointCRD bool

	// K8sEnabled indicates whether Kubernetes support is enabled
	K8sEnabled bool
}
