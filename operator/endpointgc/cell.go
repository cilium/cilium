// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointgc

import (
	"time"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/metrics"
)

// Cell is a cell that implements a periodic and one-off Cilium endpoints
// garbage collector.
// The GC loops through all the Cilium Endpoints in the cluster and validates
// which one of them should be deleted. Then deleting all that should be
// deleted.
var Cell = cell.Module(
	"k8s-endpoints-gc",
	"Cilium endpoints garbage collector",

	cell.Config(defaultConfig),

	// Invoke forces the instantiation of the endpoint gc
	cell.Invoke(registerGC),

	metrics.Metric(NewMetrics),
)

// Config contains the configuration for the endpoint GC cell.
type Config struct {
	// CiliumEndpointGCInterval is the interval between attempts of the CEP GC controller.
	CiliumEndpointGCInterval time.Duration
}

var defaultConfig = Config{
	CiliumEndpointGCInterval: 5 * time.Minute,
}

// Flags registers the flags for Config.
func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Duration("cilium-endpoint-gc-interval", def.CiliumEndpointGCInterval, "GC interval for cilium endpoints")
}

// SharedConfig contains the configuration that is shared between
// this module and others.
// It is a temporary solution meant to avoid polluting this module with a direct
// dependency on global operator and daemon configurations.
type SharedConfig struct {
	// DisableCiliumEndpointCRD disables the use of CiliumEndpoint CRD
	DisableCiliumEndpointCRD bool
}
