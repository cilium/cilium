// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gc

import (
	"time"

	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/hive/cell"
)

const (
	// EndpointGCInterval is the interval between two consecutive attempts of the CEP GC.
	// Note that only one node per cluster should run this, and most iterations will simply return.
	EndpointGCInterval = "cilium-endpoint-gc-interval"
)

var Cell = cell.Module(
	"cilium-endpoints-gc",
	"Cilium endpoints garbage collector",

	cell.Config(defaultConfig),
	cell.Invoke(registerGC),
	cell.Metric(newMetrics),
)

type Config struct {
	CiliumEndpointGCInterval time.Duration
}

var defaultConfig = Config{
	CiliumEndpointGCInterval: 5 * time.Minute,
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Duration(EndpointGCInterval, defaultConfig.CiliumEndpointGCInterval, "GC interval for cilium endpoints")
}
