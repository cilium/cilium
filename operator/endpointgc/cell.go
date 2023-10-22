// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointgc

import (
	"time"

	"github.com/cilium/cilium/pkg/hive/cell"
)

// Cell is a cell that implements a periodic and one-off Cilium endpoints
// garbage collector.
// The GC loops through all the Cilium Endpoints in the cluster and validates
// which one of them should be deleted. Then deleting all that should be
// deleted.
var Cell = cell.Module(
	"k8s-endpoints-gc",
	"Cilium endpoints garbage collector",

	// Invoke forces the instantiation of the endpoint gc
	cell.Invoke(registerGC),

	cell.Metric(NewMetrics),
)

// SharedConfig contains the configuration that is shared between
// this module and others.
// It is a temporary solution meant to avoid polluting this module with a direct
// dependency on global operator and daemon configurations.
type SharedConfig struct {
	// Interval is the interval between attempts of the CEP GC controller.
	// Note that only one node per cluster should run this, and most iterations
	// will simply return.
	Interval time.Duration

	// DisableCiliumEndpointCRD disables the use of CiliumEndpoint CRD
	DisableCiliumEndpointCRD bool
}
