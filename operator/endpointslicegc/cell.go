// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointslicegc

import (
	"github.com/cilium/hive/cell"
)

// Cell is a cell that implements a one-off CiliumEndpointSlice
// garbage collector.
// The GC loops through all the CiliumEndpointSlices in the cluster and deletes
// all of them, if the CES feature has been disabled.
var Cell = cell.Module(
	"k8s-endpointslice-gc",
	"CiliumEndpointSlice garbage collector",

	// Invoke forces the instantiation of the endpoint gc
	cell.Invoke(registerGC),
)
