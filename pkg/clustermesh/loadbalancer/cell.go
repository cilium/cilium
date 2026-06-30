// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loadbalancer

import (
	"github.com/cilium/hive/cell"
)

var Cell = cell.Module(
	"clustermesh-loadbalancer",
	"ClusterMesh code related to load balancer interactions",

	cell.Invoke(injectSelectBackends),

	cell.Provide(newServiceMerger),
	cell.Invoke(registerServicesInitialized),
)
