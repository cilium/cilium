// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package infraendpoints

import "github.com/cilium/hive/cell"

// Cell is responsible to initialize the Cilium Agent "infrastructure"
// (host, health, ingress) endpoints. This includes IP allocation and
// setting up the endpoint.
var Cell = cell.Module(
	"agent-infra-endpoints",
	"Cilium Agent infrastructure endpoints",

	cell.Provide(newInfraIPAllocator),
	cell.Invoke(registerIngressEndpoint),
)
