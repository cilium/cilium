// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package restapi

import "github.com/cilium/cilium/pkg/hive/cell"

var Cell = cell.Module(
	"cilium-restapi",
	"Cilium Agent API handlers",

	rateLimiterCell, // Request rate-limiting
)
