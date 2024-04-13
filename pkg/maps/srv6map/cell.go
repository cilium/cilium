// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package srv6map

import "github.com/cilium/hive/cell"

var Cell = cell.Module(
	"srv6map",
	"SRv6 Maps",
	cell.Provide(
		newPolicyMaps,
		newVRFMaps,
		newSIDMap,
	),
	cell.Invoke(cleanupStateMap),
)
