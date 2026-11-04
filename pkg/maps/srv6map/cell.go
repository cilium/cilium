// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package srv6map

import "github.com/cilium/hive/cell"

// We need to create and pin these maps even if `EnableSRv6` is not enabled.
// This is because these maps are referenced by the eBPF programs,
// even if the feature is not enabled in the datapath.
// Therefore, to avoid race conditions on creation and pinning,
// we create and pin the maps regardless of the feature flag.
var Cell = cell.Module(
	"srv6map",
	"SRv6 Maps",
	cell.Provide(
		newPolicyMaps,
		newVRFMaps,
		newSIDMap,
	),
)
