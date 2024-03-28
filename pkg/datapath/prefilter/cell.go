// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package prefilter

import "github.com/cilium/hive/cell"

// Cell provides prefilter, a means of configuring XDP pre-filters for DDoS-mitigation.
var Cell = cell.Module(
	"prefilter",
	"Provides a means of configuring XDP pre-filters for DDoS-mitigation",

	cell.Provide(NewPreFilter),
)
