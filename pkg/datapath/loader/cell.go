// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	loaderTypes "github.com/cilium/cilium/pkg/datapath/loader/types"
	"github.com/cilium/cilium/pkg/hive/cell"
)

var Cell = cell.Module(
	"loader",
	"Loader",
	cell.Provide(NewLoader),
)

// NewLoader returns a new loader.
func NewLoader(sc sysctl.Sysctl) loaderTypes.Loader {
	return newLoader(sc)
}
