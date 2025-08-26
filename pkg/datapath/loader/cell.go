// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"github.com/cilium/hive/cell"

	datapath "github.com/cilium/cilium/pkg/datapath/types"
)

var Cell = cell.Module(
	"loader",
	"Loader",

	cell.Provide(NewLoader),
	cell.Provide(NewCompilationLock),
)

// NewLoader returns a new loader.
func NewLoader(p Params) datapath.Loader {
	return newLoader(p)
}
