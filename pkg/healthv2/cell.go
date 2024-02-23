// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package healthv2

import "github.com/cilium/cilium/pkg/hive/cell"

var Cell = cell.Module(
	"healthv2",
	"Modular Health Provider V2",
	cell.Provide(newHealthV2Provider),
)
