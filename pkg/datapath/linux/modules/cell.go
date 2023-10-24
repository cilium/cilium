// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package modules

import "github.com/cilium/cilium/pkg/hive/cell"

var Cell = cell.Module(
	"kernel-modules-manager",
	"Load kernel modules required by Cilium",

	cell.Provide(newManager),
)
