// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import "github.com/cilium/hive/cell"

var Cell = cell.Module(
	"ipcache-map",
	"IPCache BPF Map",

	cell.Provide(NewMap),
)
