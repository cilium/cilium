// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lxcmap

import "github.com/cilium/hive/cell"

var Cell = cell.Module(
	"lxc-map",
	"Local endpoint BPF map",
	cell.Provide(NewLXCMap),
)
