// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fragmap

import "github.com/cilium/hive/cell"

var Cell = cell.Module(
	"frag-map",
	"Datagram fragment to L4 port mapping BPF map",
	cell.Provide(NewFragMap4),
	cell.Provide(NewFragMap6),
)
