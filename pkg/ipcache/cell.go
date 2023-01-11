// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import "github.com/cilium/cilium/pkg/hive/cell"

var Cell = cell.Module(
	"ipcache",
	"IPCache maps IPs to identities",

	cell.Provide(NewIPCache),
)
