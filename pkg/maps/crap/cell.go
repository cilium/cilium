// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package crap

import "github.com/cilium/hive/cell"

var Cell = cell.Module(
	"crap",
	"CRAP provides direct public access",
	cell.Provide(createPolicyMapFromDaemonConfig),
)
