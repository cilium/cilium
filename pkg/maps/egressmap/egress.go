// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressmap

import "github.com/cilium/cilium/pkg/hive/cell"

var Cell = cell.Module(
	"egressmaps",
	"Egressmaps provide access to the egress gateway datapath maps",
	cell.Config(DefaultPolicyConfig),
	cell.Provide(createPolicyMapFromDaemonConfig),
)
