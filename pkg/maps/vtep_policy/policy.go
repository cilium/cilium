// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vtep_policy

import "github.com/cilium/hive/cell"

var Cell = cell.Module(
	"vteppolicy",
	"VTEP policy provide access to the egress gateway datapath maps",
	cell.Provide(createPolicyMapFromDaemonConfig),
)
