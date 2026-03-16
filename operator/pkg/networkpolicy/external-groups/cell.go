// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package externalgroups

import "github.com/cilium/hive/cell"

var Cell = cell.Module(
	"network-policy-external-groups",
	"Translates external Groups references in polices to CiliumCIDRGroups",

	cell.Provide(NewExternalGroupTable),
	cell.Provide(NewGroupManager),
)
