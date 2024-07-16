// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identitymanager

import "github.com/cilium/hive/cell"

var Cell = cell.Module(
	"identity-manager",
	"Identity manager tracks identities assigned to locally managed endpoints ",
	cell.Provide(NewIdentityManager),
)
