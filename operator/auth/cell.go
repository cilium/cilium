// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package auth

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/operator/auth/spire"
)

var Cell = cell.Module(
	"auth-identity",
	"Cilium Mutual Authentication Identity management",
	spire.Cell,
	cell.Invoke(registerIdentityWatcher),
)
