// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dra

import (
	"github.com/cilium/hive/cell"
)

// Cell implements a network driver to manage DRA resources.
var Cell = cell.Module(
	"dra-driver",
	"Cilium network DRA driver",

	cell.Invoke(registerDRA),
)
