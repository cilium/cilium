// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tables

import (
	"github.com/cilium/cilium/pkg/hive/cell"
)

var Cell = cell.Group(
	L2AnnouncementTableCell,
)
