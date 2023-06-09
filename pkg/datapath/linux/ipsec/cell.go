// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipsec

import "github.com/cilium/cilium/pkg/hive/cell"

var Cell = cell.Module(
	"ipsec",
	"IPSec",
	cell.Metric(NewIPSecMetrics),
)
