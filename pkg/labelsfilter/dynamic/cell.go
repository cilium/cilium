// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dynamic

import (
	"github.com/cilium/cilium/pkg/labelsfilter/dynamic/signals"
	"github.com/cilium/hive/cell"
)

var Cell = cell.Module(
	"dlf-policy-watcher",
	"Watches network policies events to update dynamic label filter",

	cell.ProvidePrivate(signals.NewSignal),
	cell.Invoke(registerController),
)
