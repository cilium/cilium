// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package labelsfilterdynamic

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/labelsfilterdynamic/signals"
)

var Cell = cell.Module(
	"dlf-policy-watcher",
	"Watches network policies events to update dynamic label filter",

	cell.ProvidePrivate(signals.NewSignal),
	cell.Invoke(registerController),
)
