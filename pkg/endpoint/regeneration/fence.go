// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package regeneration

import (
	"log/slog"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/hive"
)

// Fence delays the endpoint regeneration until all registered wait functions
// have returned.
//
// A new type around [hive.Fence] to give it a unique type that can be provided
// to Hive.
type Fence hive.Fence

func NewFence(lc cell.Lifecycle, log *slog.Logger) Fence {
	return hive.NewFence(lc, log)
}
