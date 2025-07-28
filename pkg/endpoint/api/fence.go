// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"log/slog"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/hive"
)

// A new type around [hive.Fence] to give it a unique type that can be provided
// to Hive.
type Fence hive.Fence

// Create a new fence to wait on readiness of Endpoint API subsystem.
// The fence is unblocked once the endpoint DeletionQueue processing is complete.
func newFence(lc cell.Lifecycle, log *slog.Logger, dq *DeletionQueue) Fence {
	fence := hive.NewFence(lc, log)
	fence.Add("cni-deletion-queue", dq.Wait)

	return fence
}
