// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"
	"log/slog"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/fqdn/bootstrap"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/promise"
)

// A new type around [hive.Fence] to give it a unique type that can be provided
// to Hive.
type Fence hive.Fence

// Create a new fence to wait on readiness of Endpoint API subsystem.
// The fence waits for queued endpoint deletions and DNS proxy initialization.
func newFence(lc cell.Lifecycle, log *slog.Logger, dq *DeletionQueue, dnsProxyPromise promise.Promise[bootstrap.DNSProxyInitialized]) Fence {
	fence := hive.NewFence(lc, log)
	fence.Add("cni-deletion-queue", dq.Wait)
	// Gate endpoint creation and updates on DNS proxy readiness even without restoration.
	// Await in the fence so this dependency does not block Hive startup.
	fence.Add("dns-proxy", func(ctx context.Context) error {
		_, err := dnsProxyPromise.Await(ctx)
		return err
	})

	return fence
}
