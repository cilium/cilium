// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package locksweeper

import (
	"context"
	"errors"
	"log/slog"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/pkg/allocator"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/kvstore"
	kvstoreallocator "github.com/cilium/cilium/pkg/kvstore/allocator"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type params struct {
	cell.In

	Logger      *slog.Logger
	JobGroup    job.Group
	Client      kvstore.Client
	ClusterInfo cmtypes.ClusterInfo
}

func runLockSweeper(p params) {
	if !p.Client.IsEnabled() {
		return
	}

	p.Logger.Info("Starting kvstore lock sweeper", logfields.Interval, defaults.LockLeaseTTL)

	backend, err := kvstoreallocator.NewKVStoreBackend(p.Logger, kvstoreallocator.KVStoreBackendConfiguration{
		BasePath: cache.IdentitiesPath,
		Backend:  p.Client,
	})
	if err != nil {
		logging.Fatal(p.Logger, "Unable to initialize kvstore backend for stale locks collection", logfields.Error, err)
	}

	minID := idpool.ID(identity.GetMinimalAllocationIdentity(p.ClusterInfo.ID))
	maxID := idpool.ID(identity.GetMaximumAllocationIdentity(p.ClusterInfo.ID))
	a := allocator.NewAllocatorForGC(p.Logger, backend, allocator.WithMin(minID), allocator.WithMax(maxID))

	keysToDelete := map[string]kvstore.Value{}

	p.JobGroup.Add(
		job.Timer("kvstore-lock-sweeper", func(ctx context.Context) error {
			ctxTimeout, cancel := context.WithTimeout(ctx, defaults.LockLeaseTTL)
			defer cancel()

			keysToDelete = getOldestLeases(keysToDelete)
			keysToDeleteNext, err := a.RunLocksGC(ctxTimeout, keysToDelete)
			if err != nil && !errors.Is(ctx.Err(), context.Canceled) {
				p.Logger.Warn("Unable to run stale locks collector", logfields.Error, err)
				return err
			}
			keysToDelete = keysToDeleteNext

			return nil
		}, defaults.LockLeaseTTL),
	)
}

// getOldestLeases returns the value that has the smaller revision for each
// 'path'. A 'path' shares the same common prefix for different locks.
func getOldestLeases(lockPaths map[string]kvstore.Value) map[string]kvstore.Value {
	type LockValue struct {
		kvstore.Value
		keyPath string
	}
	oldestPaths := map[string]LockValue{}
	for lockPath, v := range lockPaths {
		keyPath := keyPathFromLockPath(lockPath)
		oldestKeyPath, ok := oldestPaths[keyPath]
		if !ok || v.ModRevision < oldestKeyPath.ModRevision {
			// Store the oldest common path
			oldestPaths[keyPath] = LockValue{
				keyPath: lockPath,
				Value:   v,
			}
		}
	}
	oldestLeases := map[string]kvstore.Value{}
	for _, v := range oldestPaths {
		// Retrieve the oldest lock path
		oldestLeases[v.keyPath] = v.Value
	}
	return oldestLeases
}

// keyPathFromLockPath returns the path of the given key that contains a lease
// prefixed to its path.
func keyPathFromLockPath(k string) string {
	// vendor/go.etcd.io/etcd/clientv3/concurrency/mutex.go:L46
	i := strings.LastIndexByte(k, '/')
	if i >= 0 {
		return k[:i]
	}
	return k
}
