// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/allocator"
	cmoperator "github.com/cilium/cilium/pkg/clustermesh/operator"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	cmutils "github.com/cilium/cilium/pkg/clustermesh/utils"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/idpool"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/kvstore"
	kvstoreallocator "github.com/cilium/cilium/pkg/kvstore/allocator"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

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

func startKvstoreWatchdog(cfgMCSAPI cmoperator.MCSAPIConfig) {
	log.WithField(logfields.Interval, defaults.LockLeaseTTL).Infof("Starting kvstore watchdog")
	backend, err := kvstoreallocator.NewKVStoreBackend(cache.IdentitiesPath, "", nil, kvstore.Client())
	if err != nil {
		log.WithError(err).Fatal("Unable to initialize kvstore backend for identity garbage collection")
	}

	minID := idpool.ID(identity.GetMinimalAllocationIdentity(option.Config.ClusterID))
	maxID := idpool.ID(identity.GetMaximumAllocationIdentity(option.Config.ClusterID))
	a := allocator.NewAllocatorForGC(backend, allocator.WithMin(minID), allocator.WithMax(maxID))

	keysToDelete := map[string]kvstore.Value{}
	go func() {
		lockTimer, lockTimerDone := inctimer.New()
		defer lockTimerDone()
		for {
			keysToDelete = getOldestLeases(keysToDelete)
			ctx, cancel := context.WithTimeout(context.Background(), defaults.LockLeaseTTL)
			keysToDelete2, err := a.RunLocksGC(ctx, keysToDelete)
			if err != nil {
				log.WithError(err).Warning("Unable to run security identity garbage collector")
			} else {
				keysToDelete = keysToDelete2
			}
			cancel()

			<-lockTimer.After(defaults.LockLeaseTTL)
		}
	}()

	go func() {
		hbTimer, hbTimerDone := inctimer.New()
		defer hbTimerDone()
		for {
			ctx, cancel := context.WithTimeout(context.Background(), defaults.LockLeaseTTL)

			err := kvstore.Client().Update(ctx, kvstore.HeartbeatPath, []byte(time.Now().Format(time.RFC3339)), true)
			if err != nil {
				log.WithError(err).Warning("Unable to update heartbeat key")
			}

			if option.Config.ClusterName != defaults.ClusterName && option.Config.ClusterID != 0 {
				// The cluster config continues to be enforced also after the initial successful
				// insertion to prevent issues in case of, e.g., unexpected lease expiration.
				cfg := cmtypes.CiliumClusterConfig{
					ID: option.Config.ClusterID,
					Capabilities: cmtypes.CiliumClusterConfigCapabilities{
						MaxConnectedClusters:  option.Config.MaxConnectedClusters,
						ServiceExportsEnabled: &cfgMCSAPI.ClusterMeshEnableMCSAPI,
					}}
				if err := cmutils.SetClusterConfig(ctx, option.Config.ClusterName, cfg, kvstore.Client()); err != nil {
					log.WithError(err).Warning("Unable to set local cluster config")
				}
			}

			cancel()
			<-hbTimer.After(kvstore.HeartbeatWriteInterval)
		}
	}()
}
