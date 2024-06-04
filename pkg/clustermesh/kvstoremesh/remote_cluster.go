// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstoremesh

import (
	"context"
	"fmt"
	"path"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/clustermesh/common"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	cmutils "github.com/cilium/cilium/pkg/clustermesh/utils"
	"github.com/cilium/cilium/pkg/clustermesh/wait"
	identityCache "github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
	nodeStore "github.com/cilium/cilium/pkg/node/store"
	serviceStore "github.com/cilium/cilium/pkg/service/store"
)

// remoteCluster represents a remote cluster other than the local one this
// service is running in
type remoteCluster struct {
	name string

	localBackend kvstore.BackendOperations

	nodes      reflector
	services   reflector
	identities reflector
	ipcache    reflector

	// status is the function which fills the common part of the status.
	status common.StatusFunc

	cancel context.CancelFunc
	wg     sync.WaitGroup

	storeFactory store.Factory

	// synced tracks the initial synchronization of the remote cluster.
	synced synced
	// readyTimeout is the duration to wait for a connection to be established
	// before removing the cluster from readiness checks.
	readyTimeout time.Duration

	logger logrus.FieldLogger
}

func (rc *remoteCluster) Run(ctx context.Context, backend kvstore.BackendOperations, srccfg types.CiliumClusterConfig, ready chan<- error) {
	// Closing the synced.connected channel cancels the timeout goroutine.
	// Ensure we do not attempt to close the channel more than once.
	select {
	case <-rc.synced.connected:
	default:
		close(rc.synced.connected)
	}

	dstcfg := types.CiliumClusterConfig{
		ID: srccfg.ID,
		Capabilities: types.CiliumClusterConfigCapabilities{
			SyncedCanaries:       true,
			Cached:               true,
			MaxConnectedClusters: srccfg.Capabilities.MaxConnectedClusters,
		},
	}

	stopAndWait, err := cmutils.EnforceClusterConfig(ctx, rc.name, dstcfg, rc.localBackend, rc.logger)
	defer stopAndWait()
	if err != nil {
		ready <- fmt.Errorf("failed to propagate cluster configuration: %w", err)
		close(ready)
		return
	}

	var mgr store.WatchStoreManager
	if srccfg.Capabilities.SyncedCanaries {
		mgr = rc.storeFactory.NewWatchStoreManager(backend, rc.name)
	} else {
		mgr = store.NewWatchStoreManagerImmediate(rc.name)
	}

	adapter := func(prefix string) string { return prefix }
	if srccfg.Capabilities.Cached {
		adapter = kvstore.StateToCachePrefix
	}

	mgr.Register(adapter(nodeStore.NodeStorePrefix), func(ctx context.Context) {
		rc.nodes.watcher.Watch(ctx, backend, path.Join(adapter(nodeStore.NodeStorePrefix), rc.name))
	})

	mgr.Register(adapter(serviceStore.ServiceStorePrefix), func(ctx context.Context) {
		rc.services.watcher.Watch(ctx, backend, path.Join(adapter(serviceStore.ServiceStorePrefix), rc.name))
	})

	mgr.Register(adapter(ipcache.IPIdentitiesPath), func(ctx context.Context) {
		suffix := ipcache.DefaultAddressSpace
		if srccfg.Capabilities.Cached {
			suffix = rc.name
		}

		rc.ipcache.watcher.Watch(ctx, backend, path.Join(adapter(ipcache.IPIdentitiesPath), suffix))
	})

	mgr.Register(adapter(identityCache.IdentitiesPath), func(ctx context.Context) {
		var suffix string
		if srccfg.Capabilities.Cached {
			suffix = rc.name
		}

		rc.identities.watcher.Watch(ctx, backend, path.Join(adapter(identityCache.IdentitiesPath), suffix))
	})

	close(ready)
	mgr.Run(ctx)
}

func (rc *remoteCluster) Stop() {
	rc.cancel()
	rc.synced.Stop()
	rc.wg.Wait()
}

func (rc *remoteCluster) Remove() {
	// Cluster specific keys are not explicitly removed, but they will be
	// disappear once the associated lease expires.
}

// waitForConnection waits for a connection to be established to the remote cluster.
// If the connection is not established within the timeout, the remote cluster is
// removed from readiness checks.
func (rc *remoteCluster) waitForConnection(ctx context.Context) {
	select {
	case <-ctx.Done():
	case <-rc.synced.connected:
	case <-time.After(rc.readyTimeout):
		rc.logger.Info("Remote cluster did not connect within timeout, removing from readiness checks")
		for {
			select {
			case <-rc.synced.resources.WaitChannel():
				return
			default:
				rc.synced.resources.Done()
			}
		}
	}
}

func (rc *remoteCluster) Status() *models.RemoteCluster {
	status := rc.status()

	status.NumNodes = int64(rc.nodes.watcher.NumEntries())
	status.NumSharedServices = int64(rc.services.watcher.NumEntries())
	status.NumIdentities = int64(rc.identities.watcher.NumEntries())
	status.NumEndpoints = int64(rc.ipcache.watcher.NumEntries())

	status.Synced = &models.RemoteClusterSynced{
		Nodes:      rc.nodes.watcher.Synced(),
		Services:   rc.services.watcher.Synced(),
		Identities: rc.identities.watcher.Synced(),
		Endpoints:  rc.ipcache.watcher.Synced(),
	}

	status.Ready = status.Ready &&
		status.Synced.Nodes && status.Synced.Services &&
		status.Synced.Identities && status.Synced.Endpoints

	return status
}

type reflector struct {
	watcher store.WatchStore
	syncer  syncer
}

type syncer struct {
	store.SyncStore
	synced *lock.StoppableWaitGroup
}

func (o *syncer) OnUpdate(key store.Key) {
	o.UpsertKey(context.Background(), key)
}

func (o *syncer) OnDelete(key store.NamedKey) {
	o.DeleteKey(context.Background(), key)
}

func (o *syncer) OnSync(ctx context.Context) {
	o.Synced(ctx, func(context.Context) { o.synced.Done() })
}

func newReflector(local kvstore.BackendOperations, cluster, prefix string, factory store.Factory, synced *lock.StoppableWaitGroup) reflector {
	synced.Add()
	prefix = kvstore.StateToCachePrefix(prefix)
	syncer := syncer{
		SyncStore: factory.NewSyncStore(cluster, local, path.Join(prefix, cluster),
			store.WSSWithSyncedKeyOverride(prefix)),
		synced: synced,
	}

	watcher := factory.NewWatchStore(cluster, store.KVPairCreator, &syncer,
		store.RWSWithOnSyncCallback(syncer.OnSync),
	)

	return reflector{
		syncer:  syncer,
		watcher: watcher,
	}
}

type synced struct {
	wait.SyncedCommon
	resources *lock.StoppableWaitGroup
	connected chan struct{}
}

func newSynced() synced {
	return synced{
		SyncedCommon: wait.NewSyncedCommon(),
		resources:    lock.NewStoppableWaitGroup(),
		connected:    make(chan struct{}),
	}
}

func (s *synced) Resources(ctx context.Context) error {
	return s.Wait(ctx, s.resources.WaitChannel())
}
