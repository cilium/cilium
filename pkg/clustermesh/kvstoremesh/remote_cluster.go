// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstoremesh

import (
	"context"
	"fmt"
	"path"
	"sync"

	"github.com/cilium/cilium/pkg/clustermesh/types"
	cmutils "github.com/cilium/cilium/pkg/clustermesh/utils"
	identityCache "github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
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

	cancel context.CancelFunc
	wg     sync.WaitGroup

	storeFactory store.Factory
}

func (rc *remoteCluster) Run(ctx context.Context, backend kvstore.BackendOperations, srccfg *types.CiliumClusterConfig, ready chan<- error) {
	dstcfg := types.CiliumClusterConfig{
		Capabilities: types.CiliumClusterConfigCapabilities{
			SyncedCanaries: true,
			Cached:         true,
		},
	}

	if srccfg != nil {
		dstcfg.ID = srccfg.ID
	}

	if err := cmutils.SetClusterConfig(ctx, rc.name, &dstcfg, rc.localBackend); err != nil {
		ready <- fmt.Errorf("failed to propagate cluster configuration: %w", err)
		close(ready)
		return
	}

	var capabilities types.CiliumClusterConfigCapabilities
	if srccfg != nil {
		capabilities = srccfg.Capabilities
	}

	var mgr store.WatchStoreManager
	if capabilities.SyncedCanaries {
		mgr = rc.storeFactory.NewWatchStoreManager(backend, rc.name)
	} else {
		mgr = store.NewWatchStoreManagerImmediate(rc.name)
	}

	adapter := func(prefix string) string { return prefix }
	if capabilities.Cached {
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
		if capabilities.Cached {
			suffix = rc.name
		}

		rc.ipcache.watcher.Watch(ctx, backend, path.Join(adapter(ipcache.IPIdentitiesPath), suffix))
	})

	mgr.Register(adapter(identityCache.IdentitiesPath), func(ctx context.Context) {
		var suffix string
		if capabilities.Cached {
			suffix = rc.name
		}

		rc.identities.watcher.Watch(ctx, backend, path.Join(adapter(identityCache.IdentitiesPath), suffix))
	})

	close(ready)
	mgr.Run(ctx)
}

func (rc *remoteCluster) Stop() {
	rc.cancel()
	rc.wg.Wait()
}

func (rc *remoteCluster) Remove() {
	// Cluster specific keys are not explicitly removed, but they will be
	// disappear once the associated lease expires.
}

func (rc *remoteCluster) ClusterConfigRequired() bool { return false }

type reflector struct {
	watcher store.WatchStore
	syncer  syncer
}

type syncer struct {
	store.SyncStore
}

func (o *syncer) OnUpdate(key store.Key) {
	o.UpsertKey(context.Background(), key)
}

func (o *syncer) OnDelete(key store.NamedKey) {
	o.DeleteKey(context.Background(), key)
}

func (o *syncer) OnSync(ctx context.Context) {
	o.Synced(ctx)
}

func newReflector(local kvstore.BackendOperations, cluster, prefix string, factory store.Factory) reflector {
	prefix = kvstore.StateToCachePrefix(prefix)
	syncer := syncer{
		SyncStore: factory.NewSyncStore(cluster, local, path.Join(prefix, cluster),
			store.WSSWithSyncedKeyOverride(prefix)),
	}

	watcher := factory.NewWatchStore(cluster, store.KVPairCreator, &syncer,
		store.RWSWithOnSyncCallback(syncer.OnSync),
	)

	return reflector{
		syncer:  syncer,
		watcher: watcher,
	}
}
