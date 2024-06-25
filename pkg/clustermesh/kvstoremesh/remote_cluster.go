// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstoremesh

import (
	"context"
	"fmt"
	"path"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sirupsen/logrus"
	"k8s.io/utils/clock"
	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/clustermesh/common"
	mcsapitypes "github.com/cilium/cilium/pkg/clustermesh/mcsapi/types"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	cmutils "github.com/cilium/cilium/pkg/clustermesh/utils"
	"github.com/cilium/cilium/pkg/clustermesh/wait"
	identityCache "github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeStore "github.com/cilium/cilium/pkg/node/store"
	serviceStore "github.com/cilium/cilium/pkg/service/store"
)

// remoteCluster represents a remote cluster other than the local one this
// service is running in
type remoteCluster struct {
	name string

	localBackend kvstore.BackendOperations

	nodes          reflector
	services       reflector
	serviceExports reflector
	identities     reflector
	ipcache        reflector

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

	// disableDrainOnDisconnection disables the removal of cached data upon
	// cluster disconnection.
	disableDrainOnDisconnection bool

	logger logrus.FieldLogger
	clock  clock.Clock
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
			SyncedCanaries:        true,
			Cached:                true,
			MaxConnectedClusters:  srccfg.Capabilities.MaxConnectedClusters,
			ServiceExportsEnabled: srccfg.Capabilities.ServiceExportsEnabled,
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

	if srccfg.Capabilities.ServiceExportsEnabled != nil {
		mgr.Register(adapter(mcsapitypes.ServiceExportStorePrefix), func(ctx context.Context) {
			rc.serviceExports.watcher.Watch(ctx, backend, path.Join(adapter(mcsapitypes.ServiceExportStorePrefix), rc.name))
		})
	} else {
		// Additionnally drain the service exports to remove stale entries if the
		// service exports was previously supported and is now not supported anymore.
		rc.serviceExports.watcher.Drain()
		// Also mimic that the service exports are synced if the remote cluster
		// doesn't support service exports (remote cluster is running Cilium
		// version 1.16 or less).
		rc.serviceExports.syncer.OnSync(ctx)
	}

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

func (rc *remoteCluster) Remove(ctx context.Context) {
	if rc.disableDrainOnDisconnection {
		rc.logger.Warning("Remote cluster disconnected, but cached data removal is disabled. " +
			"Reconnecting to the same cluster without first restarting KVStoreMesh may lead to inconsistencies")
		return
	}

	const retries = 5
	var (
		retry   = 0
		backoff = 2 * time.Second
	)

	rc.logger.Info("Remote cluster disconnected: draining cached data")
	for {
		err := rc.drain(ctx, retry == 0)
		switch {
		case err == nil:
			rc.logger.Info("Successfully removed all cached data from kvstore")
			return
		case ctx.Err() != nil:
			return
		case retry == retries:
			rc.logger.WithError(err).Error(
				"Failed to remove cached data from kvstore, despite retries. Reconnecting to the " +
					"same cluster without first restarting KVStoreMesh may lead to inconsistencies")
			return
		}

		rc.logger.WithError(err).Warning("Failed to remove cached data from kvstore, retrying")
		select {
		case <-rc.clock.After(backoff):
			retry++
			backoff *= 2
		case <-ctx.Done():
			return
		}
	}
}

// drain drains the cached data from the local kvstore. The cluster configuration
// is removed as first step, to prevent bootstrapping agents from connecting while
// removing the rest of the cached data. Indeed, there's no point in retrieving
// incomplete data, and it is expected that agents will be disconnecting as well.
func (rc *remoteCluster) drain(ctx context.Context, withGracePeriod bool) (err error) {
	keys := []string{
		path.Join(kvstore.ClusterConfigPrefix, rc.name),
	}
	prefixes := []string{
		path.Join(kvstore.SyncedPrefix, rc.name),
		path.Join(kvstore.StateToCachePrefix(nodeStore.NodeStorePrefix), rc.name),
		path.Join(kvstore.StateToCachePrefix(serviceStore.ServiceStorePrefix), rc.name),
		path.Join(kvstore.StateToCachePrefix(mcsapitypes.ServiceExportStorePrefix), rc.name),
		path.Join(kvstore.StateToCachePrefix(identityCache.IdentitiesPath), rc.name),
		path.Join(kvstore.StateToCachePrefix(ipcache.IPIdentitiesPath), rc.name),
	}

	for _, key := range keys {
		if err = rc.localBackend.Delete(ctx, key); err != nil {
			return fmt.Errorf("deleting key %q: %w", key, err)
		}
	}

	if withGracePeriod {
		// Wait for the grace period before deleting all the cached data. This
		// allows Cilium agents to disconnect in the meanwhile, to reduce the
		// overhead on etcd and prevent issues in case KVStoreMesh is disabled
		// (as the removal of the configurations would cause the draining as
		// well). The cluster configuration is deleted before waiting to prevent
		// new agents from connecting in this time window.
		const drainGracePeriod = 3 * time.Minute
		rc.logger.WithField(logfields.Duration, drainGracePeriod).
			Info("Waiting before removing cached data from kvstore, to allow Cilium agents to disconnect")
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-rc.clock.After(drainGracePeriod):
			rc.logger.Info("Finished waiting before removing cached data from kvstore")
		}
	}

	for _, prefix := range prefixes {
		if err = rc.localBackend.DeletePrefix(ctx, prefix+"/"); err != nil {
			return fmt.Errorf("deleting prefix %q: %w", prefix+"/", err)
		}
	}

	return nil
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
	status.NumServiceExports = int64(rc.serviceExports.watcher.NumEntries())
	status.NumIdentities = int64(rc.identities.watcher.NumEntries())
	status.NumEndpoints = int64(rc.ipcache.watcher.NumEntries())

	status.Synced = &models.RemoteClusterSynced{
		Nodes:      rc.nodes.watcher.Synced(),
		Services:   rc.services.watcher.Synced(),
		Identities: rc.identities.watcher.Synced(),
		Endpoints:  rc.ipcache.watcher.Synced(),
	}
	if status.Config != nil && status.Config.ServiceExportsEnabled != nil {
		status.Synced.ServiceExports = ptr.To(rc.serviceExports.watcher.Synced())
	}

	status.Ready = status.Ready &&
		status.Synced.Nodes && status.Synced.Services &&
		(status.Synced.ServiceExports == nil || *status.Synced.ServiceExports) &&
		status.Synced.Identities && status.Synced.Endpoints

	return status
}

type reflector struct {
	watcher store.WatchStore
	syncer  syncer
}

type syncer struct {
	store.SyncStore
	synced   *lock.StoppableWaitGroup
	isSynced *atomic.Bool
}

func (o *syncer) OnUpdate(key store.Key) {
	o.UpsertKey(context.Background(), key)
}

func (o *syncer) OnDelete(key store.NamedKey) {
	o.DeleteKey(context.Background(), key)
}

func (o *syncer) OnSync(ctx context.Context) {
	// As we send fake OnSync when service exports support is disabled we need
	// to make sure that this is called only once.
	if o.isSynced.CompareAndSwap(false, true) {
		o.Synced(ctx, func(context.Context) { o.synced.Done() })
	}
}

func newReflector(local kvstore.BackendOperations, cluster, prefix string, factory store.Factory, synced *lock.StoppableWaitGroup) reflector {
	synced.Add()
	prefix = kvstore.StateToCachePrefix(prefix)
	syncer := syncer{
		SyncStore: factory.NewSyncStore(cluster, local, path.Join(prefix, cluster),
			store.WSSWithSyncedKeyOverride(prefix)),
		synced:   synced,
		isSynced: &atomic.Bool{},
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
