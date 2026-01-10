// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package operator

import (
	"context"
	"errors"
	"log/slog"
	"path"
	"sync/atomic"

	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/clustermesh/common"
	mcsapitypes "github.com/cilium/cilium/pkg/clustermesh/mcsapi/types"
	"github.com/cilium/cilium/pkg/clustermesh/observer"
	serviceStore "github.com/cilium/cilium/pkg/clustermesh/store"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/clustermesh/wait"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
)

var (
	// ErrObserverNotRegistered is the error returned when referencing an observer
	// which has not been registered.
	ErrObserverNotRegistered = errors.New("observer not registered")
)

// remoteCluster implements the clustermesh business logic on top of
// common.RemoteCluster.
type remoteCluster struct {
	logger *slog.Logger
	// name is the name of the cluster
	name string

	clusterMeshEnableEndpointSync bool
	clusterMeshEnableMCSAPI       bool

	// remoteServices is the shared store representing services in remote clusters
	remoteServices store.WatchStore
	// remoteServiceExports is the shared store representing service exports in remote clusters
	remoteServiceExports store.WatchStore

	// observers are observers watching additional prefixes.
	observers map[observer.Name]observer.Observer

	storeFactory store.Factory

	clusterAddHooks    []func(string)
	clusterDeleteHooks []func(string)

	// status is the function which fills the common part of the status.
	status common.StatusFunc

	// registered represents whether the observers have been registered.
	registered atomic.Bool

	// synced tracks the initial synchronization with the remote cluster.
	synced synced
}

func (rc *remoteCluster) Run(ctx context.Context, backend kvstore.BackendOperations, config types.CiliumClusterConfig, ready chan<- error) {
	var mgr store.WatchStoreManager
	if config.Capabilities.SyncedCanaries {
		mgr = rc.storeFactory.NewWatchStoreManager(backend, rc.name)
	} else {
		mgr = store.NewWatchStoreManagerImmediate(rc.logger)
	}

	adapter := func(prefix string) string { return prefix }
	if config.Capabilities.Cached {
		adapter = kvstore.StateToCachePrefix
	}

	if rc.clusterMeshEnableEndpointSync {
		mgr.Register(adapter(serviceStore.ServiceStorePrefix), func(ctx context.Context) {
			rc.remoteServices.Watch(ctx, backend, path.Join(adapter(serviceStore.ServiceStorePrefix), rc.name))
		})
	}

	if rc.clusterMeshEnableMCSAPI && config.Capabilities.ServiceExportsEnabled != nil {
		mgr.Register(adapter(mcsapitypes.ServiceExportStorePrefix), func(ctx context.Context) {
			rc.remoteServiceExports.Watch(ctx, backend, path.Join(adapter(mcsapitypes.ServiceExportStorePrefix), rc.name))
		})
	} else {
		// Drain the remote service exports in case the remote cluster no longer supports them
		rc.remoteServiceExports.Drain()
		// Mimic that service exports are synced if not enabled
		rc.synced.serviceExports.Stop()
	}

	for _, obs := range rc.observers {
		obs.Register(mgr, backend, config)
	}

	rc.registered.Store(true)
	defer rc.registered.Store(false)

	close(ready)
	for _, clusterAddHook := range rc.clusterAddHooks {
		clusterAddHook(rc.name)
	}
	mgr.Run(ctx)
}

func (rc *remoteCluster) Stop() {
	rc.synced.Stop()
}

// RevokeCache performs a partial revocation of the remote cluster's cache, draining only remote
// services and serviceExports (and possible extra observers that may implement revocation). This
// prevents the operator from maintaining state for potentially stale information.
func (rc *remoteCluster) RevokeCache(ctx context.Context) {
	rc.remoteServices.Drain()
	rc.remoteServiceExports.Drain()

	for _, obs := range rc.observers {
		obs.Revoke()
	}
}

func (rc *remoteCluster) Remove(context.Context) {
	for _, clusterDeleteHook := range rc.clusterDeleteHooks {
		clusterDeleteHook(rc.name)
	}
	// Draining shall occur only when the configuration for the remote cluster
	// is removed, and not in case the operator is shutting down, otherwise we
	// would break existing connections on restart.
	rc.remoteServices.Drain()
	rc.remoteServiceExports.Drain()

	for _, obs := range rc.observers {
		obs.Drain()
	}
}

type synced struct {
	wait.SyncedCommon
	services       *lock.StoppableWaitGroup
	serviceExports *lock.StoppableWaitGroup
	observers      map[observer.Name]chan struct{}
}

func newSynced() synced {
	return synced{
		SyncedCommon:   wait.NewSyncedCommon(),
		services:       lock.NewStoppableWaitGroup(),
		serviceExports: lock.NewStoppableWaitGroup(),
		observers:      make(map[observer.Name]chan struct{}),
	}
}

// Services returns after that the initial list of shared services has been
// received from the remote cluster, the remote cluster is disconnected,
// or the given context is canceled.
func (s *synced) Services(ctx context.Context) error {
	return s.Wait(ctx, s.services.WaitChannel())
}

// ServiceExports returns after that the initial list of service exports has been
// received from the remote cluster, the remote cluster is disconnected,
// or the given context is canceled.
func (s *synced) ServiceExports(ctx context.Context) error {
	return s.Wait(ctx, s.serviceExports.WaitChannel())
}

// ObserverSynced returns after that either the given named observer has
// received the initial list of entries from the remote clusters, the
// remote cluster is disconnected, or the given context is canceled.
// It returns an error if the target observer is not registered.
func (s *synced) Observer(ctx context.Context, name observer.Name) error {
	wait, ok := s.observers[name]
	if !ok {
		return ErrObserverNotRegistered
	}

	return s.Wait(ctx, wait)
}

func (rc *remoteCluster) Status() *models.RemoteCluster {
	status := rc.status()

	status.NumSharedServices = int64(rc.remoteServices.NumEntries())
	status.NumServiceExports = int64(rc.remoteServiceExports.NumEntries())

	status.Synced = &models.RemoteClusterSynced{
		Services: !rc.clusterMeshEnableEndpointSync || rc.remoteServices.Synced(),
		// The operator does not watch nodes, endpoints and identities, hence
		// let's pretend them to be synchronized by default.
		Nodes:      true,
		Endpoints:  true,
		Identities: true,
	}
	if status.Config != nil && status.Config.ServiceExportsEnabled != nil &&
		rc.clusterMeshEnableMCSAPI {
		status.Synced.ServiceExports = ptr.To(rc.remoteServiceExports.Synced())
	}

	status.Ready = status.Ready &&
		status.Synced.Nodes && status.Synced.Services &&
		(status.Synced.ServiceExports == nil || *status.Synced.ServiceExports) &&
		status.Synced.Identities && status.Synced.Endpoints

	// We mark the status as ready only after being sure that all observers
	// have been registered, as at that point we expect that [status.Enabled]
	// is set if the reflector is enabled for the current configuration.
	status.Ready = status.Ready && rc.registered.Load()
	for _, obs := range rc.observers {
		var st = obs.Status()
		status.Ready = status.Ready && (!st.Enabled || st.Synced)
	}

	return status
}
