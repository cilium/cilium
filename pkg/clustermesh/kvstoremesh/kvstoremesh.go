// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstoremesh

import (
	"context"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/clustermesh-apiserver/syncstate"
	"github.com/cilium/cilium/pkg/clustermesh/common"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/clustermesh/wait"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/hive/job"
	identityCache "github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeStore "github.com/cilium/cilium/pkg/node/store"
	"github.com/cilium/cilium/pkg/promise"
	serviceStore "github.com/cilium/cilium/pkg/service/store"
)

type Config struct {
	PerClusterReadyTimeout time.Duration
	GlobalReadyTimeout     time.Duration
}

var DefaultConfig = Config{
	PerClusterReadyTimeout: 15 * time.Second,
	GlobalReadyTimeout:     10 * time.Minute,
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Duration("per-cluster-ready-timeout", def.PerClusterReadyTimeout, "Remote clusters will be disregarded for readiness checks if a connection cannot be established within this duration")
	flags.Duration("global-ready-timeout", def.GlobalReadyTimeout, "KVStoreMesh will be considered ready even if any remote clusters have failed to synchronize within this duration")
}

// KVStoreMesh is a cache of multiple remote clusters
type KVStoreMesh struct {
	common common.ClusterMesh
	config Config

	// backend is the interface to operate the local kvstore
	backend        kvstore.BackendOperations
	backendPromise promise.Promise[kvstore.BackendOperations]

	storeFactory store.Factory

	logger logrus.FieldLogger
}

type params struct {
	cell.In

	Config

	ClusterInfo  types.ClusterInfo
	CommonConfig common.Config

	BackendPromise promise.Promise[kvstore.BackendOperations]

	Metrics      common.Metrics
	StoreFactory store.Factory

	Logger logrus.FieldLogger
}

func newKVStoreMesh(lc cell.Lifecycle, params params) *KVStoreMesh {
	km := KVStoreMesh{
		config:         params.Config,
		backendPromise: params.BackendPromise,
		storeFactory:   params.StoreFactory,
		logger:         params.Logger,
	}
	km.common = common.NewClusterMesh(common.Configuration{
		Config:           params.CommonConfig,
		ClusterInfo:      params.ClusterInfo,
		NewRemoteCluster: km.newRemoteCluster,
		Metrics:          params.Metrics,
	})

	lc.Append(&km)

	// The "common" Start hook needs to be executed after that the kvstoremesh one
	// terminated, to ensure that the backend promise has already been resolved.
	lc.Append(km.common)

	return &km
}

type SyncWaiterParams struct {
	cell.In

	KVStoreMesh *KVStoreMesh
	SyncState   syncstate.SyncState
	Lifecycle   cell.Lifecycle
	JobRegistry job.Registry
	Scope       cell.Scope
}

func RegisterSyncWaiter(p SyncWaiterParams) {
	syncedCallback := p.SyncState.WaitForResource()
	p.SyncState.Stop()

	jobGroup := p.JobRegistry.NewGroup(p.Scope)
	jobGroup.Add(
		job.OneShot("kvstoremesh-sync-waiter", func(ctx context.Context, health cell.HealthReporter) error {
			return p.KVStoreMesh.synced(ctx, syncedCallback)
		}),
	)

	p.Lifecycle.Append(jobGroup)
}

func (km *KVStoreMesh) Start(ctx cell.HookContext) error {
	backend, err := km.backendPromise.Await(ctx)
	if err != nil {
		return err
	}

	km.backend = backend
	return nil
}

func (km *KVStoreMesh) Stop(cell.HookContext) error {
	return nil
}

func (km *KVStoreMesh) newRemoteCluster(name string, _ common.StatusFunc) common.RemoteCluster {
	ctx, cancel := context.WithCancel(context.Background())

	synced := newSynced()
	defer synced.resources.Stop()

	rc := &remoteCluster{
		name:         name,
		localBackend: km.backend,

		cancel: cancel,

		nodes:        newReflector(km.backend, name, nodeStore.NodeStorePrefix, km.storeFactory, synced.resources),
		services:     newReflector(km.backend, name, serviceStore.ServiceStorePrefix, km.storeFactory, synced.resources),
		identities:   newReflector(km.backend, name, identityCache.IdentitiesPath, km.storeFactory, synced.resources),
		ipcache:      newReflector(km.backend, name, ipcache.IPIdentitiesPath, km.storeFactory, synced.resources),
		storeFactory: km.storeFactory,
		synced:       synced,
		readyTimeout: km.config.PerClusterReadyTimeout,
		logger:       km.logger.WithField(logfields.ClusterName, name),
	}

	run := func(fn func(context.Context)) {
		rc.wg.Add(1)
		go func() {
			fn(ctx)
			rc.wg.Done()
		}()
	}

	run(rc.nodes.syncer.Run)
	run(rc.services.syncer.Run)
	run(rc.identities.syncer.Run)
	run(rc.ipcache.syncer.Run)

	run(rc.waitForConnection)

	return rc
}

// synced returns once all remote clusters have been synchronized or the global
// timeout has been reached. The given syncCallback is always executed before
// the function returns.
func (km *KVStoreMesh) synced(ctx context.Context, syncCallback func(context.Context)) error {
	ctx, cancel := context.WithTimeout(ctx, km.config.GlobalReadyTimeout)
	defer func() {
		syncCallback(ctx)
		cancel()
	}()

	waiters := make([]wait.Fn, 0)
	km.common.ForEachRemoteCluster(func(rci common.RemoteCluster) error {
		rc := rci.(*remoteCluster)
		waiters = append(waiters, rc.synced.Resources)
		return nil
	})

	if err := wait.ForAll(ctx, waiters); err != nil {
		km.logger.WithError(err).Info("Failed to wait for synchronization. KVStoreMesh will now handle requests, but some clusters may not have been synchronized.")
		return err
	}

	return nil
}
