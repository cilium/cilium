// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstoremesh

import (
	"cmp"
	"context"
	"log/slog"
	"slices"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/spf13/pflag"
	"k8s.io/utils/clock"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/clustermesh-apiserver/syncstate"
	"github.com/cilium/cilium/pkg/clustermesh/common"
	mcsapitypes "github.com/cilium/cilium/pkg/clustermesh/mcsapi/types"
	serviceStore "github.com/cilium/cilium/pkg/clustermesh/store"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/clustermesh/wait"
	identityCache "github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeStore "github.com/cilium/cilium/pkg/node/store"
)

type Config struct {
	PerClusterReadyTimeout time.Duration
	GlobalReadyTimeout     time.Duration
	EnableHeartBeat        bool

	DisableDrainOnDisconnection bool
}

var DefaultConfig = Config{
	PerClusterReadyTimeout:      15 * time.Second,
	GlobalReadyTimeout:          10 * time.Minute,
	EnableHeartBeat:             false,
	DisableDrainOnDisconnection: false,
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Duration("per-cluster-ready-timeout", def.PerClusterReadyTimeout, "Remote clusters will be disregarded for readiness checks if a connection cannot be established within this duration")
	flags.Duration("global-ready-timeout", def.GlobalReadyTimeout, "KVStoreMesh will be considered ready even if any remote clusters have failed to synchronize within this duration")
	flags.Bool("enable-heartbeat", def.EnableHeartBeat, "KVStoreMesh will maintain heartbeat in destination etcd cluster")

	flags.Bool("disable-drain-on-disconnection", def.DisableDrainOnDisconnection, "Do not drain cached data upon cluster disconnection")
	flags.MarkHidden("disable-drain-on-disconnection")
}

// KVStoreMesh is a cache of multiple remote clusters
type KVStoreMesh struct {
	common common.ClusterMesh
	config Config

	// client is the interface to operate the local kvstore
	client kvstore.Client

	storeFactory store.Factory

	logger *slog.Logger

	// clock allows to override the clock for testing purposes
	clock clock.Clock
}

type params struct {
	cell.In

	Config

	ClusterInfo  types.ClusterInfo
	CommonConfig common.Config

	// Client is the client targeting the local cluster
	Client kvstore.Client

	// RemoteClientFactory is the factory to create clients targeting remote clusters
	RemoteClientFactory common.RemoteClientFactoryFn

	Metrics      common.Metrics
	StoreFactory store.Factory

	Logger *slog.Logger
}

func newKVStoreMesh(lc cell.Lifecycle, params params) *KVStoreMesh {
	km := KVStoreMesh{
		config:       params.Config,
		client:       params.Client,
		storeFactory: params.StoreFactory,
		logger:       params.Logger,
		clock:        clock.RealClock{},
	}
	km.common = common.NewClusterMesh(common.Configuration{
		Logger:              params.Logger,
		Config:              params.CommonConfig,
		ClusterInfo:         params.ClusterInfo,
		RemoteClientFactory: params.RemoteClientFactory,
		NewRemoteCluster:    km.newRemoteCluster,
		Metrics:             params.Metrics,
	})

	lc.Append(km.common)

	return &km
}

type SyncWaiterParams struct {
	cell.In

	KVStoreMesh *KVStoreMesh
	SyncState   syncstate.SyncState
	Lifecycle   cell.Lifecycle
	JobGroup    job.Group
	Health      cell.Health
}

func RegisterSyncWaiter(p SyncWaiterParams) {
	syncedCallback := p.SyncState.WaitForResource()

	p.JobGroup.Add(
		job.OneShot("kvstoremesh-sync-waiter", func(ctx context.Context, health cell.Health) error {
			return p.KVStoreMesh.synced(ctx, syncedCallback)
		}),
	)
}

func (km *KVStoreMesh) newRemoteCluster(name string, status common.StatusFunc) common.RemoteCluster {
	ctx, cancel := context.WithCancel(context.Background())

	synced := newSynced()
	defer synced.resources.Stop()

	identityCacheSuffix := "id"

	rc := &remoteCluster{
		name:         name,
		localBackend: km.client,

		cancel: cancel,

		nodes:          newReflector(km.client, name, nodeStore.NodeStorePrefix, "", km.storeFactory, synced.resources),
		services:       newReflector(km.client, name, serviceStore.ServiceStorePrefix, "", km.storeFactory, synced.resources),
		serviceExports: newReflector(km.client, name, mcsapitypes.ServiceExportStorePrefix, "", km.storeFactory, synced.resources),
		identities:     newReflector(km.client, name, identityCache.IdentitiesPath, identityCacheSuffix, km.storeFactory, synced.resources),
		ipcache:        newReflector(km.client, name, ipcache.IPIdentitiesPath, "", km.storeFactory, synced.resources),
		status:         status,
		storeFactory:   km.storeFactory,
		synced:         synced,
		readyTimeout:   km.config.PerClusterReadyTimeout,
		logger:         km.logger.With(logfields.ClusterName, name),
		clock:          km.clock,

		disableDrainOnDisconnection: km.config.DisableDrainOnDisconnection,
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
	run(rc.serviceExports.syncer.Run)
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
		km.logger.Info("Failed to wait for synchronization. KVStoreMesh will now handle requests, but some clusters may not have been synchronized.", logfields.Error, err)
		return err
	}

	return nil
}

// Status returns the status of the ClusterMesh subsystem
func (km *KVStoreMesh) status() []*models.RemoteCluster {
	var clusters []*models.RemoteCluster

	km.common.ForEachRemoteCluster(func(rci common.RemoteCluster) error {
		rc := rci.(*remoteCluster)
		clusters = append(clusters, rc.Status())
		return nil
	})

	// Sort the remote clusters information to ensure consistent ordering.
	slices.SortFunc(clusters,
		func(a, b *models.RemoteCluster) int { return cmp.Compare(a.Name, b.Name) })

	return clusters
}
