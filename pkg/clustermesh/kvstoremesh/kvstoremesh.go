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

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/clustermesh-apiserver/syncstate"
	"github.com/cilium/cilium/pkg/clustermesh/common"
	"github.com/cilium/cilium/pkg/clustermesh/kvstoremesh/reflector"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/clustermesh/wait"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/logging/logfields"
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

	reflectorFactories []reflector.Factory

	logger *slog.Logger

	started chan struct{}
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

	ReflectorFactories []reflector.Factory `group:"kvstoremesh-reflectors"`

	Metrics      common.Metrics
	StoreFactory store.Factory

	Logger *slog.Logger
}

func newKVStoreMesh(lc cell.Lifecycle, params params) *KVStoreMesh {
	km := KVStoreMesh{
		config:             params.Config,
		client:             params.Client,
		storeFactory:       params.StoreFactory,
		reflectorFactories: params.ReflectorFactories,
		logger:             params.Logger,
		started:            make(chan struct{}),
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

	// Needs to run after the "common" start hook, to signal that initialization
	// successfully completed.
	lc.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			close(km.started)
			return nil
		},
	})

	return &km
}

// SyncWaiter wraps a SyncState to wait for KVStoreMesh synchronization, while
// allowing to force marking it as ready when necessary.
type SyncWaiter func()

func NewSyncWaiter(jg job.Group, km *KVStoreMesh, ss syncstate.SyncState) SyncWaiter {
	done := ss.WaitForResource()

	jg.Add(
		job.OneShot("kvstoremesh-sync-waiter", func(ctx context.Context, health cell.Health) error {
			return km.synced(ctx, func(ctx context.Context) {
				done(ctx)
				ss.Stop()
			})
		}),
	)

	return func() { ss.Stop(); done(context.Background()) }
}

func (sw SyncWaiter) ForceReady() { sw() }

func (km *KVStoreMesh) newRemoteCluster(name string, status common.StatusFunc) common.RemoteCluster {
	ctx, cancel := context.WithCancel(context.Background())

	synced := newSynced()
	defer synced.resources.Stop()

	rc := &remoteCluster{
		name:         name,
		localBackend: km.client,
		reflectors:   make(map[reflector.Name]reflector.Reflector),

		cancel: cancel,

		status:       status,
		storeFactory: km.storeFactory,
		synced:       synced,
		readyTimeout: km.config.PerClusterReadyTimeout,
		logger:       km.logger.With(logfields.ClusterName, name),

		disableDrainOnDisconnection: km.config.DisableDrainOnDisconnection,
	}

	for _, factory := range km.reflectorFactories {
		reflector := factory(km.client, km.storeFactory, name, synced.resources.Add())
		rc.reflectors[reflector.Name()] = reflector
		rc.wg.Go(func() { reflector.Run(ctx) })
	}

	rc.wg.Go(func() { rc.waitForConnection(ctx) })

	return rc
}

// synced returns once all remote clusters have been synchronized or the global
// timeout has been reached. The given syncCallback is always executed before
// the function returns.
func (km *KVStoreMesh) synced(ctx context.Context, syncCallback func(context.Context)) error {
	select {
	case <-km.started:
	case <-ctx.Done():
		return ctx.Err()
	}

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
