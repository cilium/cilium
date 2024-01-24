// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstoremesh

import (
	"context"

	"github.com/cilium/cilium/pkg/clustermesh/internal"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/hive/cell"
	identityCache "github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/kvstore"
	nodeStore "github.com/cilium/cilium/pkg/node/store"
	"github.com/cilium/cilium/pkg/promise"
	serviceStore "github.com/cilium/cilium/pkg/service/store"
)

// KVStoreMesh is a cache of multiple remote clusters
type KVStoreMesh struct {
	internal internal.ClusterMesh

	// backend is the interface to operate the local kvstore
	backend        kvstore.BackendOperations
	backendPromise promise.Promise[kvstore.BackendOperations]
}

type params struct {
	cell.In

	types.ClusterIDName
	internal.Config

	BackendPromise promise.Promise[kvstore.BackendOperations]

	Metrics internal.Metrics
}

func newKVStoreMesh(lc cell.Lifecycle, params params) *KVStoreMesh {
	km := KVStoreMesh{backendPromise: params.BackendPromise}
	km.internal = internal.NewClusterMesh(internal.Configuration{
		Config:           params.Config,
		ClusterIDName:    params.ClusterIDName,
		NewRemoteCluster: km.newRemoteCluster,
		Metrics:          params.Metrics,
	})

	lc.Append(&km)

	// The "internal" Start hook needs to be executed after that the kvstoremesh one
	// terminated, to ensure that the backend promise has already been resolved.
	lc.Append(&km.internal)

	return &km
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

func (km *KVStoreMesh) newRemoteCluster(name string, _ internal.StatusFunc) internal.RemoteCluster {
	ctx, cancel := context.WithCancel(context.Background())

	rc := &remoteCluster{
		name:         name,
		localBackend: km.backend,

		cancel: cancel,

		nodes:      newReflector(km.backend, name, nodeStore.NodeStorePrefix),
		services:   newReflector(km.backend, name, serviceStore.ServiceStorePrefix),
		identities: newReflector(km.backend, name, identityCache.IdentitiesPath),
		ipcache:    newReflector(km.backend, name, ipcache.IPIdentitiesPath),
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

	return rc
}
