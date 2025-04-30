// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"context"
	"log/slog"
	"sync"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/clustermesh"
	"github.com/cilium/cilium/pkg/clustermesh/wait"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/time"
)

var (
	RegeneratorCell = cell.Module(
		"endpoint-regeneration",
		"Endpoints regeneration",

		cell.Provide(newRegenerator),
	)
)

// KVStoreNodesWaitFn is the type of the function used to wait for synchronization
// of all nodes from the kvstore.
type KVStoreNodesWaitFn wait.Fn

// Regenerator wraps additional functionalities for endpoint regeneration.
type Regenerator struct {
	nodesWaitFn   KVStoreNodesWaitFn
	ipcacheWaitFn wait.Fn
	cmWaitFn      wait.Fn
	cmWaitTimeout time.Duration

	logger        *slog.Logger
	cmSyncLogOnce sync.Once
}

func newRegenerator(in struct {
	cell.In

	Logger *slog.Logger

	Config      wait.TimeoutConfig
	NodesWaitFn KVStoreNodesWaitFn
	IPCacheSync *ipcache.IPIdentityWatcher
	ClusterMesh *clustermesh.ClusterMesh
}) *Regenerator {
	waitFn := func(context.Context) error { return nil }
	if in.ClusterMesh != nil {
		waitFn = in.ClusterMesh.IPIdentitiesSynced
	}

	return &Regenerator{
		logger:        in.Logger,
		nodesWaitFn:   in.NodesWaitFn,
		ipcacheWaitFn: in.IPCacheSync.WaitForSync,
		cmWaitFn:      waitFn,
		cmWaitTimeout: in.Config.ClusterMeshSyncTimeout,
	}
}

func (r *Regenerator) WaitForKVStoreSync(ctx context.Context) error {
	if err := r.nodesWaitFn(ctx); err != nil {
		return err
	}

	return r.ipcacheWaitFn(ctx)
}

func (r *Regenerator) WaitForClusterMeshIPIdentitiesSync(ctx context.Context) error {
	wctx, cancel := context.WithTimeout(ctx, r.cmWaitTimeout)
	defer cancel()
	err := r.cmWaitFn(wctx)

	switch {
	case ctx.Err() != nil:
		// The context associated with the endpoint has been canceled.
		return ErrNotAlive
	case err != nil:
		// We don't return an error in case the wait operation timed out, as we can
		// continue with the endpoint regeneration, although at the cost of possible
		// connectivity drops for cross-cluster connections. We additionally print
		// the warning message only once, to avoid repeating it for every endpoint.
		r.cmSyncLogOnce.Do(func() {
			r.logger.Warn("Failed waiting for clustermesh IPs and identities synchronization before regenerating endpoints, expect possible disruption of cross-cluster connections")
		})
	}

	return nil
}
