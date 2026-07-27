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
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/time"
)

var (
	RegeneratorCell = cell.Module(
		"endpoint-regeneration",
		"Endpoints regeneration",

		cell.Provide(
			newRegenerator,

			// Provide [regeneration.Fence] to allow sub-systems to delay the initial
			// endpoint regeneration.
			regeneration.NewFence,
		),
	)
)

// Regenerator wraps additional functionalities for endpoint regeneration.
type Regenerator struct {
	cmWaitFn      wait.Fn
	cmWaitTimeout time.Duration
	fence         regeneration.Fence

	logger        *slog.Logger
	cmSyncLogOnce sync.Once
}

func newRegenerator(in struct {
	cell.In

	Logger *slog.Logger

	Config         wait.TimeoutConfig
	ClusterMesh    *clustermesh.ClusterMesh
	Fence          regeneration.Fence
	LBInitWaitFunc loadbalancer.InitWaitFunc
}) *Regenerator {
	waitFn := func(context.Context) error { return nil }
	if in.ClusterMesh != nil {
		waitFn = in.ClusterMesh.IPIdentitiesSynced
	}
	r := &Regenerator{
		logger:        in.Logger,
		cmWaitFn:      waitFn,
		cmWaitTimeout: in.Config.ClusterMeshSyncTimeout,
		fence:         in.Fence,
	}

	// !!! Do not add more waits here. These will eventually move out from here
	// to their proper places !!!

	// Wait for ipcache and identities synchronization from all remote clusters,
	// to prevent disrupting cross-cluster connections on endpoint regeneration.
	in.Fence.Add(
		"clustermesh",
		r.waitForClusterMeshIPIdentitiesSync,
	)

	// Wait for the initial load-balancing state to be reconciled to BPF maps.
	in.Fence.Add(
		"loadbalancer",
		in.LBInitWaitFunc,
	)
	return r
}

func (r *Regenerator) WaitForFence(ctx context.Context) error {
	return r.fence.Wait(ctx)
}

func (r *Regenerator) waitForClusterMeshIPIdentitiesSync(ctx context.Context) error {
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
