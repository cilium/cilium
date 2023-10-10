// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"context"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/clustermesh"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

var (
	RegeneratorCell = cell.Module(
		"endpoint-regeneration",
		"Endpoints regeneration",

		cell.Config(RegeneratorConfigDefault),
		cell.Provide(newRegenerator),
	)
)

// Regenerator wraps additional functionalities for endpoint regeneration.
type Regenerator struct {
	RegeneratorConfig

	cmWaitFn clustermesh.SyncedWaitFn

	logger        logrus.FieldLogger
	cmSyncLogOnce sync.Once
}

type RegeneratorConfig struct {
	// ClusterMeshIPIdentitiesSyncTimeout is the timeout when waiting for the
	// initial synchronization of ipcache entries and identities from all remote
	// clusters before regenerating the local endpoints.
	ClusterMeshIPIdentitiesSyncTimeout time.Duration
}

func (def RegeneratorConfig) Flags(flags *pflag.FlagSet) {
	flags.Duration("clustermesh-ip-identities-sync-timeout", def.ClusterMeshIPIdentitiesSyncTimeout,
		"Timeout waiting for the initial synchronization of IPs and identities from remote clusters before local endpoints regeneration")
}

var RegeneratorConfigDefault = RegeneratorConfig{
	ClusterMeshIPIdentitiesSyncTimeout: 1 * time.Minute,
}

func newRegenerator(in struct {
	cell.In

	Logger logrus.FieldLogger

	Config      RegeneratorConfig
	ClusterMesh *clustermesh.ClusterMesh
}) *Regenerator {
	waitFn := func(context.Context) error { return nil }
	if in.ClusterMesh != nil {
		waitFn = in.ClusterMesh.IPIdentitiesSynced
	}

	return &Regenerator{
		RegeneratorConfig: in.Config,
		logger:            in.Logger,
		cmWaitFn:          waitFn,
	}
}

// CapTimeoutForSynchronousRegeneration caps the timeout to a value suitable in
// case the regeneration of an endpoint needs to be performed synchronously
// (currently required when IPSec is enabled). In particular, this is necessary
// to not block the agent bootstrap, as that prevents the scheduling of new
// workloads. This logic is implemented as a separate function to avoid
// forgetting to remove it when the synchronous regeneration is removed.
func (r *Regenerator) CapTimeoutForSynchronousRegeneration() {
	const maxTimeout = 5 * time.Second
	if r.ClusterMeshIPIdentitiesSyncTimeout > maxTimeout {
		r.ClusterMeshIPIdentitiesSyncTimeout = maxTimeout
		r.logger.WithField(logfields.Value, maxTimeout).
			Info("Capped clustermesh-ip-identities-sync-timeout because endpoint regeneration needs to be performed synchronously")
	}
}

func (r *Regenerator) WaitForClusterMeshIPIdentitiesSync(ctx context.Context) error {
	wctx, cancel := context.WithTimeout(ctx, r.ClusterMeshIPIdentitiesSyncTimeout)
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
			r.logger.Warning("Failed waiting for clustermesh IPs and identities synchronization before regenerating endpoints, expect possible disruption of cross-cluster connections")
		})
	}

	return nil
}
