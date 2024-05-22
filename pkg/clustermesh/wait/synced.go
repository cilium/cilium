// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package wait

import (
	"time"

	"github.com/spf13/pflag"
)

type TimeoutConfig struct {
	// ClusterMeshSyncTimeout is the timeout when waiting for the initial
	// synchronization from all remote clusters, before triggering the
	// circuit breaker and possibly disrupting cross-cluster connections.
	ClusterMeshSyncTimeout time.Duration

	// ClusterMeshIPIdentitiesSyncTimeout is the timeout when waiting for the
	// initial synchronization of ipcache entries and identities from all remote
	// clusters before regenerating the local endpoints.
	// Deprecated in favor of ClusterMeshSyncTimeout.
	ClusterMeshIPIdentitiesSyncTimeout time.Duration
}

func (def TimeoutConfig) Flags(flags *pflag.FlagSet) {
	flags.Duration("clustermesh-sync-timeout", def.ClusterMeshSyncTimeout,
		"Timeout waiting for the initial synchronization of information from remote clusters")

	flags.Duration("clustermesh-ip-identities-sync-timeout", def.ClusterMeshIPIdentitiesSyncTimeout,
		"Timeout waiting for the initial synchronization of IPs and identities from remote clusters before local endpoints regeneration")
	flags.MarkDeprecated("clustermesh-ip-identities-sync-timeout", "Use --clustermesh-sync-timeout instead")
}

func (tc TimeoutConfig) Timeout() time.Duration {
	if tc.ClusterMeshSyncTimeout != TimeoutConfigDefault.ClusterMeshSyncTimeout {
		return tc.ClusterMeshSyncTimeout
	}

	return tc.ClusterMeshIPIdentitiesSyncTimeout
}

var (
	// TimeoutConfigDefault is the default timeout configuration.
	TimeoutConfigDefault = TimeoutConfig{
		ClusterMeshSyncTimeout:             1 * time.Minute,
		ClusterMeshIPIdentitiesSyncTimeout: 1 * time.Minute,
	}
)
