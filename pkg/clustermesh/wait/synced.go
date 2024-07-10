// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package wait

import (
	"context"
	"errors"
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

	// ErrRemoteClusterDisconnected is the error returned by wait for sync
	// operations if the remote cluster is disconnected while still waiting.
	ErrRemoteClusterDisconnected = errors.New("remote cluster disconnected")
)

// SyncedCommon contains common fields and methods used for tracking the
// synchronization status of a remote cluster.
type SyncedCommon struct {
	stopped chan struct{}
}

// NewSyncedCommon returns a new SyncedCommon instance.
func NewSyncedCommon() SyncedCommon {
	return SyncedCommon{
		stopped: make(chan struct{}),
	}
}

// Wait returns after all of the given channels have been closed, the remote
// cluster has been disconnected, or the given context has been cancelled.
func (sc *SyncedCommon) Wait(ctx context.Context, chs ...<-chan struct{}) error {
	for _, ch := range chs {
		select {
		case <-ch:
			continue
		case <-sc.stopped:
			return ErrRemoteClusterDisconnected
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

func (sc *SyncedCommon) Stop() {
	close(sc.stopped)
}

// Fn is the type of a function to wait for the initial synchronization
// of a given resource type from all remote clusters.
type Fn func(ctx context.Context) error

// ForAll returns after the all of the provided waiters have been executed.
func ForAll(ctx context.Context, waiters []Fn) error {
	for _, wait := range waiters {
		err := wait(ctx)

		// Ignore the error in case the given cluster was disconnected in
		// the meanwhile, as we do not longer care about it.
		if err != nil && !errors.Is(err, ErrRemoteClusterDisconnected) {
			return err
		}
	}
	return nil
}
