// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstoremesh

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"maps"
	"path"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"k8s.io/utils/ptr"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/clustermesh/clustercfg"
	"github.com/cilium/cilium/pkg/clustermesh/common"
	"github.com/cilium/cilium/pkg/clustermesh/kvstoremesh/reflector"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/clustermesh/wait"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// remoteCluster represents a remote cluster other than the local one this
// service is running in
type remoteCluster struct {
	name string

	localBackend kvstore.BackendOperations

	// reflectors are the reflectors that handle the synchronization.
	reflectors map[reflector.Name]reflector.Reflector

	// status is the function which fills the common part of the status.
	status common.StatusFunc

	// registered represents whether the watchers have been registered.
	registered atomic.Bool

	cancel context.CancelFunc
	wg     sync.WaitGroup

	storeFactory store.Factory

	// synced tracks the initial synchronization of the remote cluster.
	synced synced
	// readyTimeout is the duration to wait for a connection to be established
	// before removing the cluster from readiness checks.
	readyTimeout time.Duration

	// disableDrainOnDisconnection disables the removal of cached data upon
	// cluster disconnection.
	disableDrainOnDisconnection bool

	logger *slog.Logger
}

func (rc *remoteCluster) Run(ctx context.Context, backend kvstore.BackendOperations, srccfg types.CiliumClusterConfig, ready chan<- error) {
	// Closing the synced.connected channel cancels the timeout goroutine.
	// Ensure we do not attempt to close the channel more than once.
	select {
	case <-rc.synced.connected:
	default:
		close(rc.synced.connected)
	}

	var dstcfg = srccfg
	dstcfg.Capabilities.SyncedCanaries = true
	dstcfg.Capabilities.Cached = true

	stopAndWait, err := clustercfg.Enforce(ctx, rc.name, dstcfg, rc.localBackend, rc.logger)
	defer stopAndWait()
	if err != nil {
		ready <- fmt.Errorf("failed to propagate cluster configuration: %w", err)
		close(ready)
		return
	}

	var mgr store.WatchStoreManager
	if srccfg.Capabilities.SyncedCanaries {
		mgr = rc.storeFactory.NewWatchStoreManager(backend, rc.name)
	} else {
		mgr = store.NewWatchStoreManagerImmediate(rc.logger)
	}

	for _, rfl := range rc.reflectors {
		rfl.Register(mgr, backend, srccfg)
	}

	rc.registered.Store(true)
	defer rc.registered.Store(false)

	close(ready)
	mgr.Run(ctx)
}

func (rc *remoteCluster) Stop() {
	rc.cancel()
	rc.synced.Stop()
	rc.wg.Wait()
}

// RevokeCache performs a partial revocation of the remote cluster's cache, draining only remote
// services and serviceExports. This prevents the kvstoremesh from keeping services in the kvstore
// for clusters with potentially stale service backends. Other resources are left intact to reduce
// churn and avoid disrupting existing connections like active IPsec security associations.
func (rc *remoteCluster) RevokeCache(ctx context.Context) {
	for _, rfl := range rc.reflectors {
		rfl.RevokeCache(ctx)
	}
}

func (rc *remoteCluster) Remove(ctx context.Context) {
	if rc.disableDrainOnDisconnection {
		rc.logger.Warn("Remote cluster disconnected, but cached data removal is disabled. " +
			"Reconnecting to the same cluster without first restarting KVStoreMesh may lead to inconsistencies")
		return
	}

	const retries = 5
	var (
		retry   = 0
		backoff = 2 * time.Second
	)

	rc.logger.Info("Remote cluster disconnected: draining cached data")
	for {
		err := rc.drain(ctx, retry == 0)
		switch {
		case err == nil:
			rc.logger.Info("Successfully removed all cached data from kvstore")
			return
		case ctx.Err() != nil:
			return
		case retry == retries:
			rc.logger.Error(
				"Failed to remove cached data from kvstore, despite retries. Reconnecting to the "+
					"same cluster without first restarting KVStoreMesh may lead to inconsistencies",
				logfields.Error, err,
			)
			return
		}

		rc.logger.Warn("Failed to remove cached data from kvstore, retrying", logfields.Error, err)
		select {
		case <-time.After(backoff):
			retry++
			backoff *= 2
		case <-ctx.Done():
			return
		}
	}
}

// drain drains the cached data from the local kvstore. The cluster configuration
// is removed as first step, to prevent bootstrapping agents from connecting while
// removing the rest of the cached data. Indeed, there's no point in retrieving
// incomplete data, and it is expected that agents will be disconnecting as well.
func (rc *remoteCluster) drain(ctx context.Context, withGracePeriod bool) (err error) {
	var cfgkey = path.Join(kvstore.ClusterConfigPrefix, rc.name)
	if err = rc.localBackend.Delete(ctx, cfgkey); err != nil {
		return fmt.Errorf("deleting key %q: %w", cfgkey, err)
	}

	if withGracePeriod {
		// Wait for the grace period before deleting all the cached data. This
		// allows Cilium agents to disconnect in the meanwhile, to reduce the
		// overhead on etcd and prevent issues in case KVStoreMesh is disabled
		// (as the removal of the configurations would cause the draining as
		// well). The cluster configuration is deleted before waiting to prevent
		// new agents from connecting in this time window.
		const drainGracePeriod = 3 * time.Minute
		rc.logger.Info(
			"Waiting before removing cached data from kvstore, to allow Cilium agents to disconnect",
			logfields.Duration, drainGracePeriod,
		)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(drainGracePeriod):
			rc.logger.Info("Finished waiting before removing cached data from kvstore")
		}
	}

	var synpfx = path.Join(kvstore.SyncedPrefix, rc.name) + "/"
	if err = rc.localBackend.DeletePrefix(ctx, synpfx); err != nil {
		return fmt.Errorf("deleting prefix %q: %w", synpfx, err)
	}

	// Sort the reflectors to ensure consistent ordering, relied upon by tests.
	sorted := slices.SortedFunc(
		maps.Values(rc.reflectors),
		func(a, b reflector.Reflector) int { return cmp.Compare(a.Name(), b.Name()) },
	)

	for _, rfl := range sorted {
		if err = rfl.DeleteCache(ctx); err != nil {
			return fmt.Errorf("draining reflector: %w", err)
		}
	}

	return nil
}

// waitForConnection waits for a connection to be established to the remote cluster.
// If the connection is not established within the timeout, the remote cluster is
// removed from readiness checks.
func (rc *remoteCluster) waitForConnection(ctx context.Context) {
	select {
	case <-ctx.Done():
	case <-rc.synced.connected:
	case <-time.After(rc.readyTimeout):
		rc.logger.Info("Remote cluster did not connect within timeout, removing from readiness checks")
		rc.synced.resources.ForceAllDone()
	}
}

func (rc *remoteCluster) Status() *models.RemoteCluster {
	status := rc.status()

	get := func(name reflector.Name) reflector.Status {
		rfl, ok := rc.reflectors[name]
		if ok {
			return rfl.Status()
		}
		return reflector.Status{}
	}

	status.NumNodes = int64(get(reflector.Nodes).Entries)
	status.NumSharedServices = int64(get(reflector.Services).Entries)
	status.NumServiceExports = int64(get(reflector.ServiceExports).Entries)
	status.NumIdentities = int64(get(reflector.Identities).Entries)
	status.NumEndpoints = int64(get(reflector.Endpoints).Entries)

	status.Synced = &models.RemoteClusterSynced{
		Nodes:      get(reflector.Nodes).Synced,
		Services:   get(reflector.Services).Synced,
		Identities: get(reflector.Identities).Synced,
		Endpoints:  get(reflector.Endpoints).Synced,
	}

	if get(reflector.ServiceExports).Enabled {
		status.Synced.ServiceExports = ptr.To(get(reflector.ServiceExports).Synced)
	}

	// We mark the status as ready only after being sure that all reflectors
	// have been registered, and at that point we know that [status.Enabled]
	// is set if the reflector is enabled for the current configuration.
	status.Ready = status.Ready && rc.registered.Load()
	for _, rfl := range rc.reflectors {
		var st = rfl.Status()
		status.Ready = status.Ready && (!st.Enabled || st.Synced)
	}

	return status
}

// resources is a wrapper around StoppableWaitGroup that collects the
// [lock.DoneFunc]s to allow overriding the waiting.
type resources struct {
	*lock.StoppableWaitGroup
	mu        lock.Mutex
	doneFuncs []lock.DoneFunc
}

func (r *resources) Add() lock.DoneFunc {
	r.mu.Lock()
	defer r.mu.Unlock()
	done := r.StoppableWaitGroup.Add()
	r.doneFuncs = append(r.doneFuncs, done)
	return done
}

func (r *resources) ForceAllDone() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, done := range r.doneFuncs {
		done()
	}
	r.doneFuncs = nil
}

type synced struct {
	wait.SyncedCommon
	resources *resources
	connected chan struct{}
}

func newSynced() synced {
	return synced{
		SyncedCommon: wait.NewSyncedCommon(),
		resources:    &resources{StoppableWaitGroup: lock.NewStoppableWaitGroup()},
		connected:    make(chan struct{}),
	}
}

func (s *synced) Resources(ctx context.Context) error {
	return s.Wait(ctx, s.resources.WaitChannel())
}
