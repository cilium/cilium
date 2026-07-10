// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package common

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/clustermesh/clustercfg"
	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/metrics"
)

type fakeBackend struct {
	kvstore.BackendOperations
	statusErrors chan error
}

func (fb *fakeBackend) StatusCheckErrors() <-chan error {
	return fb.statusErrors
}

func fakeRemoteClusterFactory(client kvstore.BackendOperations, errs ...error) RemoteClientFactoryFn {
	return func(context.Context, *slog.Logger, string, kvstore.ExtraOptions) (kvstore.BackendOperations, chan error) {
		errch := make(chan error, len(errs))
		for _, err := range errs {
			errch <- err
		}

		close(errch)
		return client, errch
	}
}

func TestRemoteClusterWatchdog(t *testing.T) {
	client := kvstore.NewInMemoryClient(statedb.New(), "__all__")

	const name = "remote"
	path := filepath.Join(t.TempDir(), name)
	writeFile(t, path, fmt.Sprintf("endpoints:\n- %s\n", kvstore.EtcdDummyAddress()))
	require.NoError(t, clustercfg.Set(context.Background(), name, types.CiliumClusterConfig{ID: 2}, client))

	wait := func(t *testing.T, ch <-chan struct{}, msg string) {
		t.Helper()
		select {
		case <-ch:
		case <-time.After(timeout):
			t.Fatal(msg)
		}
	}

	var statusfn StatusFunc
	ready := make(chan struct{}, 1)
	cm := NewClusterMesh(Configuration{
		Logger:      hivetest.Logger(t),
		ClusterInfo: types.ClusterInfo{ID: 255, Name: "local"},
		NewRemoteCluster: func(name string, sf StatusFunc) RemoteCluster {
			statusfn = sf
			return &fakeRemoteCluster{
				onRun: func(context.Context) { ready <- struct{}{} },
			}
		},
		Metrics: MetricsProvider(metrics.SubsystemClusterMesh)(),
	})

	rc := cm.(*clusterMesh).newRemoteCluster(name, path)

	statusErrors := make(chan error, 1)
	rc.remoteClientFactory = fakeRemoteClusterFactory(&fakeBackend{client, statusErrors})

	var cl *clusterLock
	rc.clusterLockFactory = func() *clusterLock {
		cl = newClusterLock()
		return cl
	}

	rc.connect()
	t.Cleanup(rc.onStop)

	// Wait until the cluster is ready
	wait(t, ready, "Remote cluster didn't turn ready for the first time")
	status := statusfn()
	require.True(t, status.Ready, "Cluster status should report ready")
	require.Zero(t, status.NumFailures, "Cluster status should report no failures")
	require.Zero(t, status.LastFailure, "Cluster status should report no failures")

	// Trigger a status error to force a reconnection
	statusErrors <- errors.New("error")

	// Wait until the cluster turns ready again
	wait(t, ready, "Remote cluster didn't turn ready after kvstore error")
	status = statusfn()
	require.True(t, status.Ready, "Cluster status should report ready")
	require.EqualValues(t, 1, status.NumFailures, "Cluster status should report one failure")
	require.NotZero(t, status.LastFailure, "Cluster status should report one failure")

	// Trigger a cluster lock error to force a reconnection
	cl.errors <- errors.New("error")

	// Wait until the cluster turns ready again
	wait(t, ready, "Remote cluster didn't turn ready after clusterlock error")
	status = statusfn()
	require.True(t, status.Ready, "Cluster status should report ready")
	require.EqualValues(t, 2, status.NumFailures, "Cluster status should report two failures")
	require.NotZero(t, status.LastFailure, "Cluster status should report two failures")
}

func TestRemoteClusterCacheRevokeOnTimeout(t *testing.T) {
	client := kvstore.NewInMemoryClient(statedb.New(), "etcd")

	const name = "remote-revoke-test"
	path := filepath.Join(t.TempDir(), name)
	writeFile(t, path, "endpoints:\n- in-memory\n")
	require.NoError(t, clustercfg.Set(t.Context(), name, types.CiliumClusterConfig{ID: 2}, client))

	ready := make(chan struct{}, 1)
	revoked := make(chan struct{}, 1)

	cm := NewClusterMesh(Configuration{
		Logger:      hivetest.Logger(t),
		ClusterInfo: types.ClusterInfo{ID: 255, Name: "local"},
		NewRemoteCluster: func(name string, sf StatusFunc) RemoteCluster {
			return &fakeRemoteCluster{
				onRun: func(context.Context) {
					ready <- struct{}{}
				},
				onRevokeCache: func(context.Context) {
					revoked <- struct{}{}
				},
			}
		},
		Metrics: MetricsProvider("clustermesh")(),
	})

	rc := cm.(*clusterMesh).newRemoteCluster(name, path)

	statusErrors := make(chan error, 1)
	rc.remoteClientFactory = fakeRemoteClusterFactory(&fakeBackend{client, statusErrors})

	rc.connect()
	t.Cleanup(rc.onStop)

	select {
	case <-ready:
	case <-time.After(timeout):
		t.Fatal("Remote cluster didn't turn ready for the first time")
	}

	// Configure the TTL and mock the factory to permanently fail all future connections.
	rc.ttlChecker.ttl = 100 * time.Millisecond
	rc.remoteClientFactory = fakeRemoteClusterFactory(nil, errors.New("persistent connection failure"))

	// Trigger a status error to force a reconnection
	statusErrors <- errors.New("error")

	select {
	case <-revoked:
		// Success
	case <-time.After(timeout):
		t.Fatal("Cache was not revoked after timeout")
	}
}
