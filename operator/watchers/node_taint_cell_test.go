// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/tools/cache"

	operatorK8s "github.com/cilium/cilium/operator/k8s"
	"github.com/cilium/cilium/operator/pkg/ciliumpod"
	"github.com/cilium/cilium/pkg/hive"
	k8sFakeClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/option"
)

// TestNodeTaintSyncCellShutdownDoesNotDeadlock verifies that starting and
// stopping CiliumNodeGCCell and NodeTaintSyncCell does not deadlock. Both cells
// depend on the package-global Node informer, store, and queue initialized by
// nodesInit. CiliumNodeGCCell starts first and owns the informer lifecycle and
// deferred queue shutdown, while NodeTaintSyncCell owns the workers consuming
// that queue. Since Hive stops the cells in reverse order, NodeTaintSyncCell
// must shut down the queue before waiting for its workers; otherwise the GC
// stop hook that owns the informer cannot run.
func TestNodeTaintSyncCellShutdownDoesNotDeadlock(t *testing.T) {
	resetNodeWatcherStateForTest()

	testHive := hive.New(
		k8sFakeClient.FakeClientCell(),
		operatorK8s.ResourcesCell,
		ciliumpod.Cell,
		cell.Provide(func() *option.DaemonConfig {
			return &option.DaemonConfig{EnableCiliumNodeCRD: true}
		}),
		CiliumNodeGCCell,
		NodeTaintSyncCell,
	)
	hive.AddConfigOverride(testHive, func(cfg *CiliumNodeGCConfig) {
		cfg.NodesGCInterval = time.Hour
	})
	hive.AddConfigOverride(testHive, func(cfg *NodeTaintSyncConfig) {
		cfg.TaintSyncWorkers = 1
	})

	logger := hivetest.Logger(t)
	needsStop := true
	t.Cleanup(func() {
		if needsStop {
			if nodeQueue != nil {
				nodeQueue.ShutDown()
			}
			_ = testHive.Stop(logger, context.Background())
		}
		resetNodeWatcherStateForTest()
	})

	require.NoError(t, testHive.Start(logger, t.Context()))
	queue := nodeQueue
	require.NotNil(t, queue)
	require.False(t, queue.ShuttingDown())

	stopResult := make(chan error, 1)
	stopCtx := t.Context()
	go func() {
		stopResult <- testHive.Stop(logger, stopCtx)
	}()

	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()

	select {
	case err := <-stopResult:
		needsStop = false
		require.NoError(t, err)
	case <-timer.C:
		queue.ShutDown()
		err := <-stopResult
		needsStop = false
		require.NoError(t, err)
		t.Fatal("operator Hive deadlocked while stopping NodeTaintSyncCell")
	}

	require.True(t, queue.ShuttingDown())
}

// resetNodeWatcherStateForTest resets the package-global state guarded by
// nodeSyncOnce. Without this reset, repeated test runs would reuse the stopped
// queue and would no longer exercise the original startup and shutdown order.
func resetNodeWatcherStateForTest() {
	nodeSyncOnce = sync.Once{}
	slimNodeStore = nil
	slimNodeStoreSynced = make(chan struct{})
	nodeController = nil
	nodeQueue = nil
	ciliumPodsStore = cache.NewIndexer(cache.DeletionHandlingMetaNamespaceKeyFunc, ciliumIndexers)
	mno = markNodeOptions{}
}
