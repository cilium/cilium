// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	operatorK8s "github.com/cilium/cilium/operator/k8s"
	"github.com/cilium/cilium/operator/pkg/ciliumpod"
	"github.com/cilium/cilium/pkg/hive"
	k8sFakeClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/option"
)

// TestNodeTaintSyncCellShutdown verifies that starting and stopping
// CiliumNodeGCCell and NodeTaintSyncCell together does not deadlock.
//
// Both cells read Kubernetes nodes, and the taint sync's workers block on a
// queue fed from those node events. Hive runs stop hooks in reverse start
// order, so if either cell owned state the other had to release, one stop hook
// would wait on a hook that cannot run yet. The node resource owns the
// informer and the taint sync owns its queue, so neither cell has to reach
// into the other, and the order they are registered in must not matter.
//
// The EnableCiliumNodeCRD cases matter because the GC cell only reads nodes on
// the enabled branch: with the CRD disabled the taint sync is the sole reader,
// which used to swap which cell owned the shared informer.
func TestNodeTaintSyncCellShutdown(t *testing.T) {
	for _, tc := range []struct {
		name                string
		enableCiliumNodeCRD bool
		taintSyncFirst      bool
	}{
		{name: "CRD enabled", enableCiliumNodeCRD: true},
		{name: "CRD disabled", enableCiliumNodeCRD: false},
		{name: "CRD enabled, taint sync registered first", enableCiliumNodeCRD: true, taintSyncFirst: true},
		{name: "CRD disabled, taint sync registered first", enableCiliumNodeCRD: false, taintSyncFirst: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			watcherCells := []cell.Cell{CiliumNodeGCCell, NodeTaintSyncCell}
			if tc.taintSyncFirst {
				watcherCells[0], watcherCells[1] = watcherCells[1], watcherCells[0]
			}

			testHive := hive.New(append([]cell.Cell{
				k8sFakeClient.FakeClientCell(),
				operatorK8s.ResourcesCell,
				ciliumpod.Cell,
				cell.Provide(func() *option.DaemonConfig {
					return &option.DaemonConfig{EnableCiliumNodeCRD: tc.enableCiliumNodeCRD}
				}),
			}, watcherCells...)...)
			hive.AddConfigOverride(testHive, func(cfg *CiliumNodeGCConfig) {
				cfg.NodesGCInterval = time.Hour
			})
			hive.AddConfigOverride(testHive, func(cfg *NodeTaintSyncConfig) {
				cfg.TaintSyncWorkers = 1
			})

			logger := hivetest.Logger(t)
			require.NoError(t, testHive.Start(logger, t.Context()))

			stopResult := make(chan error, 1)
			go func() {
				stopResult <- testHive.Stop(logger, context.Background())
			}()

			timer := time.NewTimer(5 * time.Second)
			defer timer.Stop()

			select {
			case err := <-stopResult:
				require.NoError(t, err)
			case <-timer.C:
				t.Fatal("operator Hive deadlocked while stopping the node watcher cells")
			}
		})
	}
}
