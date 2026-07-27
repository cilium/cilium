// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package writer

import (
	"context"
	"testing"
	"testing/synctest"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"

	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/node"
)

func TestZoneWatcher(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		p := fixture(t)

		// Create services with different traffic distributions
		svcSpecs := []struct {
			name string
			td   loadbalancer.TrafficDistribution
			port uint16
		}{
			{"svc-default", loadbalancer.TrafficDistributionDefault, 80},
			{"svc-same-zone", loadbalancer.TrafficDistributionPreferSameZone, 81},
			{"svc-prefer-close", loadbalancer.TrafficDistributionPreferClose, 82},
			{"svc-same-node", loadbalancer.TrafficDistributionPreferSameNode, 83},
		}

		wtxn := p.Writer.WriteTxn()
		for _, spec := range svcSpecs {
			svcName := loadbalancer.NewServiceName("test", spec.name)
			err := p.Writer.UpsertServiceAndFrontends(
				wtxn,
				&loadbalancer.Service{
					Name:                svcName,
					TrafficDistribution: spec.td,
					Source:              "test",
				},
				loadbalancer.FrontendParams{
					Address:     loadbalancer.NewL3n4Addr(loadbalancer.TCP, intToAddr(1), spec.port, loadbalancer.ScopeExternal),
					Type:        loadbalancer.SVCTypeClusterIP,
					ServicePort: spec.port,
				},
			)
			require.NoError(t, err)
		}
		wtxn.Commit()

		// Helper to get frontend revision
		getFERev := func(name string, port uint16) statedb.Revision {
			txn := p.DB.ReadTxn()
			addr := loadbalancer.NewL3n4Addr(loadbalancer.TCP, intToAddr(1), port, loadbalancer.ScopeExternal)
			_, rev, found := p.FrontendTable.Get(txn, loadbalancer.FrontendByAddress(addr))
			require.True(t, found, "frontend %s not found", name)
			return rev
		}

		// Capture initial revisions
		initialRevs := make(map[string]statedb.Revision)
		for _, spec := range svcSpecs {
			initialRevs[spec.name] = getFERev(spec.name, spec.port)
		}

		// Instantiate and run zoneWatcher manually
		zw := zoneWatcher{
			zoneWatcherParams: zoneWatcherParams{
				Config: loadbalancer.Config{
					UserConfig: loadbalancer.UserConfig{
						EnableServiceTopology: true,
					},
				},
				Writer: p.Writer,
				Nodes:  p.Nodes,
			},
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		health, _ := cell.NewSimpleHealth()
		errCh := make(chan error, 1)
		go func() {
			errCh <- zw.run(ctx, health)
		}()

		// Helper to wait and verify changes relative to a baseline
		verifyRevisions := func(baseline map[string]statedb.Revision, expectedChanges map[string]bool, desc string) map[string]statedb.Revision {
			currentRevs := make(map[string]statedb.Revision)
			require.Eventually(t, func() bool {
				allGood := true
				for _, spec := range svcSpecs {
					rev := getFERev(spec.name, spec.port)
					currentRevs[spec.name] = rev
					changed := rev > baseline[spec.name]
					if expectedChanges[spec.name] != changed {
						allGood = false
					}
				}
				return allGood
			}, 2*time.Second, 10*time.Millisecond, "Verification failed for: %s", desc)
			return currentRevs
		}

		// --- Scenario 1: Initial Zone Discovery ---
		t.Log("Scenario 1: Setting initial zone")
		p.LocalNodeStore.Update(func(n *node.LocalNode) {
			if n.Labels == nil {
				n.Labels = map[string]string{}
			}
			n.Labels[corev1.LabelTopologyZone] = "zone-a"
		})
		synctest.Wait()

		// Expected: Zonal services are refreshed, default and same-node are not.
		expectedInitChanges := map[string]bool{
			"svc-default":      false,
			"svc-same-zone":    true,
			"svc-prefer-close": true,
			"svc-same-node":    false,
		}
		revsAfterInit := verifyRevisions(initialRevs, expectedInitChanges, "Initial Zone Discovery")

		// --- Scenario 2: Unrelated Node Update ---
		t.Log("Scenario 2: Updating unrelated node label (zone remains same)")
		p.LocalNodeStore.Update(func(n *node.LocalNode) {
			n.Labels["dummy-label"] = "dummy-value"
		})
		synctest.Wait()

		// --- Scenario 3: Zone Change ---
		t.Log("Scenario 3: Changing zone")
		p.LocalNodeStore.Update(func(n *node.LocalNode) {
			n.Labels[corev1.LabelTopologyZone] = "zone-b"
		})
		synctest.Wait()

		// Expected: Zonal services are refreshed again due to Scenario 3's zone change.
		// By checking relative to revsAfterInit and using verifyRevisions (which uses require.Eventually),
		// we guarantee that the background worker has fully caught up and processed everything
		// up to and including Scenario 3.
		expectedZoneChanges := map[string]bool{
			"svc-default":      false,
			"svc-same-zone":    true,
			"svc-prefer-close": true,
			"svc-same-node":    false,
		}
		revsAfterScenario3 := verifyRevisions(revsAfterInit, expectedZoneChanges, "Zone Change")

		// To verify that the unrelated node label update (Scenario 2) did not trigger any
		// front-end path re-computations or database writes, we assert on the precise revision increment.
		//
		// Expected write transaction lifecycle commits affecting changed frontends:
		// - Scenario 3 LocalNodeStore zone label update.
		// - zoneWatcher background job path refresh and commit.
		//
		// An implementation that correctly filters unrelated updates results in a total revision delta
		// of exactly 2 for the zonal services. Any extra frontend writes (e.g., due to unexpected path churn)
		// would cause a higher revision delta.
		delta := revsAfterScenario3["svc-same-zone"] - revsAfterInit["svc-same-zone"]
		require.Equal(t, statedb.Revision(2), delta,
			"Service was wrongly refreshed on unrelated node update (extra revision jump detected)")
	})
}
