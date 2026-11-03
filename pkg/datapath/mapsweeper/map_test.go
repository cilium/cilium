// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mapsweeper

import (
	"fmt"
	"path/filepath"
	"slices"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/maps/policymap"
)

type testEPManager struct {
	endpoints       map[uint16]struct{}
	paths           []string
	removedPaths    []string
	removedMappings []int
}

func (tm *testEPManager) EndpointExists(id uint16) bool {
	_, exists := tm.endpoints[id]
	return exists
}

func (tm *testEPManager) RemoveDatapathMapping(id uint16) error {
	tm.removedMappings = append(tm.removedMappings, int(id))
	return nil
}

func (tm *testEPManager) RemoveMapPath(path string) {
	tm.removedPaths = append(tm.removedPaths, filepath.Base(path))
}

func (tm *testEPManager) ListMapsDir(path string) []string {
	return tm.paths
}

func (tm *testEPManager) addEndpoint(id uint16) {
	tm.endpoints[id] = struct{}{}
}

func newTestEPManager(paths []string) *testEPManager {
	return &testEPManager{
		endpoints:       make(map[uint16]struct{}),
		paths:           paths,
		removedPaths:    make([]string, 0),
		removedMappings: make([]int, 0),
	}
}

func TestCollectStaleMapGarbage(t *testing.T) {
	testCases := []struct {
		name            string
		endpoints       []uint16
		paths           []string
		removedPaths    []string
		removedMappings []int
	}{
		{
			name: "No deletes",
			endpoints: []uint16{
				1,
				42,
			},
			paths: []string{
				"cilium_policy_v3_00001",
				"cilium_policy_v3_00001",
				"cilium_policy_v3_00042",
			},
			removedPaths:    []string{},
			removedMappings: []int{},
		},
		{
			name: "Delete some endpoints",
			endpoints: []uint16{
				42,
			},
			paths: []string{
				"cilium_policy_v3_00001",
				"cilium_policy_v3_00042",
			},
			removedPaths: []string{
				"cilium_policy_v3_00001",
			},
			removedMappings: []int{
				1,
			},
		},
		{
			name: "Delete some endpoints",
			endpoints: []uint16{
				1,
			},
			paths: []string{
				"cilium_policy_v3_00001",
				"cilium_policy_v3_00042",
			},
			removedPaths: []string{
				"cilium_policy_v3_00042",
			},
			removedMappings: []int{
				42,
			},
		},
		{
			name:      "Delete every map",
			endpoints: []uint16{},
			paths: []string{
				"cilium_policy_v3_00001",
				"cilium_policy_v3_00042",
			},
			removedPaths: []string{
				"cilium_policy_v3_00001",
				"cilium_policy_v3_00042",
			},
			removedMappings: []int{
				1,
				42,
			},
		},
		{
			name: "Delete maps with old path format",
			endpoints: []uint16{
				1,
				42,
			},
			paths: []string{
				"cilium_policy_v3_1",
				"cilium_policy_v3_42",
				"cilium_policy_v3_00001",
				"cilium_policy_v3_00042",
			},
			removedPaths: []string{
				"cilium_policy_v3_1",
				"cilium_policy_v3_42",
			},
			removedMappings: []int{},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			testEPManager := newTestEPManager(tt.paths)
			sweeper := newMapSweeper(hivetest.Logger(t), testEPManager, loadbalancer.DefaultConfig, kpr.KPRConfig{}, &policyMapFactorySweeper{})

			for _, ep := range tt.endpoints {
				testEPManager.addEndpoint(ep)
			}
			for _, path := range testEPManager.paths {
				err := sweeper.walk(path, nil, nil)
				require.NoError(t, err)
			}
			slices.Sort(tt.removedPaths)
			slices.Sort(testEPManager.removedPaths)
			slices.Sort(tt.removedMappings)
			slices.Sort(testEPManager.removedMappings)
			require.Equal(t, tt.removedPaths, testEPManager.removedPaths)
		})
	}
}

func TestRemoveDisabledMaps(t *testing.T) {
	t.Run("Deprecated maps removed", func(t *testing.T) {
		testEPManager := newTestEPManager(
			[]string{
				"cilium_proxy4",
				"cilium_proxy6",
				"cilium_policy_01234",
				"cilium_policy_v3_01234",
				"cilium_policy_v3_reserved_1",
				"cilium_auth_map",
			},
		)
		depricatedMaps := []string{
			"cilium_proxy4",
			"cilium_proxy6",
			"cilium_policy_01234",
			"cilium_auth_map",
		}

		sweeper := newMapSweeper(hivetest.Logger(t), testEPManager, loadbalancer.DefaultConfig, kpr.KPRConfig{}, &policyMapFactorySweeper{})

		sweeper.RemoveDisabledMaps()
		require.Equal(t, depricatedMaps, testEPManager.removedPaths)
	})

	t.Run("SRv6 maps kept with SRv6 disabled", func(t *testing.T) {
		testEPManager := newTestEPManager(
			[]string{
				"cilium_srv6_sid",
				"cilium_srv6_policy_v4",
				"cilium_srv6_policy_v6",
				"cilium_srv6_vrf_v4",
				"cilium_srv6_vrf_v6",
			},
		)

		sweeper := newMapSweeper(hivetest.Logger(t), testEPManager, loadbalancer.DefaultConfig, kpr.KPRConfig{}, &policyMapFactorySweeper{})

		sweeper.RemoveDisabledMaps()
		require.Empty(t, testEPManager.removedPaths)
	})

	sharedPolicyPaths := []string{
		policymap.SharedPolicyMapName,
		policymap.PolicyOverlayMapName,
		"cilium_policy_v3_00001",
	}
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("Shared policy maps with enable-shared-policy=%t", enabled), func(t *testing.T) {
			testEPManager := newTestEPManager(sharedPolicyPaths)
			policyMapFactory := &policyMapFactorySweeper{enabled: enabled}
			sweeper := newMapSweeper(hivetest.Logger(t), testEPManager, loadbalancer.DefaultConfig, kpr.KPRConfig{}, policyMapFactory)
			sweeper.RemoveDisabledMaps()

			if enabled {
				require.ElementsMatch(t, []string{"cilium_policy_v3_00001"},
					testEPManager.removedPaths)
			} else {
				// The shared policy maps must not survive a restart with the shared policy
				// map disabled, otherwise their stale contents would take effect again when
				// it is re-enabled. Per-endpoint policy maps are kept.
				require.ElementsMatch(t, []string{policymap.SharedPolicyMapName, policymap.PolicyOverlayMapName},
					testEPManager.removedPaths)
			}
		})
	}
}

type policyMapFactorySweeper struct {
	policymap.Factory
	overlays map[uint16]bool
	enabled  bool
}

func (p *policyMapFactorySweeper) SharedPolicyEnabled() bool {
	return p != nil && p.enabled
}

func (p *policyMapFactorySweeper) RemoveStaleEndpointOverlays(exists func(uint16) bool) error {
	for id := range p.overlays {
		if !exists(id) {
			delete(p.overlays, id)
		}
	}
	return nil
}

func TestCollectStaleSharedPolicyOverlays(t *testing.T) {
	policyMapFactory := &policyMapFactorySweeper{overlays: map[uint16]bool{1: true, 42: true}}
	testEPManager := newTestEPManager(nil)
	testEPManager.addEndpoint(42)
	sweeper := newMapSweeper(hivetest.Logger(t), testEPManager, loadbalancer.DefaultConfig, kpr.KPRConfig{}, policyMapFactory)
	sweeper.CollectStaleMapGarbage()

	require.NotContains(t, policyMapFactory.overlays, uint16(1), "overlay entry of deleted endpoint must be removed")
	require.Contains(t, policyMapFactory.overlays, uint16(42))
}
