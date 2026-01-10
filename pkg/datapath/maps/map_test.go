// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package maps

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	fakeTypes "github.com/cilium/cilium/pkg/datapath/fake/types"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/loadbalancer"
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

func newTestBWManager() types.BandwidthManager {
	return &fakeTypes.BandwidthManager{}
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
				"cilium_policy_v2_00001",
				"cilium_policy_v2_00001",
				"cilium_policy_v2_00042",
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
				"cilium_policy_v2_00001",
				"cilium_policy_v2_00042",
			},
			removedPaths: []string{
				"cilium_policy_v2_00001",
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
				"cilium_policy_v2_00001",
				"cilium_policy_v2_00042",
			},
			removedPaths: []string{
				"cilium_policy_v2_00042",
			},
			removedMappings: []int{
				42,
			},
		},
		{
			name:      "Delete every map",
			endpoints: []uint16{},
			paths: []string{
				"cilium_policy_v2_00001",
				"cilium_policy_v2_00042",
			},
			removedPaths: []string{
				"cilium_policy_v2_00001",
				"cilium_policy_v2_00042",
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
				"cilium_policy_v2_1",
				"cilium_policy_v2_42",
				"cilium_policy_v2_00001",
				"cilium_policy_v2_00042",
			},
			removedPaths: []string{
				"cilium_policy_v2_1",
				"cilium_policy_v2_42",
			},
			removedMappings: []int{},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			testEPManager := newTestEPManager(tt.paths)
			bwManager := newTestBWManager()
			sweeper := newMapSweeper(hivetest.Logger(t), testEPManager, bwManager, loadbalancer.DefaultConfig, kpr.KPRConfig{})

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
				"cilium_policy_v2_01234",
				"cilium_policy_v2_reserved_1",
			},
		)
		depricatedMaps := []string{
			"cilium_proxy4",
			"cilium_proxy6",
			"cilium_policy_01234",
		}
		bwManager := newTestBWManager()
		sweeper := newMapSweeper(hivetest.Logger(t), testEPManager, bwManager, loadbalancer.DefaultConfig, kpr.KPRConfig{})

		sweeper.RemoveDisabledMaps()
		require.Equal(t, depricatedMaps, testEPManager.removedPaths)
	})
}
