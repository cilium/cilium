// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package maps

import (
	"sort"
	"testing"

	"github.com/cilium/cilium/pkg/checker"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
type MapTestSuite struct{}

var _ = Suite(&MapTestSuite{})

func Test(t *testing.T) {
	TestingT(t)
}

type testEPManager struct {
	endpoints       map[uint16]struct{}
	removedPaths    []string
	removedMappings []int
}

func (tm *testEPManager) EndpointExists(id uint16) bool {
	_, exists := tm.endpoints[id]
	return exists
}

func (tm *testEPManager) HasGlobalCT() bool {
	return false
}

func (tm *testEPManager) RemoveDatapathMapping(id uint16) error {
	tm.removedMappings = append(tm.removedMappings, int(id))
	return nil
}

func (tm *testEPManager) RemoveMapPath(path string) {
	tm.removedPaths = append(tm.removedPaths, path)
}

func (tm *testEPManager) addEndpoint(id uint16) {
	tm.endpoints[id] = struct{}{}
}

func newTestEPManager() *testEPManager {
	return &testEPManager{
		endpoints:       make(map[uint16]struct{}),
		removedPaths:    make([]string, 0),
		removedMappings: make([]int, 0),
	}
}

func (s *MapTestSuite) TestCollectStaleMapGarbage(c *C) {

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
				"cilium_policy_00001",
				"cilium_policy_00001",
				"cilium_policy_00042",
				"cilium_ct6_00001",
				"cilium_ct4_00001",
				"cilium_ct_any6_00001",
				"cilium_ct_any4_00001",
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
				"cilium_policy_00001",
				"cilium_policy_00042",
				"cilium_ct6_00001",
				"cilium_ct4_00001",
				"cilium_ct_any6_00001",
				"cilium_ct_any4_00001",
			},
			removedPaths: []string{
				"cilium_policy_00001",
				"cilium_ct6_00001",
				"cilium_ct4_00001",
				"cilium_ct_any6_00001",
				"cilium_ct_any4_00001",
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
				"cilium_policy_00001",
				"cilium_policy_00042",
				"cilium_ct6_00001",
				"cilium_ct4_00001",
				"cilium_ct_any6_00001",
				"cilium_ct_any4_00001",
			},
			removedPaths: []string{
				"cilium_policy_00042",
			},
			removedMappings: []int{
				42,
			},
		},
		{
			name:      "Delete every map",
			endpoints: []uint16{},
			paths: []string{
				"cilium_policy_00001",
				"cilium_policy_00042",
				"cilium_ct6_00001",
				"cilium_ct4_00001",
				"cilium_ct_any6_00001",
				"cilium_ct_any4_00001",
			},
			removedPaths: []string{
				"cilium_policy_00001",
				"cilium_policy_00042",
				"cilium_ct6_00001",
				"cilium_ct4_00001",
				"cilium_ct_any6_00001",
				"cilium_ct_any4_00001",
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
				"cilium_policy_1",
				"cilium_policy_42",
				"cilium_ct6_1",
				"cilium_ct4_1",
				"cilium_ct_any6_1",
				"cilium_ct_any4_1",
				"cilium_policy_00001",
				"cilium_policy_00042",
				"cilium_ct6_00001",
				"cilium_ct4_00001",
				"cilium_ct_any6_00001",
				"cilium_ct_any4_00001",
			},
			removedPaths: []string{
				"cilium_policy_1",
				"cilium_policy_42",
				"cilium_ct6_1",
				"cilium_ct4_1",
				"cilium_ct_any6_1",
				"cilium_ct_any4_1",
			},
			removedMappings: []int{},
		},
	}

	for _, tt := range testCases {
		c.Log(tt.name)
		testEPManager := newTestEPManager()
		sweeper := NewMapSweeper(testEPManager)

		for _, ep := range tt.endpoints {
			testEPManager.addEndpoint(ep)
		}
		for _, path := range tt.paths {
			err := sweeper.walk(path, nil, nil)
			c.Assert(err, IsNil)
		}
		sort.Strings(tt.removedPaths)
		sort.Strings(testEPManager.removedPaths)
		sort.Ints(tt.removedMappings)
		sort.Ints(testEPManager.removedMappings)
		c.Assert(testEPManager.removedPaths, checker.DeepEquals, tt.removedPaths)
	}
}
