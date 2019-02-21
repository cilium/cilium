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

type testWalker struct {
	endpoints       map[uint16]struct{}
	removedPaths    []string
	removedMappings []int
}

func (tw *testWalker) shouldRemove(id uint16) bool {
	_, exists := tw.endpoints[id]
	return !exists
}

func (tw *testWalker) removeMapping(id uint32) error {
	tw.removedMappings = append(tw.removedMappings, int(id))
	return nil
}

func (tw *testWalker) removePath(path string) {
	tw.removedPaths = append(tw.removedPaths, path)
}

func (tw *testWalker) addEndpoint(id uint16) {
	tw.endpoints[id] = struct{}{}
}

func newTestWalker() *testWalker {
	return &testWalker{
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
				"cilium_policy_1",
				"cilium_policy_42",
				"cilium_ct6_1",
				"cilium_ct4_1",
				"cilium_ct_any6_1",
				"cilium_ct_any4_1",
				"cilium_ep_config_1",
			},
			removedPaths:    []string{},
			removedMappings: []int{},
		},
		{
			name: "Delete some endpoints",
			endpoints: []uint16{
				1,
			},
			paths: []string{
				"cilium_policy_1",
				"cilium_policy_42",
				"cilium_ct6_1",
				"cilium_ct4_1",
				"cilium_ct_any6_1",
				"cilium_ct_any4_1",
				"cilium_ep_config_1",
			},
			removedPaths: []string{
				"cilium_policy_42",
			},
			removedMappings: []int{
				42,
			},
		},
		{
			name:      "Delete every map",
			endpoints: []uint16{},
			paths: []string{
				"cilium_policy_1",
				"cilium_policy_42",
				"cilium_ct6_1",
				"cilium_ct4_1",
				"cilium_ct_any6_1",
				"cilium_ct_any4_1",
				"cilium_ep_config_1",
			},
			removedPaths: []string{
				"cilium_policy_1",
				"cilium_policy_42",
				"cilium_ct6_1",
				"cilium_ct4_1",
				"cilium_ct_any6_1",
				"cilium_ct_any4_1",
				"cilium_ep_config_1",
			},
			removedMappings: []int{
				1,
				42,
			},
		},
	}

	for _, tt := range testCases {
		testWalker := newTestWalker()
		sweeper := newMapSweeper(testWalker)

		for _, ep := range tt.endpoints {
			testWalker.addEndpoint(ep)
		}
		for _, path := range tt.paths {
			err := sweeper.walk(path, nil, nil)
			c.Assert(err, IsNil)
		}
		sort.Strings(tt.removedPaths)
		sort.Strings(testWalker.removedPaths)
		sort.Ints(tt.removedMappings)
		sort.Ints(testWalker.removedMappings)
		c.Assert(testWalker.removedPaths, checker.DeepEquals, tt.removedPaths)
	}
}
