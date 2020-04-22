// Copyright 2018-2019 Authors of Cilium
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

package api

import (
	"fmt"

	k8sapi "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"

	. "gopkg.in/check.v1"
)

// matches returns true if the entity matches the labels
func (e Entity) matches(ctx labels.LabelArray) bool {
	return EntitySlice{e}.matches(ctx)
}

// matches returns true if any of the entities in the slice match the labels
func (s EntitySlice) matches(ctx labels.LabelArray) bool {
	return s.GetAsEndpointSelectors().Matches(ctx)
}

func (s *PolicyAPITestSuite) TestEntityMatches(c *C) {
	InitEntities("cluster1", false)

	c.Assert(EntityHost.matches(labels.ParseLabelArray("reserved:host")), Equals, true)
	c.Assert(EntityHost.matches(labels.ParseLabelArray("reserved:host", "id:foo")), Equals, true)
	c.Assert(EntityHost.matches(labels.ParseLabelArray("reserved:world")), Equals, false)
	c.Assert(EntityHost.matches(labels.ParseLabelArray("reserved:health")), Equals, false)
	c.Assert(EntityHost.matches(labels.ParseLabelArray("reserved:unmanaged")), Equals, false)
	c.Assert(EntityHost.matches(labels.ParseLabelArray("reserved:none")), Equals, false)
	c.Assert(EntityHost.matches(labels.ParseLabelArray("id=foo")), Equals, false)

	c.Assert(EntityAll.matches(labels.ParseLabelArray("reserved:host")), Equals, true)
	c.Assert(EntityAll.matches(labels.ParseLabelArray("reserved:world")), Equals, true)
	c.Assert(EntityAll.matches(labels.ParseLabelArray("reserved:health")), Equals, true)
	c.Assert(EntityAll.matches(labels.ParseLabelArray("reserved:unmanaged")), Equals, true)
	c.Assert(EntityAll.matches(labels.ParseLabelArray("reserved:none")), Equals, true) // in a white-list model, All trumps None
	c.Assert(EntityAll.matches(labels.ParseLabelArray("id=foo")), Equals, true)

	c.Assert(EntityCluster.matches(labels.ParseLabelArray("reserved:host")), Equals, true)
	c.Assert(EntityCluster.matches(labels.ParseLabelArray("reserved:init")), Equals, true)
	c.Assert(EntityCluster.matches(labels.ParseLabelArray("reserved:health")), Equals, true)
	c.Assert(EntityCluster.matches(labels.ParseLabelArray("reserved:unmanaged")), Equals, true)
	c.Assert(EntityCluster.matches(labels.ParseLabelArray("reserved:world")), Equals, false)
	c.Assert(EntityCluster.matches(labels.ParseLabelArray("reserved:none")), Equals, false)

	clusterLabel := fmt.Sprintf("k8s:%s=%s", k8sapi.PolicyLabelCluster, "cluster1")
	c.Assert(EntityCluster.matches(labels.ParseLabelArray(clusterLabel, "id=foo")), Equals, true)
	c.Assert(EntityCluster.matches(labels.ParseLabelArray(clusterLabel, "id=foo", "id=bar")), Equals, true)
	c.Assert(EntityCluster.matches(labels.ParseLabelArray("id=foo")), Equals, false)

	c.Assert(EntityWorld.matches(labels.ParseLabelArray("reserved:host")), Equals, false)
	c.Assert(EntityWorld.matches(labels.ParseLabelArray("reserved:world")), Equals, true)
	c.Assert(EntityWorld.matches(labels.ParseLabelArray("reserved:health")), Equals, false)
	c.Assert(EntityWorld.matches(labels.ParseLabelArray("reserved:unmanaged")), Equals, false)
	c.Assert(EntityWorld.matches(labels.ParseLabelArray("reserved:none")), Equals, false)
	c.Assert(EntityWorld.matches(labels.ParseLabelArray("id=foo")), Equals, false)
	c.Assert(EntityWorld.matches(labels.ParseLabelArray("id=foo", "id=bar")), Equals, false)

	c.Assert(EntityNone.matches(labels.ParseLabelArray("reserved:host")), Equals, false)
	c.Assert(EntityNone.matches(labels.ParseLabelArray("reserved:world")), Equals, false)
	c.Assert(EntityNone.matches(labels.ParseLabelArray("reserved:health")), Equals, false)
	c.Assert(EntityNone.matches(labels.ParseLabelArray("reserved:unmanaged")), Equals, false)
	c.Assert(EntityNone.matches(labels.ParseLabelArray("reserved:init")), Equals, false)
	c.Assert(EntityNone.matches(labels.ParseLabelArray("id=foo")), Equals, false)
	c.Assert(EntityNone.matches(labels.ParseLabelArray(clusterLabel, "id=foo", "id=bar")), Equals, false)

}

func (s *PolicyAPITestSuite) TestEntitySliceMatches(c *C) {
	InitEntities("cluster1", false)

	slice := EntitySlice{EntityHost, EntityWorld}
	c.Assert(slice.matches(labels.ParseLabelArray("reserved:host")), Equals, true)
	c.Assert(slice.matches(labels.ParseLabelArray("reserved:world")), Equals, true)
	c.Assert(slice.matches(labels.ParseLabelArray("reserved:health")), Equals, false)
	c.Assert(slice.matches(labels.ParseLabelArray("reserved:unmanaged")), Equals, false)
	c.Assert(slice.matches(labels.ParseLabelArray("reserved:none")), Equals, false)
	c.Assert(slice.matches(labels.ParseLabelArray("id=foo")), Equals, false)

	slice = EntitySlice{EntityHost, EntityHealth}
	c.Assert(slice.matches(labels.ParseLabelArray("reserved:host")), Equals, true)
	c.Assert(slice.matches(labels.ParseLabelArray("reserved:world")), Equals, false)
	c.Assert(slice.matches(labels.ParseLabelArray("reserved:health")), Equals, true)
	c.Assert(slice.matches(labels.ParseLabelArray("reserved:unmanaged")), Equals, false)
	c.Assert(slice.matches(labels.ParseLabelArray("reserved:none")), Equals, false)
	c.Assert(slice.matches(labels.ParseLabelArray("id=foo")), Equals, false)
}

func (s *PolicyAPITestSuite) TestEntityHostAllowsRemoteNode(c *C) {
	tests := []struct {
		name                  string
		treatRemoteNodeAsHost bool
		expectedMatches       labels.LabelArray
		expectedNonMatches    labels.LabelArray
	}{
		{
			"host entity selects remote-node identity",
			true,
			labels.ParseLabelArray("reserved:remote-node"),
			labels.ParseLabelArray("reserved:all"),
		},
		{
			"host entity does not select remote-node identity",
			false,
			labels.ParseLabelArray("reserved:host"),
			labels.ParseLabelArray("reserved:remote-node"),
		},
	}

	for _, tt := range tests {
		InitEntities("cluster1", tt.treatRemoteNodeAsHost)
		hostSelector := EntitySelectorMapping[EntityHost]
		c.Assert(hostSelector.Matches(tt.expectedMatches), Equals, true, Commentf("Test Name: %s", tt.name))
		c.Assert(hostSelector.Matches(tt.expectedNonMatches), Equals, false, Commentf("Test Name: %s", tt.name))
	}
}
