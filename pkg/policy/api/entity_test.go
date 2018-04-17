// Copyright 2018 Authors of Cilium
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

package api

import (
	"github.com/cilium/cilium/pkg/labels"

	. "gopkg.in/check.v1"
)

func (s *PolicyAPITestSuite) TestEntityMatches(c *C) {
	c.Assert(EntityHost.Matches(labels.ParseLabelArray("reserved:host")), Equals, true)
	c.Assert(EntityHost.Matches(labels.ParseLabelArray("reserved:host", "id:foo")), Equals, true)
	c.Assert(EntityHost.Matches(labels.ParseLabelArray("reserved:cluster")), Equals, false)
	c.Assert(EntityHost.Matches(labels.ParseLabelArray("reserved:world")), Equals, false)
	c.Assert(EntityHost.Matches(labels.ParseLabelArray("id=foo")), Equals, false)

	c.Assert(EntityAll.Matches(labels.ParseLabelArray("reserved:host")), Equals, true)
	c.Assert(EntityAll.Matches(labels.ParseLabelArray("reserved:cluster")), Equals, true)
	c.Assert(EntityAll.Matches(labels.ParseLabelArray("reserved:world")), Equals, true)
	c.Assert(EntityAll.Matches(labels.ParseLabelArray("id=foo")), Equals, true)

	// EntityCluster doesn't select host, as EndpointSelector can't express OR relationships.
	c.Assert(EntityCluster.Matches(labels.ParseLabelArray("reserved:host")), Equals, false)
	c.Assert(EntityCluster.Matches(labels.ParseLabelArray("reserved:cluster")), Equals, true)
	c.Assert(EntityCluster.Matches(labels.ParseLabelArray("reserved:world")), Equals, false)
	c.Assert(EntityCluster.Matches(labels.ParseLabelArray("id=foo")), Equals, false)
	c.Assert(EntityCluster.Matches(labels.ParseLabelArray("id=foo", "id=bar")), Equals, false)

	c.Assert(EntityWorld.Matches(labels.ParseLabelArray("reserved:host")), Equals, false)
	c.Assert(EntityWorld.Matches(labels.ParseLabelArray("reserved:cluster")), Equals, false)
	c.Assert(EntityWorld.Matches(labels.ParseLabelArray("reserved:world")), Equals, true)
	c.Assert(EntityWorld.Matches(labels.ParseLabelArray("id=foo")), Equals, false)
	c.Assert(EntityWorld.Matches(labels.ParseLabelArray("id=foo", "id=bar")), Equals, false)
}

func (s *PolicyAPITestSuite) TestEntitySliceMatches(c *C) {
	slice := EntitySlice{EntityHost, EntityWorld}
	c.Assert(slice.Matches(labels.ParseLabelArray("reserved:host")), Equals, true)
	c.Assert(slice.Matches(labels.ParseLabelArray("reserved:world")), Equals, true)
	c.Assert(slice.Matches(labels.ParseLabelArray("id=foo")), Equals, false)

	// result must be identical if matched via endpoint selector
	selector := slice.GetAsEndpointSelectors()
	c.Assert(selector.Matches(labels.ParseLabelArray("reserved:host")), Equals, true)
	c.Assert(selector.Matches(labels.ParseLabelArray("reserved:world")), Equals, true)
	c.Assert(selector.Matches(labels.ParseLabelArray("id=foo")), Equals, false)
}
