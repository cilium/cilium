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

// +build !privileged_tests

package api

import (
	"fmt"

	k8sapi "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"

	. "gopkg.in/check.v1"
)

func (s *PolicyAPITestSuite) TestEntityMatches(c *C) {
	InitEntities("cluster1")

	c.Assert(EntityHost.Matches(labels.ParseLabelArrayWithHash("reserved:host")), Equals, true)
	c.Assert(EntityHost.Matches(labels.ParseLabelArrayWithHash("reserved:host", "id:foo")), Equals, true)
	c.Assert(EntityHost.Matches(labels.ParseLabelArrayWithHash("reserved:world")), Equals, false)
	c.Assert(EntityHost.Matches(labels.ParseLabelArrayWithHash("reserved:none")), Equals, false)
	c.Assert(EntityHost.Matches(labels.ParseLabelArrayWithHash("id=foo")), Equals, false)

	c.Assert(EntityAll.Matches(labels.ParseLabelArrayWithHash("reserved:host")), Equals, true)
	c.Assert(EntityAll.Matches(labels.ParseLabelArrayWithHash("reserved:world")), Equals, true)
	c.Assert(EntityAll.Matches(labels.ParseLabelArrayWithHash("reserved:none")), Equals, true) // in a white-list model, All trumps None
	c.Assert(EntityAll.Matches(labels.ParseLabelArrayWithHash("id=foo")), Equals, true)

	c.Assert(EntityCluster.Matches(labels.ParseLabelArrayWithHash("reserved:host")), Equals, true)
	c.Assert(EntityCluster.Matches(labels.ParseLabelArrayWithHash("reserved:init")), Equals, true)
	c.Assert(EntityCluster.Matches(labels.ParseLabelArrayWithHash("reserved:world")), Equals, false)
	c.Assert(EntityCluster.Matches(labels.ParseLabelArrayWithHash("reserved:none")), Equals, false)

	clusterLabel := fmt.Sprintf("k8s:%s=%s", k8sapi.PolicyLabelCluster, "cluster1")
	c.Assert(EntityCluster.Matches(labels.ParseLabelArrayWithHash(clusterLabel, "id=foo")), Equals, true)
	c.Assert(EntityCluster.Matches(labels.ParseLabelArrayWithHash(clusterLabel, "id=foo", "id=bar")), Equals, true)
	c.Assert(EntityCluster.Matches(labels.ParseLabelArrayWithHash("id=foo")), Equals, false)

	c.Assert(EntityWorld.Matches(labels.ParseLabelArrayWithHash("reserved:host")), Equals, false)
	c.Assert(EntityWorld.Matches(labels.ParseLabelArrayWithHash("reserved:world")), Equals, true)
	c.Assert(EntityWorld.Matches(labels.ParseLabelArrayWithHash("reserved:none")), Equals, false)
	c.Assert(EntityWorld.Matches(labels.ParseLabelArrayWithHash("id=foo")), Equals, false)
	c.Assert(EntityWorld.Matches(labels.ParseLabelArrayWithHash("id=foo", "id=bar")), Equals, false)

	c.Assert(EntityNone.Matches(labels.ParseLabelArrayWithHash("reserved:host")), Equals, false)
	c.Assert(EntityNone.Matches(labels.ParseLabelArrayWithHash("reserved:world")), Equals, false)
	c.Assert(EntityNone.Matches(labels.ParseLabelArrayWithHash("reserved:init")), Equals, false)
	c.Assert(EntityNone.Matches(labels.ParseLabelArrayWithHash("id=foo")), Equals, false)
	c.Assert(EntityNone.Matches(labels.ParseLabelArrayWithHash(clusterLabel, "id=foo", "id=bar")), Equals, false)

}

func (s *PolicyAPITestSuite) TestEntitySliceMatches(c *C) {
	InitEntities("cluster1")

	slice := EntitySlice{EntityHost, EntityWorld}
	c.Assert(slice.Matches(labels.ParseLabelArrayWithHash("reserved:host")), Equals, true)
	c.Assert(slice.Matches(labels.ParseLabelArrayWithHash("reserved:world")), Equals, true)
	c.Assert(slice.Matches(labels.ParseLabelArrayWithHash("reserved:none")), Equals, false)
	c.Assert(slice.Matches(labels.ParseLabelArrayWithHash("id=foo")), Equals, false)

	// result must be identical if matched via endpoint selector
	selector := slice.GetAsEndpointSelectors()
	c.Assert(selector.Matches(labels.ParseLabelArrayWithHash("reserved:host")), Equals, true)
	c.Assert(selector.Matches(labels.ParseLabelArrayWithHash("reserved:world")), Equals, true)
	c.Assert(selector.Matches(labels.ParseLabelArrayWithHash("reserved:none")), Equals, false)
	c.Assert(selector.Matches(labels.ParseLabelArrayWithHash("id=foo")), Equals, false)
}
