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

package endpoint

import (
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/testutils/allocator"
	"github.com/cilium/cilium/pkg/u8proto"

	. "gopkg.in/check.v1"
)

func (s *EndpointSuite) TestUpdateVisibilityPolicy(c *C) {
	ep := NewEndpointWithState(&DummyOwner{repo: policy.NewPolicyRepository(nil, nil)}, nil, &allocator.FakeIdentityAllocator{}, 12345, StateReady)
	regenNeeded, err := ep.UpdateVisibilityPolicy("")
	c.Assert(err, IsNil)
	c.Assert(regenNeeded, Equals, false)
	c.Assert(ep.visibilityPolicy, IsNil)

	regenNeeded, err = ep.UpdateVisibilityPolicy("<Ingress/80/TCP/HTTP>")
	c.Assert(err, IsNil)
	c.Assert(regenNeeded, Equals, true)

	c.Assert(ep.visibilityPolicy, Not(IsNil))
	c.Assert(ep.visibilityPolicy.Ingress["80/TCP"], DeepEquals, &policy.VisibilityMetadata{
		Parser:  policy.ParserTypeHTTP,
		Port:    uint16(80),
		Proto:   u8proto.TCP,
		Ingress: true,
	})

	// Check that error is a no-op
	ovp := ep.visibilityPolicy
	regenNeeded, err = ep.UpdateVisibilityPolicy("<Inkress/80/TCP/HTTP>")
	c.Assert(err, Not(IsNil))
	c.Assert(regenNeeded, Equals, false)
	c.Assert(ep.visibilityPolicy, Equals, ovp)

	// Check that updating after previously having value works.
	regenNeeded, err = ep.UpdateVisibilityPolicy("")
	c.Assert(err, IsNil)
	c.Assert(regenNeeded, Equals, true)
	c.Assert(ep.visibilityPolicy, IsNil)

	// Check that no change is a no-op
	regenNeeded, err = ep.UpdateVisibilityPolicy("")
	c.Assert(err, IsNil)
	c.Assert(regenNeeded, Equals, false)
	c.Assert(ep.visibilityPolicy, IsNil)
}
