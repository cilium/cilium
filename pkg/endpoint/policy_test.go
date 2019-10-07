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
	"github.com/cilium/cilium/pkg/u8proto"
	"gopkg.in/check.v1"
)

func (s *EndpointSuite) TestUpdateVisibilityPolicy(c *check.C) {
	ep := NewEndpointWithState(&DummyOwner{repo: policy.NewPolicyRepository()}, nil, 12345, StateReady)
	ep.UpdateVisibilityPolicy("")
	c.Assert(ep.visibilityPolicy, check.IsNil)

	ep.UpdateVisibilityPolicy("<Ingress/80/TCP/HTTP>")

	c.Assert(ep.visibilityPolicy, check.Not(check.Equals), nil)
	c.Assert(ep.visibilityPolicy.Ingress["80/TCP"], check.DeepEquals, &policy.VisibilityMetadata{
		Parser:  policy.ParserTypeHTTP,
		Port:    uint16(80),
		Proto:   u8proto.TCP,
		Ingress: true,
	})

	// Check that updating after previously having value works.
	ep.UpdateVisibilityPolicy("")
	c.Assert(ep.visibilityPolicy, check.IsNil)
}
