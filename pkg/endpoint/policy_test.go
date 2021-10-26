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
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	"github.com/cilium/cilium/pkg/u8proto"

	"gopkg.in/check.v1"
)

func (s *EndpointSuite) TestUpdateVisibilityPolicy(c *check.C) {
	ep := NewEndpointWithState(&DummyOwner{repo: policy.NewPolicyRepository(nil, nil, nil)}, nil, testidentity.NewFakeIdentityAllocator(nil), 12345, StateReady)
	ep.UpdateVisibilityPolicy(func(_, _ string) (string, error) {
		return "", nil
	})
	c.Assert(ep.visibilityPolicy, check.IsNil)

	ep.UpdateVisibilityPolicy(func(_, _ string) (proxyVisibility string, err error) {
		return "<Ingress/80/TCP/HTTP>", nil
	})

	c.Assert(ep.visibilityPolicy, check.Not(check.Equals), nil)
	c.Assert(ep.visibilityPolicy.Ingress["80/TCP"], check.DeepEquals, &policy.VisibilityMetadata{
		Parser:  policy.ParserTypeHTTP,
		Port:    uint16(80),
		Proto:   u8proto.TCP,
		Ingress: true,
	})

	// Check that updating after previously having value works.
	ep.UpdateVisibilityPolicy(func(_, _ string) (string, error) {
		return "", nil
	})
	c.Assert(ep.visibilityPolicy, check.IsNil)
}
