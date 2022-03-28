// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests && integration_tests

package endpoint

import (
	"gopkg.in/check.v1"

	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/policy"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	"github.com/cilium/cilium/pkg/u8proto"
)

func (s *EndpointSuite) TestUpdateVisibilityPolicy(c *check.C) {
	do := &DummyOwner{repo: policy.NewPolicyRepository(nil, nil, nil)}
	ep := NewEndpointWithState(do, do, ipcache.NewIPCache(nil), nil, testidentity.NewMockIdentityAllocator(nil), 12345, StateReady)
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
