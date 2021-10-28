// SPDX-License-Identifier: Apache-2.0
// Copyright 2019-2021 Authors of Cilium

//go:build !privileged_tests && integration_tests
// +build !privileged_tests,integration_tests

package endpoint

import (
	"github.com/cilium/cilium/pkg/policy"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	"github.com/cilium/cilium/pkg/u8proto"

	"gopkg.in/check.v1"
)

func (s *EndpointSuite) TestUpdateVisibilityPolicy(c *check.C) {
	ep := NewEndpointWithState(&DummyOwner{repo: policy.NewPolicyRepository(nil, nil, nil)}, nil, testidentity.NewMockIdentityAllocator(nil), 12345, StateReady)
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
