// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests && integration_tests

package kvstore

import (
	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) {
	TestingT(t)
}

// independentSuite tests are tests which can run without creating a backend
type independentSuite struct{}

var _ = Suite(&independentSuite{})

func (s *independentSuite) TestGetLockPath(c *C) {
	const path = "foo/path"
	c.Assert(getLockPath(path), Equals, path+".lock")
}

func (s *independentSuite) TestValidateScopesFromKey(c *C) {
	mockData := map[string]string{
		"cilium/state/identities/v1/id": "identities/v1",
		"cilium/state/identities/v1/value/Y29udGFpbmVyOmlkPWFwcDE7Y29udGFpbmVyOmlkLnNlcnZpY2UxPTs=": "identities/v1",
		"cilium/state/ip/v1/default/10.15.189.183":                                                  "ip/v1",
		"cilium/state/ip/v1/default/f00d::a0f:0:0:6f2e":                                             "ip/v1",
		"cilium/state/nodes/v1/default/runtime":                                                     "nodes/v1",
	}

	for key, val := range mockData {
		c.Assert(getScopeFromKey(key), Equals, val)
	}
}
