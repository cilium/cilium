// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests
// +build !privileged_tests

package dnsproxy

import (
	"testing"

	"github.com/golang/groupcache/lru"
	. "gopkg.in/check.v1"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
)

type DNSProxyHelperTestSuite struct{}

var _ = Suite(&DNSProxyHelperTestSuite{})

// Hook up gocheck into the "go test" runner.
func TestNonPrivileged(t *testing.T) {
	TestingT(t)
}

func (s *DNSProxyHelperTestSuite) TestGetSelectorRegexMap(c *C) {
	selector := MockCachedSelector{}

	dnsName := "example.name."

	l7 := policy.L7DataMap{
		selector: &policy.PerSelectorPolicy{
			L7Rules: api.L7Rules{DNS: []api.PortRuleDNS{
				{
					MatchName: dnsName,
				},
			}},
		},
	}
	cache := &lru.Cache{}
	m, err := GetSelectorRegexMap(l7, cache)

	c.Assert(err, Equals, nil)

	regex, ok := m[selector]

	c.Assert(ok, Equals, true)

	c.Assert(regex.MatchString(dnsName), Equals, true)
	c.Assert(regex.MatchString(dnsName+"trolo"), Equals, false)
}

type MockCachedSelector struct{}

func (m MockCachedSelector) GetSelections() []identity.NumericIdentity {
	return nil
}

func (m MockCachedSelector) Selects(_ identity.NumericIdentity) bool {
	return false
}

func (m MockCachedSelector) IsWildcard() bool {
	return false
}

func (m MockCachedSelector) IsNone() bool {
	return false
}

func (m MockCachedSelector) String() string {
	return "string"
}
