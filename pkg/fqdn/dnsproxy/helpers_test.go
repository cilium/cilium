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

package dnsproxy

import (
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/golang/groupcache/lru"
	. "gopkg.in/check.v1"
	"testing"
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
