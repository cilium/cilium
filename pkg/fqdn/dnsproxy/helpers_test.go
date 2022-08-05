// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package dnsproxy

import (
	"regexp"
	"testing"

	. "gopkg.in/check.v1"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/fqdn/re"
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

func (s *DNSProxyHelperTestSuite) TestSetPortRulesForID(c *C) {
	re.InitRegexCompileLRU(1)
	rules := policy.L7DataMap{}
	epID := uint64(1)
	pea := perEPAllow{}
	cache := newMatcherCache()
	rules[new(MockCachedSelector)] = &policy.PerSelectorPolicy{
		L7Rules: api.L7Rules{
			DNS: []api.PortRuleDNS{
				{MatchName: "cilium.io."},
				{MatchPattern: "*.cilium.io."},
			},
		},
	}
	err := pea.setPortRulesForID(cache, epID, 8053, rules)
	c.Assert(err, Equals, nil)
	c.Assert(len(cache.patternMatcherCache), Equals, 1)
	c.Assert(len(cache.nameMatcherCache), Equals, 1)

	selector2 := new(MockCachedSelector)
	rules[selector2] = &policy.PerSelectorPolicy{
		L7Rules: api.L7Rules{
			DNS: []api.PortRuleDNS{
				{MatchName: "cilium2.io."},
				{MatchPattern: "*.cilium2.io."},
				{MatchPattern: "*.cilium3.io."},
			},
		},
	}
	err = pea.setPortRulesForID(cache, epID, 8053, rules)
	c.Assert(err, Equals, nil)
	c.Assert(len(cache.patternMatcherCache), Equals, 2)
	c.Assert(len(cache.nameMatcherCache), Equals, 2)

	delete(rules, selector2)
	err = pea.setPortRulesForID(cache, epID, 8053, rules)
	c.Assert(err, Equals, nil)
	c.Assert(len(cache.patternMatcherCache), Equals, 1)
	c.Assert(len(cache.nameMatcherCache), Equals, 1)

	err = pea.setPortRulesForID(cache, epID, 8053, nil)
	c.Assert(err, Equals, nil)
	c.Assert(len(cache.patternMatcherCache), Equals, 0)
	c.Assert(len(cache.nameMatcherCache), Equals, 0)
}

func (s *DNSProxyHelperTestSuite) TestSetPortRulesForIDFromUnifiedFormat(c *C) {
	re.InitRegexCompileLRU(1)
	rules := make(CachedSelectorREEntry)
	epID := uint64(1)
	pea := perEPAllow{}
	cache := newMatcherCache()
	rules[new(MockCachedSelector)] = regexp.MustCompile("^.*[.]cilium[.]io$")
	rules[new(MockCachedSelector)] = regexp.MustCompile("^.*[.]cilium[.]io$")

	err := pea.setPortRulesForIDFromUnifiedFormat(cache, epID, 8053, rules)
	c.Assert(err, Equals, nil)
	c.Assert(len(cache.patternMatcherCache), Equals, 1)
	c.Assert(len(cache.nameMatcherCache), Equals, 0)

	selector2 := new(MockCachedSelector)
	rules[selector2] = regexp.MustCompile("^sub[.]cilium[.]io")
	err = pea.setPortRulesForIDFromUnifiedFormat(cache, epID, 8053, rules)
	c.Assert(err, Equals, nil)
	c.Assert(len(cache.patternMatcherCache), Equals, 2)
	c.Assert(len(cache.nameMatcherCache), Equals, 0)

	delete(rules, selector2)
	err = pea.setPortRulesForIDFromUnifiedFormat(cache, epID, 8053, rules)
	c.Assert(err, Equals, nil)
	c.Assert(len(cache.patternMatcherCache), Equals, 1)
	c.Assert(len(cache.nameMatcherCache), Equals, 0)

	err = pea.setPortRulesForIDFromUnifiedFormat(cache, epID, 8053, nil)
	c.Assert(err, Equals, nil)
	c.Assert(len(cache.patternMatcherCache), Equals, 0)
	c.Assert(len(cache.nameMatcherCache), Equals, 0)

	delete(rules, selector2)
	err = pea.setPortRulesForIDFromUnifiedFormat(cache, epID, 8053, rules)
	c.Assert(err, Equals, nil)
	c.Assert(len(cache.patternMatcherCache), Equals, 1)
	c.Assert(len(cache.nameMatcherCache), Equals, 0)

	err = pea.setPortRulesForIDFromUnifiedFormat(cache, epID, 8053, nil)
	c.Assert(err, Equals, nil)
	c.Assert(len(cache.patternMatcherCache), Equals, 0)
	c.Assert(len(cache.nameMatcherCache), Equals, 0)
}

func (s *DNSProxyHelperTestSuite) TestGeneratePatternAndFqdns(c *C) {
	dnsName := "example.name."
	dnsPattern := "*matc*.name."

	l7 := &policy.PerSelectorPolicy{
		L7Rules: api.L7Rules{DNS: []api.PortRuleDNS{
			{
				MatchName: dnsName,
			},
			{
				MatchPattern: dnsPattern,
			},
		}},
	}
	re.InitRegexCompileLRU(defaults.FQDNRegexCompileLRUSize)
	pattern, fqdns := GeneratePatternAndFQDNs(l7)

	regex, err := re.CompileRegex(pattern)
	c.Assert(err, Equals, nil)

	domainMatcher := func(fqdn string) bool {
		for _, val := range fqdns {
			if val == fqdn {
				return true
			}
		}
		return regex.MatchString(fqdn)
	}

	c.Assert(domainMatcher(dnsName), Equals, true)
	c.Assert(domainMatcher(dnsName+"trolo"), Equals, false)
	c.Assert(domainMatcher("thi-is-a-match.name."), Equals, true)
}

type MockCachedSelector struct {
	key string
}

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
	return m.key
}
