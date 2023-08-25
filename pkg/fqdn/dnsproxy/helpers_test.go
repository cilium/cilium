// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dnsproxy

import (
	"regexp"
	"testing"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/fqdn/dns"
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
	cache := make(regexCache)
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
	c.Assert(len(cache), Equals, 1)

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
	c.Assert(len(cache), Equals, 2)

	delete(rules, selector2)
	err = pea.setPortRulesForID(cache, epID, 8053, rules)
	c.Assert(err, Equals, nil)
	c.Assert(len(cache), Equals, 1)

	err = pea.setPortRulesForID(cache, epID, 8053, nil)
	c.Assert(err, Equals, nil)
	c.Assert(len(cache), Equals, 0)

	rules[selector2] = &policy.PerSelectorPolicy{
		L7Rules: api.L7Rules{
			DNS: []api.PortRuleDNS{
				{MatchName: "cilium2.io."},
				{MatchPattern: "*.cilium2.io."},
				{MatchPattern: "-invalid-pattern("},
				{MatchPattern: "*.cilium3.io."},
			},
		},
	}
	err = pea.setPortRulesForID(cache, epID, 8053, rules)

	c.Assert(err, NotNil)
	c.Assert(len(cache), Equals, 0)
}

func (s *DNSProxyHelperTestSuite) TestSetPortRulesForIDFromUnifiedFormat(c *C) {
	re.InitRegexCompileLRU(1)
	rules := make(CachedSelectorREEntry)
	epID := uint64(1)
	pea := perEPAllow{}
	cache := make(regexCache)
	rules[new(MockCachedSelector)] = regexp.MustCompile("^.*[.]cilium[.]io$")
	rules[new(MockCachedSelector)] = regexp.MustCompile("^.*[.]cilium[.]io$")

	err := pea.setPortRulesForIDFromUnifiedFormat(cache, epID, 8053, rules)
	c.Assert(err, Equals, nil)
	c.Assert(len(cache), Equals, 1)

	selector2 := new(MockCachedSelector)
	rules[selector2] = regexp.MustCompile("^sub[.]cilium[.]io")
	err = pea.setPortRulesForIDFromUnifiedFormat(cache, epID, 8053, rules)
	c.Assert(err, Equals, nil)
	c.Assert(len(cache), Equals, 2)

	delete(rules, selector2)
	err = pea.setPortRulesForIDFromUnifiedFormat(cache, epID, 8053, rules)
	c.Assert(err, Equals, nil)
	c.Assert(len(cache), Equals, 1)

	err = pea.setPortRulesForIDFromUnifiedFormat(cache, epID, 8053, nil)
	c.Assert(err, Equals, nil)
	c.Assert(len(cache), Equals, 0)

	delete(rules, selector2)
	err = pea.setPortRulesForIDFromUnifiedFormat(cache, epID, 8053, rules)
	c.Assert(err, Equals, nil)
	c.Assert(len(cache), Equals, 1)

	err = pea.setPortRulesForIDFromUnifiedFormat(cache, epID, 8053, nil)
	c.Assert(err, Equals, nil)
	c.Assert(len(cache), Equals, 0)
}

func (s *DNSProxyHelperTestSuite) TestGeneratePattern(c *C) {
	l7 := &policy.PerSelectorPolicy{
		L7Rules: api.L7Rules{DNS: []api.PortRuleDNS{
			{MatchName: "example.name."},
			{MatchName: "example.com."},
			{MatchName: "demo.io."},
			{MatchName: "demoo.tld."},
			{MatchPattern: "*pattern.com"},
			{MatchPattern: "*.*.*middle.*"},
		}},
	}
	matching := []string{"example.name.", "example.com.", "demo.io.", "demoo.tld.", "testpattern.com.", "pattern.com.", "a.b.cmiddle.io."}
	notMatching := []string{"eexample.name.", "eexample.com.", "vdemo.io.", "demo.ioo.", "emoo.tld.", "test.ppattern.com.", "b.cmiddle.io."}

	re.InitRegexCompileLRU(defaults.FQDNRegexCompileLRUSize)
	pattern := GeneratePattern(l7)

	regex, err := re.CompileRegex(pattern)
	c.Assert(err, Equals, nil)

	for _, fqdn := range matching {
		c.Assert(regex.MatchString(fqdn), Equals, true, Commentf("expected fqdn %q to match, but it did not", fqdn))
	}
	for _, fqdn := range notMatching {
		c.Assert(regex.MatchString(fqdn), Equals, false, Commentf("expected fqdn %q to not match, but it did", fqdn))
	}

	pattern = GeneratePattern(
		&policy.PerSelectorPolicy{
			L7Rules: api.L7Rules{DNS: []api.PortRuleDNS{
				{MatchPattern: "domo.io."},
				{MatchPattern: "*"},
			}},
		})

	regex, err = re.CompileRegex(pattern)
	c.Assert(err, Equals, nil)

	// Ensure all fqdns match a policy with a wildcard
	for _, fqdn := range append(matching, notMatching...) {
		c.Assert(regex.MatchString(fqdn), Equals, true, Commentf("expected fqdn %q to match with wildcard policy, but it did not", fqdn))
	}

	pattern = GeneratePattern(&policy.PerSelectorPolicy{
		L7Rules: api.L7Rules{},
	})

	regex, err = re.CompileRegex(pattern)
	c.Assert(err, Equals, nil)

	// Ensure all fqdns match a policy without any dns-rules
	for _, fqdn := range append(matching, notMatching...) {
		c.Assert(regex.MatchString(fqdn), Equals, true, Commentf("expected fqdn %q to match with wildcard policy, but it did not", fqdn))
	}

	pattern = GeneratePattern(&policy.PerSelectorPolicy{
		L7Rules: api.L7Rules{DNS: []api.PortRuleDNS{}},
	})
	regex, err = re.CompileRegex(pattern)
	c.Assert(err, Equals, nil)

	// Ensure all fqdns match a policy without any dns-rules
	for _, fqdn := range append(matching, notMatching...) {
		c.Assert(regex.MatchString(fqdn), Equals, true, Commentf("expected fqdn %q to match with wildcard policy, but it did not", fqdn))
	}
}

func (s *DNSProxyHelperTestSuite) TestGeneratePatternTrailingDot(c *C) {
	dnsName := "example.name"
	dnsPattern := "*.example.name"
	generatePattern := func(name, pattern string) string {
		l7 := &policy.PerSelectorPolicy{
			L7Rules: api.L7Rules{DNS: []api.PortRuleDNS{
				{MatchName: name},
				{MatchPattern: pattern},
			}},
		}
		return GeneratePattern(l7)

	}
	c.Assert(generatePattern(dnsPattern, dnsName), checker.DeepEquals, generatePattern(dns.FQDN(dnsPattern), dns.FQDN(dnsName)))

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
