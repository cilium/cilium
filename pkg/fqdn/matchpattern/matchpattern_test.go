// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package matchpattern

import (
	"regexp"
	"testing"

	. "github.com/cilium/checkmate"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type MatchPatternTestSuite struct{}

var _ = Suite(&MatchPatternTestSuite{})

// TestMatchPatternREConversion tests that we can validate and convert a
// matchPattern to a compilable regexp.
// It tests:
// cilium.io. -> cilium[.]io[.]
// *.cilium.io. -> [-a-zA-Z0-9]+.cilium[.]io[.]
// *cilium.io. -> "([a-zA-Z0-9]+[.])?cilium[.]io[.]
func (ts *MatchPatternTestSuite) TestAnchoredMatchPatternREConversion(c *C) {
	for source, target := range map[string]string{
		"cilium.io.":      "^cilium[.]io[.]$",
		"*.cilium.io.":    "^" + allowedDNSCharsREGroup + "*[.]cilium[.]io[.]$",
		"**.cilium.io.":   "^(" + allowedDNSCharsREGroup + "+[.])+" + "cilium[.]io[.]$",
		"_sub.**.io.":     "^_sub[.](" + allowedDNSCharsREGroup + "+[.])+io[.]$",
		"**":              "(^(" + allowedDNSCharsREGroup + "+[.])+$)|(^[.]$)",
		"*":               "(^(" + allowedDNSCharsREGroup + "+[.])+$)|(^[.]$)",
		".":               "^[.]$",
		"**.":             "^(" + allowedDNSCharsREGroup + "+[.])+$",
		"*.":              "^" + allowedDNSCharsREGroup + "*[.]$",
		"**.cilium.**.io": "^(" + allowedDNSCharsREGroup + "+[.])+" + "cilium[.](" + allowedDNSCharsREGroup + "+[.])+io$",
		"**cilium.**.io":  "^" + allowedDNSCharsREGroup + "+[.]" + allowedDNSCharsREGroup + "*cilium[.](" + allowedDNSCharsREGroup + "+[.])+io$",
		"cilium.**.**.io": "^cilium[.](" + allowedDNSCharsREGroup + "+[.])+(" + allowedDNSCharsREGroup + "+[.])+io$",
		"**.**.cilium.io": "^(" + allowedDNSCharsREGroup + "+[.])+(" + allowedDNSCharsREGroup + "+[.])+cilium[.]io$",
		"**.**.":          "^(" + allowedDNSCharsREGroup + "+[.])+(" + allowedDNSCharsREGroup + "+[.])+$",
		"**.**":           "^(" + allowedDNSCharsREGroup + "+[.])+" + allowedDNSCharsREGroup + "+[.]" + allowedDNSCharsREGroup + "*$",
		"cilium.**.**.":   "^cilium[.](" + allowedDNSCharsREGroup + "+[.])+(" + allowedDNSCharsREGroup + "+[.])+$",
		"cilium.**.**":    "^cilium[.](" + allowedDNSCharsREGroup + "+[.])+" + allowedDNSCharsREGroup + "+[.]" + allowedDNSCharsREGroup + "*$",
	} {
		reStr := ToAnchoredRegexp(source)
		_, err := regexp.Compile(reStr)
		c.Assert(err, IsNil, Commentf("Regexp generated from pattern %q is not valid", source))
		c.Assert(reStr, Equals, target, Commentf("Regexp generated from pattern %q isn't expected", source))
	}
}

func (ts *MatchPatternTestSuite) TestUnAnchoredMatchPatternREConversion(c *C) {
	for source, target := range map[string]string{
		"cilium.io.":    "cilium[.]io[.]",
		"*.cilium.io.":  allowedDNSCharsREGroup + "*[.]cilium[.]io[.]",
		"**.cilium.io.": "(" + allowedDNSCharsREGroup + "+[.])+" + "cilium[.]io[.]",
		"_sub.**.io":    "_sub[.](" + allowedDNSCharsREGroup + "+[.])+io",
		"**":            MatchAllUnAnchoredPattern,
		"*":             MatchAllUnAnchoredPattern,
		".":             "[.]",
	} {
		reStr := ToUnAnchoredRegexp(source)
		_, err := regexp.Compile(reStr)
		c.Assert(err, IsNil, Commentf("Regexp generated from pattern %q is not valid", source))
		c.Assert(reStr, Equals, target, Commentf("Regexp generated from pattern %q isn't expected", source))
	}
}

// TestMatchPatternMatching tests that patterns actually match what we expect:
// cilium.io. matches only cilium.io.
// *.cilium.io. matches anysub.cilium.io. but not cilium.io.
// *cilium.io. matches  anysub.cilium.io. and cilium.io.
// *.ci*.io. matches anysub.cilium.io. anysub.ci.io., anysub.ciliumandmore.io. but not cilium.io.
// **.cilium.io. matches  anysub.cilium.io. and more subdomains.
// **.ci*.io. matches anysub.cilium.io. anysub.ci.io. and more subdomains like anysub.ciliumandmore.io and some.more.ci.io. but not cilium.io.
func (ts *MatchPatternTestSuite) TestAnchoredMatchPatternMatching(c *C) {
	for _, testCase := range []struct {
		pattern string
		accept  []string
		reject  []string
	}{
		{
			pattern: "cilium.io.",
			accept:  []string{"cilium.io."},
			reject:  []string{"", "anysub.cilium.io.", "anysub.ci.io.", "anysub.ciliumandmore.io."},
		},
		{
			pattern: "*.cilium.io.",
			accept:  []string{"anysub.cilium.io."},
			reject:  []string{"", "cilium.io.", "anysub.ci.io.", "anysub.ciliumandmore.io."},
		},
		{
			pattern: "*.ci*.io.",
			accept:  []string{"anysub.cilium.io.", "anysub.ci.io.", "anysub.ciliumandmore.io."},
			reject:  []string{"", "ci.io", "cilium.io.", "service.namesace.svc.cluster.local."},
		},
		{
			pattern: "*",
			accept:  []string{".", "io.", "cilium.io.", "svc.cluster.local.", "service.namesace.svc.cluster.local.", "_foobar._tcp.cilium.io."}, // the last is for SRV RFC-2782 and DNS-SD RFC6763
			reject:  []string{"", ".io.", ".cilium.io.", ".svc.cluster.local.", "cilium.io"},                                                    // note no final . on this last one
		},
		{
			pattern: ".",
			accept:  []string{"."},
			reject:  []string{"", ".io.", ".cilium.io"},
		},

		// These are more explicit tests for SRV RFC-2782 and DNS-SD RFC6763
		{
			pattern: "_foobar._tcp.cilium.io.",
			accept:  []string{"_foobar._tcp.cilium.io."},
			reject:  []string{"", "_tcp.cilium.io.", "cilium.io."},
		},
		{
			pattern: "*.*.cilium.io.",
			accept:  []string{"_foobar._tcp.cilium.io."},
			reject:  []string{""},
		},

		// Tests including ** which requires 1+ occurrence of characters and dots if more subdomains, double dot in a row is not accepted
		{
			pattern: "**.cilium.io.",
			accept:  []string{"anysub.cilium.io.", "_foobar._tcp.cilium.io.", "sub11.sub22.sub33._foobar._tcp.cilium.io."},
			reject:  []string{"", "cilium.io.", "anysub.ci.io.", "anysub.ciliumandmore.io.", "sub.cilium.io", "1._foobar_tcp.cilium.trio."},
		},
		{
			pattern: "*.**.cilium.io.",
			accept:  []string{"_foobar._tcp.cilium.io.", "_foobar._tcp.cilium.io.", "2._foobar._tcp.cilium.io."},
			reject:  []string{"", "_tcp.cilium.io.", "_foobar.._tcp.cilium.io."},
		},
		{
			pattern: "**.ci*.io.",
			accept:  []string{"anysub.cilium.io.", "anysub.ci.io.", "1.anysub.ciliumandmore.io.", "service.namesace.svc.ciuster.io."},
			reject:  []string{"", "cilium.io.", "cilium.io.", "service.namesace.svc..ciblaster.io."},
		},
		{
			pattern: "**.*.io.",
			accept:  []string{"anysub.cilium.io.", "anysub.ci.io.", "anysub.ciliumandmore.io.", "service.namesace.svc.ciuster.io."},
			reject:  []string{"", "io.", "..cilium.io.", "cilium.io.", "service..namesace.svc.cluster.io."},
		},
		{
			pattern: "*.**.io.",
			accept:  []string{"anysub.cilium.io.", "anysub.ci.io.", "anysub.ciliumandmore.io.", "service.namesace.svc.ciuster.io."},
			reject:  []string{"", "..cilium.io.", "io.", "cilium.io", "service.namesace.svc..cluster.io."},
		},
		{
			pattern: "**",
			accept:  []string{".", "io.", "cilium.io.", "svc.cluster.local.", "service.namesace.svc.cluster.local.", "_foobar._tcp.cilium.io."},
			reject:  []string{"", "..io.", "..cilium.io.", ".svc.cluster..local.", "cilium..io"},
		},
		{
			pattern: "**.",
			accept:  []string{"io.", "cilium.io.", "svc.cluster.local.", "service.namesace.svc.cluster.local.", "_foobar._tcp.cilium.io."},
			reject:  []string{"", ".cilium.io.", "..cilium.io.", ".svc.cluster..local.", "cilium.io"},
		},
		{
			pattern: "1.**.*io.",
			accept:  []string{"1._foobar._tcp.cilium.io.", "1.2._foobar._tcp.cilium.io.", "1._foobar_tcp.cilium.trio."},
			reject:  []string{"", "_tcp.cilium.io.", "_foobar._tcp.cilium.io.", "2._foobar._tcp.cilium.io.", "1_foobar._tcp.cilium.trio."},
		},
		{
			pattern: "subdomain.**.*ili*.io.",
			accept:  []string{"subdomain._foobar._tcp.cilium.io.", "subdomain.1.2._foobar._tcp.cili.io.", "subdomain._foobar_tcp.ilium.io."},
			reject:  []string{"", "_tcp.cilium.io.", "_foobar._tcp.cilium.io.", ".subdomain._foobar._tcp.cilium.io.", "subdomain.cilium.trio.", "subdomain.1..2._foobar._tcp.cili.io."},
		},
		{
			pattern: "1.**.cilium.io.",
			accept:  []string{"1._foobar._tcp.cilium.io.", "1.2._foobar._tcp.cilium.io."},
			reject:  []string{"", "_tcp.cilium.io.", "_foobar._tcp.cilium.io.", "2._foobar._tcp.cilium.io."},
		},
		{
			pattern: "*.1.**.cilium.io.",
			accept:  []string{"_sub.1._foobar._tcp.cilium.io.", "_sub.1.2._foobar._tcp.cilium.io."},
			reject:  []string{"", "_sub._tcp.1.cilium.io.", "_foobar._tcp.cilium.io.", "2._foobar._tcp.cilium.io.", "2._foobar.1._tcp.cilium.io."},
		},
	} {
		reStr := ToAnchoredRegexp(testCase.pattern)
		re, err := regexp.Compile(reStr)
		c.Assert(err, IsNil, Commentf("Regexp generated from pattern is not valid"))
		for _, accept := range testCase.accept {
			c.Assert(re.MatchString(accept), Equals, true, Commentf("Regexp generated from pattern %s/%s rejected a correct DNS name %s", testCase.pattern, re, accept))
		}
		for _, reject := range testCase.reject {
			c.Assert(re.MatchString(reject), Equals, false, Commentf("Regexp generated from pattern %s/%s accepted a bad DNS name %s", testCase.pattern, re, reject))
		}
	}
}

// TestMatchPatternSanitize tests that Sanitize handles any special cases
func (ts *MatchPatternTestSuite) TestMatchPatternSanitize(c *C) {
	for source, target := range map[string]string{
		"**":    "**.",
		"**.":   "**.",
		"*":     "*",
		"*.":    "*.",
		"*.com": "*.com.",
	} {
		sanitized := Sanitize(source)
		c.Assert(sanitized, Equals, target, Commentf("matchPattern: %s not sanitized correctly", source))
	}
}
