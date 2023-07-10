// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package matchpattern

import (
	"regexp"
	"testing"

	. "gopkg.in/check.v1"
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
func (ts *MatchPatternTestSuite) TestMatchPatternREConversion(c *C) {
	for source, target := range map[string]string{
		"cilium.io.":   "^cilium[.]io[.]$",
		"*.cilium.io.": "^" + allowedDNSCharsREGroup + "*[.]cilium[.]io[.]$",
		"*":            "(^(" + allowedDNSCharsREGroup + "+[.])+$)|(^[.]$)",
		".":            "^[.]$",
	} {
		reStr := ToRegexp(source)
		_, err := regexp.Compile(reStr)
		c.Assert(err, IsNil, Commentf("Regexp generated from pattern %sis not valid", source))
		c.Assert(reStr, Equals, target, Commentf("Regexp generated from pattern %s isn't expected", source))
	}
}

// TestMatchPatternMatching tests that patterns actually match what we expect:
// cilium.io. matches only cilium.io.
// *.cilium.io. matches anysub.cilium.io. but not cilium.io.
// *cilium.io. matches  anysub.cilium.io. and cilium.io.
// *.ci*.io. matches anysub.cilium.io. anysub.ci.io., anysub.ciliumandmore.io. but not cilium.io.
func (ts *MatchPatternTestSuite) TestMatchPatternMatching(c *C) {
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
			reject:  []string{"", "cilium.io."},
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
	} {
		reStr := ToRegexp(testCase.pattern)
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
		"*":     "*",
		"*.":    "*.",
		"*.com": "*.com.",
	} {
		sanitized := Sanitize(source)
		c.Assert(sanitized, Equals, target, Commentf("matchPattern: %s not sanitized correctly", source))
	}
}

// TestMatchPatternIsMoreSpecific tests IsMoreSpecific
func (ts *MatchPatternTestSuite) TestMatchPatternIsMoreSpecific(c *C) {
	type testcase struct {
		a   string
		b   string
		res bool
	}
	for _, t := range []testcase{
		{a: "", b: "", res: false},
		{a: "", b: "*", res: false},
		{a: "*", b: "", res: false},
		{a: "*.", b: "*.", res: false},
		{a: "*.com", b: "*.com.", res: false},
		{a: "com", b: "*", res: true},
		{a: "*.com", b: "*.com", res: false},
		{a: "foo.com", b: "*.com", res: true},
		{a: "foo.com.", b: "*.com", res: true},
		{a: "foo.com", b: "*.com.", res: true},
		{a: "foo.com.", b: "*.com.", res: true},
		{a: "*foo.com", b: "*.com", res: true},
		{a: "f*oo.com", b: "*.com", res: true},
		{a: "fo*o.com", b: "*.com", res: true},
		{a: "foo*.com", b: "*.com", res: true},
		{a: "*.foo.com", b: "*.com", res: false},
		{a: "foo*.com", b: "*foo.com", res: false},
		{a: "foo*.com", b: "*oo.com", res: false},
		{a: "foo.com", b: "*oo.com", res: true},
		{a: "*foo.com", b: "*oo.com", res: true},
		{a: "f*oo.com", b: "*oo.com", res: true},
		{a: "fo*o.com", b: "*oo.com", res: false},
		{a: "fo*o.com", b: "*o*o.com", res: true},
		{a: "www.fo*o.com", b: "*o*o.com", res: false},
		{a: "www.fo*o.com", b: "*.*o*o.com", res: true},
		{a: "www.foo.com", b: "www.*o*o.com", res: true},
		{a: "www.foo.com", b: "www.foo*o.com", res: false},
		{a: "www.foo.com", b: "www.fo*oo.com", res: false},
		{a: "www.foo.com", b: "www.f*oo.com", res: true},
		{a: "www.fzoo.com", b: "www.f*oo.com", res: true},
		{a: "www.f*oo.com", b: "www.f*oo.com", res: false},
		{a: "*.gogole.com", b: "*.*go*g*l*.c*m", res: true},
	} {
		res := IsMoreSpecific(t.a, t.b)
		c.Assert(res, Equals, t.res, Commentf("matchPattern: IsMoreSpecific fail: %v", t))
	}
}
