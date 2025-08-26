// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package matchpattern

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestMatchPatternREConversion tests that we can validate and convert a
// matchPattern to a compilable regexp.
// It tests:
// cilium.io. -> cilium[.]io[.]
// *.cilium.io. -> [-a-zA-Z0-9]+.cilium[.]io[.]
// *cilium.io. -> "([a-zA-Z0-9]+[.])?cilium[.]io[.]
func TestAnchoredMatchPatternREConversion(t *testing.T) {
	for source, target := range map[string]string{
		"cilium.io.":   "^cilium[.]io[.]$",
		"*.cilium.io.": "^" + allowedDNSCharsREGroup + "*[.]cilium[.]io[.]$",
		"*":            "(^(" + allowedDNSCharsREGroup + "+[.])+$)|(^[.]$)",
		".":            "^[.]$",
	} {
		reStr := ToAnchoredRegexp(source)
		_, err := regexp.Compile(reStr)
		require.NoErrorf(t, err, "Regexp generated from pattern %q is not valid", source)
		require.Equal(t, target, reStr, "Regexp generated from pattern %q isn't expected", source)
	}
}

func TestUnAnchoredMatchPatternREConversion(t *testing.T) {
	for source, target := range map[string]string{
		"cilium.io.":   "cilium[.]io[.]",
		"*.cilium.io.": allowedDNSCharsREGroup + "*[.]cilium[.]io[.]",
		"*":            MatchAllUnAnchoredPattern,
		".":            "[.]",
	} {
		reStr := ToUnAnchoredRegexp(source)
		_, err := regexp.Compile(reStr)
		require.NoErrorf(t, err, "Regexp generated from pattern %q is not valid", source)
		require.Equal(t, target, reStr, "Regexp generated from pattern %q isn't expected", source)
	}
}

// TestMatchPatternMatching tests that patterns actually match what we expect:
// cilium.io. matches only cilium.io.
// *.cilium.io. matches anysub.cilium.io. but not cilium.io.
// *cilium.io. matches  anysub.cilium.io. and cilium.io.
// *.ci*.io. matches anysub.cilium.io. anysub.ci.io., anysub.ciliumandmore.io. but not cilium.io.
func TestAnchoredMatchPatternMatching(t *testing.T) {
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
		reStr := ToAnchoredRegexp(testCase.pattern)
		re, err := regexp.Compile(reStr)
		require.NoError(t, err, "Regexp generated from pattern is not valid")
		for _, accept := range testCase.accept {
			require.True(t, re.MatchString(accept), "Regexp generated from pattern %s/%s rejected a correct DNS name %s", testCase.pattern, re, accept)
		}
		for _, reject := range testCase.reject {
			require.False(t, re.MatchString(reject), "Regexp generated from pattern %s/%s accepted a bad DNS name %s", testCase.pattern, re, reject)
		}
	}
}

// TestMatchPatternSanitize tests that Sanitize handles any special cases
func TestMatchPatternSanitize(t *testing.T) {
	for source, target := range map[string]string{
		"*":     "*",
		"*.":    "*.",
		"*.com": "*.com.",
	} {
		sanitized := Sanitize(source)
		require.Equal(t, target, sanitized, "matchPattern: %s not sanitized correctly", source)
	}
}
