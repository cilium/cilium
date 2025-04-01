// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestFQDNSelectorSanitize tests that the sanitizer correctly catches bad
// cases, and allows good ones.
func TestFQDNSelectorSanitize(t *testing.T) {
	setUpSuite(t)

	for _, accept := range []FQDNSelector{
		{MatchName: "cilium.io."},
		{MatchName: "get-cilium.io."},
		{MatchName: "foo.cilium.io."},
		{MatchName: "cilium.io"},
		{MatchName: "_cilium.io"},
		{MatchPattern: "*.cilium.io"},
		{MatchPattern: "*._cilium.io"},
		{MatchPattern: "*cilium.io"},
		{MatchPattern: "cilium.io"},
	} {
		err := accept.sanitize()
		require.NoError(t, err, "FQDNSelector %+v was rejected but it should be valid", accept)
	}

	for _, reject := range []FQDNSelector{
		{MatchName: "a{1,2}.cilium.io."},
		{MatchPattern: "[a-z]*.cilium.io."},
		{MatchName: "cilium.io", MatchPattern: "*cilium.io"},
	} {
		err := reject.sanitize()
		require.Error(t, err, "FQDNSelector %+v was accepted but it should be invalid", reject)
	}
}

// TestPortRuleDNSSanitize tests that the sanitizer correctly catches bad
// cases, and allows good ones.
func TestPortRuleDNSSanitize(t *testing.T) {
	setUpSuite(t)

	for _, accept := range []PortRuleDNS{
		{MatchName: "cilium.io."},
		{MatchName: "get-cilium.io."},
		{MatchName: "foo.cilium.io."},
		{MatchName: "cilium.io"},
		{MatchName: "_cilium.io"},
		{MatchPattern: "*.cilium.io"},
		{MatchPattern: "*._cilium.io"},
		{MatchPattern: "*cilium.io"},
		{MatchPattern: "cilium.io"},
	} {
		err := accept.Sanitize()
		require.NoError(t, err, "PortRuleDNS %+v was rejected but it should be valid", accept)
	}

	for _, reject := range []PortRuleDNS{
		{MatchName: "a{1,2}.cilium.io."},
		{MatchPattern: "[a-z]*.cilium.io."},
		{MatchName: "a{1,2}.cilium.io.", MatchPattern: "[a-z]*.cilium.io."},
	} {
		err := reject.Sanitize()
		require.Error(t, err, "PortRuleDNS %+v was accepted but it should be invalid", reject)
	}
}

// TestPortRuleDNSSanitize tests that the sanitizer correctly catches bad
// cases, and allows good ones.
func BenchmarkFQDNSelectorString(b *testing.B) {
	b.ReportAllocs()

	for b.Loop() {
		for _, s := range []FQDNSelector{
			{MatchName: "cilium.io"},
			{MatchPattern: "[a-z]*.cilium.io"},
			{MatchName: "a{1,2}.cilium.io", MatchPattern: "[a-z]*.cilium.io"},
			{MatchPattern: "*.cilium.io"},
		} {
			_ = s.String()
		}
	}
}
