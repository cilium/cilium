// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dns

import "testing"

func TestIsFQDN(t *testing.T) {
	for _, tt := range []struct {
		s      string
		expect bool
	}{
		{".", true},
		{"\\.", false},
		{"\\\\.", true},
		{"\\\\\\.", false},
		{"\\\\\\\\.", true},
		{"a.", true},
		{"a\\.", false},
		{"a\\\\.", true},
		{"a\\\\\\.", false},
		{"ab.", true},
		{"ab\\.", false},
		{"ab\\\\.", true},
		{"ab\\\\\\.", false},
		{"..", true},
		{".\\.", false},
		{".\\\\.", true},
		{".\\\\\\.", false},
		{"example.org.", true},
		{"example.org\\.", false},
		{"example.org\\\\.", true},
		{"example.org\\\\\\.", false},
		{"example\\.org.", true},
		{"example\\\\.org.", true},
		{"example\\\\\\.org.", true},
		{"\\example.org.", true},
		{"\\\\example.org.", true},
		{"\\\\\\example.org.", true},
	} {
		if got := isFQDN(tt.s); got != tt.expect {
			t.Errorf("isFQDN(%q) = %t, expected %t", tt.s, got, tt.expect)
		}
	}
}

func TestFQDN(t *testing.T) {
	for _, tt := range []struct {
		s      string
		expect string
	}{
		{".", "."},
		{"\\.", "\\.."},
		{"example.org", "example.org."},
		{"example.org.", "example.org."},
		{"example.org\\.", "example.org\\.."},
		{"example.org\\\\.", "example.org\\\\."},
		{"EXAMPLE.ORG", "example.org."},
		{"eXAMPLE.org.", "example.org."},
	} {
		if got := FQDN(tt.s); got != tt.expect {
			t.Errorf("isFQDN(%q) = %q, expected %q", tt.s, got, tt.expect)
		}
	}
}
