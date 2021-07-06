// Copyright 2021 Authors of Cilium
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
