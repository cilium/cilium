// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

const CIDRRegex = `^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([0-9]|[1-2][0-9]|3[0-2])$|^s*((([0-9A-Fa-f]{1,4}:){7}(:|([0-9A-Fa-f]{1,4})))|(([0-9A-Fa-f]{1,4}:){6}:([0-9A-Fa-f]{1,4})?)|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){0,1}):([0-9A-Fa-f]{1,4})?))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){0,2}):([0-9A-Fa-f]{1,4})?))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){0,3}):([0-9A-Fa-f]{1,4})?))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){0,4}):([0-9A-Fa-f]{1,4})?))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){0,5}):([0-9A-Fa-f]{1,4})?))|(:(:|((:[0-9A-Fa-f]{1,4}){1,7}))))(%.+)?s*/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8])$`

func TestCIDRRegex(t *testing.T) {
	reg := regexp.MustCompile(CIDRRegex)

	goodCIDRs := []string{
		"192.0.2.3/32",
		"192.0.2.0/24",
		"0.0.0.0/0",
		"::/0",
		"::cafe/128",
		"::f00d:cafe/128",
		"0:0:0:0:0:0:0:cafe/128",
		"cafe:cafe:cafe:cafe:cafe:cafe:cafe:cafe/128",
		"bad:f00d:cafe:0:0:0:0:add/64",
		"bad:f00d:cafe::bad/64",
		"f00d::/64",
		"f00d::0:0/120",
		"f00d:cafe::1:2/120",
	}

continueTest:
	for _, input := range goodCIDRs {
		if matched := reg.MatchString(input); matched {
			continue continueTest
		}
		// The below is always false, valid CIDR prefixes should
		// always skip this by continuing in the above loop.
		require.Equal(t, "failed to match CIDR.OneOf[*].Pattern", input)
	}

	badCIDRs := []string{
		"192.0.2.3",
		"192.0.2.3/",
		"abcdef",
		"0.0.0.0/0/0",
		"::",
		":",
		":/",
		"0:0",
		"::cafe/128/12",
		"abc:def",
		"abc:def/64",
		"f00d::/",
		"f00d::0:0",
		"bad.f00d.cafe.0.0.0.0.add/20",
		"::192.0.2.3/128",
		"::ffff:192.0.2.3/128",
		"abcd:192.0.2.3/128",
		":abcd:192.0.2.3/128",
		"abcd::192.0.2.3/128",
		":abcd::192.0.2.3/128",
		"bad::f00d::cafe/1",
		":bad::f00d::cafe/1",
		"::bad::f00d::cafe/1",
		"::bad::food::cafe/1",
	}

	for _, input := range badCIDRs {
		if matched := reg.MatchString(input); matched {
			// The below is always false, invalid CIDR
			// prefixes are not supposed to match the regex.
			require.Equal(t, "unexpectedly matched CIDR.OneOf[*].Pattern", input)
		}
	}
}
