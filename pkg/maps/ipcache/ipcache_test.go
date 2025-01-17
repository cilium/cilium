// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"testing"
)

func TestRemoteEndpointInfoFlagsStringReturnsCorrectValue(t *testing.T) {
	type stringTest struct {
		name string
		in   RemoteEndpointInfoFlags
		out  string
	}

	tests := []stringTest{
		{
			name: "no flags",
			in:   0,
			out:  "<none>",
		},
		{
			name: "FlagSkipTunnel",
			in:   FlagSkipTunnel,
			out:  "skiptunnel,",
		},
		{
			name: "Multiple flags",
			in:   FlagSkipTunnel | FlagIPv6TunnelEndpoint,
			out:  "skiptunnel,ipv6tunnel,",
		},
	}

	for _, test := range tests {
		if s := test.in.String(); s != test.out {
			t.Errorf(
				"Expected '%s' for string representation of %s, instead got '%s'",
				test.out, test.name, s,
			)
		}
	}
}
