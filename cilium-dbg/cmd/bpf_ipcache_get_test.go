// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetLPMValue(t *testing.T) {
	entries := map[string][]string{
		"10.0.0.0/8":     {"2"},
		"10.0.0.0/16":    {"9"},
		"10.0.0.0/32":    {"8"},
		"10.128.0.0/9":   {"4", "20"},
		"feed::ed/112":   {"3"},
		"feed::feed/128": {"5", "17"},
	}

	tests := []struct {
		ip          string   // Input ip address.
		hasIdentity bool     // true if a match should be found.
		identity    []string // Expected identity if match should be found.
	}{
		{"10.1.0.0", true, entries["10.0.0.0/8"]},
		{"10.1.0.255", true, entries["10.0.0.0/8"]},
		{"10.0.1.0", true, entries["10.0.0.0/16"]},
		{"10.0.0.0", true, entries["10.0.0.0/32"]},
		{"10.127.255.255", true, entries["10.0.0.0/8"]},
		{"10.128.255.255", true, entries["10.128.0.0/9"]},
		{"10.255.255.255", true, entries["10.128.0.0/9"]},
		{ip: "12.0.0.1", hasIdentity: false},
		{"feed::ffed", true, entries["feed::ed/112"]},
		{"feed::feed", true, entries["feed::feed/128"]},
		{ip: "feed::10.0.0.1", hasIdentity: false},
	}

	for _, tt := range tests {
		v, exists := getLPMValue(netip.MustParseAddr(tt.ip).Unmap(), entries)
		require.Equal(t, exists, tt.hasIdentity, "No identity was found for ip '%s': wanted '%s'", tt.ip, tt.identity)

		if exists {
			identity := v.([]string)
			require.Equal(t, identity, tt.identity, "Wrong number of identities was retrieved for ip %s", tt.ip)
		}
	}
}
