// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/api/v1/models"
	iputil "github.com/cilium/cilium/pkg/ip"
)

func TestSortIPListEntries(t *testing.T) {
	var entries []*models.IPListEntry
	for _, s := range []string{"f00d::/64", "11.0.0.0/8", "10.0.0.1/32", "10.0.0.0/8"} {
		entries = append(entries, &models.IPListEntry{
			Cidr: iputil.PrefixFrom(netip.MustParsePrefix(s)),
		})
	}

	sortIPListEntries(entries)

	var got []string
	for _, e := range entries {
		got = append(got, e.Cidr.String())
	}
	require.Equal(t, []string{"10.0.0.0/8", "10.0.0.1/32", "11.0.0.0/8", "f00d::/64"}, got)
}
