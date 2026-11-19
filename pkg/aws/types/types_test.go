// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	iputil "github.com/cilium/cilium/pkg/ip"
)

func TestAwsVPCIPv6CIDRs(t *testing.T) {
	vpc := &AwsVPC{
		ID:          "vpc-1",
		PrimaryCIDR: iputil.PrefixFrom(netip.MustParsePrefix("192.168.0.0/16")),
		IPv6CIDRs: []iputil.Prefix{
			iputil.PrefixFrom(netip.MustParsePrefix("2600:1f14:abcd:ef00::/56")),
		},
	}

	cp := vpc.DeepCopy()
	require.True(t, vpc.DeepEqual(cp))

	// The copy does not alias the IPv6 CIDRs of the original.
	cp.IPv6CIDRs[0] = iputil.PrefixFrom(netip.MustParsePrefix("2001:db8::/56"))
	require.Equal(t, iputil.PrefixFrom(netip.MustParsePrefix("2600:1f14:abcd:ef00::/56")), vpc.IPv6CIDRs[0])

	// DeepEqual notices IPv6-only changes.
	require.False(t, vpc.DeepEqual(cp))
	require.False(t, vpc.DeepEqual(&AwsVPC{ID: vpc.ID, PrimaryCIDR: vpc.PrimaryCIDR}))
}
