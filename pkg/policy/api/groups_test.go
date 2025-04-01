// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func GetGroupsRule() Groups {
	return Groups{
		AWS: &AWSGroup{
			Labels: map[string]string{
				"test": "a",
			},
			SecurityGroupsIds: []string{
				"a", "b", "c",
			},
			SecurityGroupsNames: []string{
				"a", "b", "c",
			},
		},
	}
}
func GetCallBackWithRule(ips ...string) GroupProviderFunc {
	netIPs := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if addr, err := netip.ParseAddr(ip); err == nil {
			netIPs = append(netIPs, addr)
		}
	}

	return func(ctx context.Context, group *Groups) ([]netip.Addr, error) {
		return netIPs, nil
	}
}

func TestGetCIDRSetWithValidValue(t *testing.T) {
	cb := GetCallBackWithRule("192.168.1.1")
	RegisterToGroupsProvider(AWSProvider, cb)

	expectedCidrRule := []CIDRRule{
		{Cidr: "192.168.1.1/32", ExceptCIDRs: []CIDR{}, Generated: true}}
	group := GetGroupsRule()
	cidr, err := group.GetCidrSet(context.TODO())
	require.Equal(t, expectedCidrRule, cidr)
	require.NoError(t, err)
}

func TestGetCIDRSetWithMultipleSorted(t *testing.T) {
	cb := GetCallBackWithRule("192.168.1.1", "192.168.10.10", "192.168.10.3")
	RegisterToGroupsProvider(AWSProvider, cb)
	expectedCidrRule := []CIDRRule{
		{Cidr: "192.168.1.1/32", ExceptCIDRs: []CIDR{}, Generated: true},
		{Cidr: "192.168.10.3/32", ExceptCIDRs: []CIDR{}, Generated: true},
		{Cidr: "192.168.10.10/32", ExceptCIDRs: []CIDR{}, Generated: true}}
	group := GetGroupsRule()
	cidr, err := group.GetCidrSet(context.TODO())
	require.Equal(t, expectedCidrRule, cidr)
	require.NoError(t, err)
}

func TestGetCIDRSetWithUniqueCIDRRule(t *testing.T) {
	cb := GetCallBackWithRule("192.168.1.1", "192.168.10.10", "192.168.1.1")
	RegisterToGroupsProvider(AWSProvider, cb)

	cidrRule := []CIDRRule{
		{Cidr: "192.168.1.1/32", ExceptCIDRs: []CIDR{}, Generated: true},
		{Cidr: "192.168.10.10/32", ExceptCIDRs: []CIDR{}, Generated: true}}

	group := GetGroupsRule()
	cidr, err := group.GetCidrSet(context.TODO())
	require.Equal(t, cidrRule, cidr)
	require.NoError(t, err)
}

func TestGetCIDRSetWithError(t *testing.T) {
	setUpSuite(t)

	cb := func(ctx context.Context, group *Groups) ([]netip.Addr, error) {
		return []netip.Addr{}, fmt.Errorf("Invalid credentials")
	}
	RegisterToGroupsProvider(AWSProvider, cb)
	group := GetGroupsRule()
	cidr, err := group.GetCidrSet(context.TODO())
	require.Nil(t, cidr)
	require.Error(t, err)
}

func TestWithoutProviderRegister(t *testing.T) {
	setUpSuite(t)

	providers.Delete(AWSProvider)
	group := GetGroupsRule()
	cidr, err := group.GetCidrSet(context.TODO())
	require.Nil(t, cidr)
	require.Error(t, err)
}

func BenchmarkGetCIDRSet(b *testing.B) {
	cb := GetCallBackWithRule("192.168.1.1", "192.168.10.10", "192.168.10.3")
	RegisterToGroupsProvider(AWSProvider, cb)
	group := GetGroupsRule()
	b.ReportAllocs()

	for b.Loop() {
		_, err := group.GetCidrSet(context.TODO())
		if err != nil {
			b.Fatal(err)
		}
	}
}
