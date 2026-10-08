// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	azureTypes "github.com/cilium/cilium/pkg/azure/types"
	iputil "github.com/cilium/cilium/pkg/ip"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

func TestDeriveSubnetCIDR(t *testing.T) {
	node := &ciliumv2.CiliumNode{}
	require.False(t, deriveSubnetCIDR(node).IsValid())

	node.Status.Azure.Interfaces = []azureTypes.AzureInterface{
		{},
		{
			Subnet: azureTypes.AzureSubnet{
				CIDR: iputil.PrefixFrom(netip.MustParsePrefix("2001:db8::/64")),
			},
		},
		{
			Subnet: azureTypes.AzureSubnet{
				CIDR: iputil.PrefixFrom(netip.MustParsePrefix("10.10.1.4/24")),
			},
		},
		{
			Subnet: azureTypes.AzureSubnet{
				CIDR: iputil.PrefixFrom(netip.MustParsePrefix("10.20.0.0/16")),
			},
		},
	}
	require.Equal(t, netip.MustParsePrefix("10.10.1.0/24"), deriveSubnetCIDR(node))
}

func TestProviderWaitReady(t *testing.T) {
	wantErr := errors.New("native routing CIDR validation failed")
	for _, tt := range []struct {
		name string
		err  error
	}{
		{name: "ready"},
		{name: "validation error", err: wantErr},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ready := make(chan error, 1)
			ready <- tt.err
			p := provider{nativeRoutingCIDRReady: ready}

			err := p.WaitReady(t.Context())
			if tt.err != nil {
				require.ErrorIs(t, err, tt.err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestAutoDetectNativeRoutingCIDR(t *testing.T) {
	subnetCIDR := netip.MustParsePrefix("10.10.0.0/16")

	for _, tt := range []struct {
		name       string
		nativeCIDR netip.Prefix
		wantError  bool
	}{
		{
			name:       "configured subnet",
			nativeCIDR: netip.MustParsePrefix("10.10.64.0/19"),
		},
		{
			name:       "configured supernet",
			nativeCIDR: netip.MustParsePrefix("10.0.0.0/8"),
		},
		{
			name:       "disjoint configuration",
			nativeCIDR: netip.MustParsePrefix("192.168.0.0/16"),
			wantError:  true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{})
			conf := &option.DaemonConfig{IPv4NativeRoutingCIDR: tt.nativeCIDR}
			err := autoDetectNativeRoutingCIDR(hivetest.Logger(t), subnetCIDR, localNodeStore, conf)
			if tt.wantError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			localNode, err := localNodeStore.Get(t.Context())
			require.NoError(t, err)
			require.False(t, localNode.Local.IPv4NativeRoutingCIDR.IsValid())
		})
	}

	t.Run("autodetected subnet", func(t *testing.T) {
		localNodeStore := node.NewTestLocalNodeStore(node.LocalNode{})
		require.NoError(t, autoDetectNativeRoutingCIDR(
			hivetest.Logger(t),
			subnetCIDR,
			localNodeStore,
			&option.DaemonConfig{},
		))

		localNode, err := localNodeStore.Get(t.Context())
		require.NoError(t, err)
		require.Equal(t, subnetCIDR, localNode.Local.IPv4NativeRoutingCIDR)
	})
}
