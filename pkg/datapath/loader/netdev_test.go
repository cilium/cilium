// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/datapath/tables"
)

func TestBPFMasqAddrs(t *testing.T) {
	masq4, masq6 := bpfMasqAddrs("test", &localNodeConfig, true, true)
	require.False(t, masq4.IsValid())
	require.False(t, masq6.IsValid())

	newConfig := localNodeConfig
	newConfig.NodeAddresses = []tables.NodeAddress{
		{
			Addr:       netip.MustParseAddr("1.0.0.1"),
			NodePort:   true,
			Primary:    true,
			DeviceName: "test",
		},
		{
			Addr:       netip.MustParseAddr("1000::1"),
			NodePort:   true,
			Primary:    true,
			DeviceName: "test",
		},
		{
			Addr:       netip.MustParseAddr("2.0.0.2"),
			NodePort:   false,
			Primary:    true,
			DeviceName: tables.WildcardDeviceName,
		},
		{
			Addr:       netip.MustParseAddr("2000::2"),
			NodePort:   false,
			Primary:    true,
			DeviceName: tables.WildcardDeviceName,
		},
	}

	masq4, masq6 = bpfMasqAddrs("test", &newConfig, true, true)
	require.Equal(t, "1.0.0.1", masq4.String())
	require.Equal(t, "1000::1", masq6.String())

	masq4, masq6 = bpfMasqAddrs("unknown", &newConfig, true, true)
	require.Equal(t, "2.0.0.2", masq4.String())
	require.Equal(t, "2000::2", masq6.String())

	masq4, masq6 = bpfMasqAddrs("test", &newConfig, false, false)
	require.False(t, masq4.IsValid())
	require.False(t, masq6.IsValid())
}
