// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mtu

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewConfiguration(t *testing.T) {
	// Add routes with no encryption or tunnel
	conf := NewConfiguration(0, false, false, false, false)
	require.NotEqual(t, 0, conf.getDeviceMTU(0))
	require.Equal(t, conf.getDeviceMTU(0), conf.getRouteMTU(0))

	// Add routes with no encryption or tunnel and set MTU
	conf = NewConfiguration(0, false, false, false, false)
	require.Equal(t, 1400, conf.getDeviceMTU(1400))
	require.Equal(t, conf.getDeviceMTU(1400), conf.getRouteMTU(1400))

	// Add routes with tunnel
	conf = NewConfiguration(0, false, true, false, false)
	require.Equal(t, 1400, conf.getDeviceMTU(1400))
	require.Equal(t, conf.getDeviceMTU(1400)-TunnelOverheadIPv4, conf.getRouteMTU(1400))

	// Add routes with tunnel over IPv6
	conf = NewConfiguration(0, false, true, false, true)
	require.Equal(t, 1400, conf.getDeviceMTU(1400))
	require.Equal(t, conf.getDeviceMTU(1400)-TunnelOverheadIPv6, conf.getRouteMTU(1400))

	// Add routes with tunnel and set MTU
	conf = NewConfiguration(0, false, true, false, false)
	require.Equal(t, 1400, conf.getDeviceMTU(1400))
	require.Equal(t, conf.getDeviceMTU(1400)-TunnelOverheadIPv4, conf.getRouteMTU(1400))

	// Add routes with encryption and set MTU using standard 128bit, larger 256bit and smaller 96bit ICVlen keys
	conf = NewConfiguration(16, true, false, false, false)
	require.Equal(t, 1400, conf.getDeviceMTU(1400))
	require.Equal(t, conf.getDeviceMTU(1400)-EncryptionIPsecOverhead, conf.getRouteMTU(1400))

	conf = NewConfiguration(32, true, false, false, false)
	require.Equal(t, 1400, conf.getDeviceMTU(1400))
	require.Equal(t, conf.getDeviceMTU(1400)-(EncryptionIPsecOverhead+16), conf.getRouteMTU(1400))

	conf = NewConfiguration(12, true, false, false, false)
	require.Equal(t, 1400, conf.getDeviceMTU(1400))
	require.Equal(t, conf.getDeviceMTU(1400)-(EncryptionIPsecOverhead-4), conf.getRouteMTU(1400))

	// Add routes with encryption and tunnels using standard 128bit, larger 256bit and smaller 96bit ICVlen keys
	conf = NewConfiguration(16, true, true, false, false)
	require.Equal(t, 1400, conf.getDeviceMTU(1400))
	require.Equal(t, conf.getDeviceMTU(1400)-(TunnelOverheadIPv4+EncryptionIPsecOverhead), conf.getRouteMTU(1400))

	conf = NewConfiguration(32, true, true, false, false)
	require.Equal(t, 1400, conf.getDeviceMTU(1400))
	require.Equal(t, conf.getDeviceMTU(1400)-(TunnelOverheadIPv4+EncryptionIPsecOverhead+16), conf.getRouteMTU(1400))

	conf = NewConfiguration(32, true, true, false, false)
	require.Equal(t, 1400, conf.getDeviceMTU(1400))
	require.Equal(t, conf.getDeviceMTU(1400)-(TunnelOverheadIPv4+EncryptionIPsecOverhead+16), conf.getRouteMTU(1400))

	// Add routes with WireGuard enabled
	conf = NewConfiguration(32, false, false, true, false)
	require.Equal(t, 1400, conf.getDeviceMTU(1400))
	require.Equal(t, conf.getDeviceMTU(1400)-WireguardOverhead, conf.getRouteMTU(1400))

	conf = NewConfiguration(32, false, true, true, false)
	require.Equal(t, 1400, conf.getDeviceMTU(1400))
	require.Equal(t, conf.getDeviceMTU(1400)-(WireguardOverhead+TunnelOverheadIPv4), conf.getRouteMTU(1400))
}
