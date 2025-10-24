// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mtu

import (
	"testing"

	"github.com/stretchr/testify/require"

	fakeTypes "github.com/cilium/cilium/pkg/datapath/fake/types"
)

func TestNewConfiguration(t *testing.T) {
	// Add routes with no encryption or tunnel
	conf := NewConfiguration(&fakeTypes.IPsecAgent{}, false, false, false)
	require.NotEqual(t, 0, conf.getDeviceMTU(0))
	require.Equal(t, conf.getDeviceMTU(0), conf.getRouteMTU(0))

	// Add routes with no encryption or tunnel and set MTU
	conf = NewConfiguration(&fakeTypes.IPsecAgent{}, false, false, false)
	require.Equal(t, 1400, conf.getDeviceMTU(1400))
	require.Equal(t, conf.getDeviceMTU(1400), conf.getRouteMTU(1400))

	// Add routes with tunnel
	conf = NewConfiguration(&fakeTypes.IPsecAgent{}, true, false, false)
	require.Equal(t, 1400, conf.getDeviceMTU(1400))
	require.Equal(t, conf.getDeviceMTU(1400)-TunnelOverheadIPv4, conf.getRouteMTU(1400))

	// Add routes with tunnel over IPv6
	conf = NewConfiguration(&fakeTypes.IPsecAgent{}, true, false, true)
	require.Equal(t, 1400, conf.getDeviceMTU(1400))
	require.Equal(t, conf.getDeviceMTU(1400)-TunnelOverheadIPv6, conf.getRouteMTU(1400))

	// Add routes with tunnel and set MTU
	conf = NewConfiguration(&fakeTypes.IPsecAgent{}, true, false, false)
	require.Equal(t, 1400, conf.getDeviceMTU(1400))
	require.Equal(t, conf.getDeviceMTU(1400)-TunnelOverheadIPv4, conf.getRouteMTU(1400))

	// Add routes with encryption and set MTU using standard 128bit, larger 256bit and smaller 96bit ICVlen keys
	conf = NewConfiguration(&fakeTypes.IPsecAgent{EnableIPsec: true, AuthKeySizeValue: 16}, false, false, false)
	require.Equal(t, 1400, conf.getDeviceMTU(1400))
	require.Equal(t, conf.getDeviceMTU(1400)-EncryptionIPsecOverhead, conf.getRouteMTU(1400))

	conf = NewConfiguration(&fakeTypes.IPsecAgent{EnableIPsec: true, AuthKeySizeValue: 32}, false, false, false)
	require.Equal(t, 1400, conf.getDeviceMTU(1400))
	require.Equal(t, conf.getDeviceMTU(1400)-(EncryptionIPsecOverhead+16), conf.getRouteMTU(1400))

	conf = NewConfiguration(&fakeTypes.IPsecAgent{EnableIPsec: true, AuthKeySizeValue: 12}, false, false, false)
	require.Equal(t, 1400, conf.getDeviceMTU(1400))
	require.Equal(t, conf.getDeviceMTU(1400)-(EncryptionIPsecOverhead-4), conf.getRouteMTU(1400))

	// Add routes with encryption and tunnels using standard 128bit, larger 256bit and smaller 96bit ICVlen keys
	conf = NewConfiguration(&fakeTypes.IPsecAgent{EnableIPsec: true, AuthKeySizeValue: 16}, true, false, false)
	require.Equal(t, 1400, conf.getDeviceMTU(1400))
	require.Equal(t, conf.getDeviceMTU(1400)-(TunnelOverheadIPv4+EncryptionIPsecOverhead), conf.getRouteMTU(1400))

	conf = NewConfiguration(&fakeTypes.IPsecAgent{EnableIPsec: true, AuthKeySizeValue: 32}, true, false, false)
	require.Equal(t, 1400, conf.getDeviceMTU(1400))
	require.Equal(t, conf.getDeviceMTU(1400)-(TunnelOverheadIPv4+EncryptionIPsecOverhead+16), conf.getRouteMTU(1400))

	conf = NewConfiguration(&fakeTypes.IPsecAgent{EnableIPsec: true, AuthKeySizeValue: 32}, true, false, false)
	require.Equal(t, 1400, conf.getDeviceMTU(1400))
	require.Equal(t, conf.getDeviceMTU(1400)-(TunnelOverheadIPv4+EncryptionIPsecOverhead+16), conf.getRouteMTU(1400))

	// Add routes with WireGuard enabled
	conf = NewConfiguration(&fakeTypes.IPsecAgent{EnableIPsec: false, AuthKeySizeValue: 32}, false, true, false)
	require.Equal(t, 1400, conf.getDeviceMTU(1400))
	require.Equal(t, conf.getDeviceMTU(1400)-WireguardOverhead, conf.getRouteMTU(1400))

	conf = NewConfiguration(&fakeTypes.IPsecAgent{EnableIPsec: false, AuthKeySizeValue: 32}, true, true, false)
	require.Equal(t, 1400, conf.getDeviceMTU(1400))
	require.Equal(t, conf.getDeviceMTU(1400)-(WireguardOverhead+TunnelOverheadIPv4), conf.getRouteMTU(1400))
}
