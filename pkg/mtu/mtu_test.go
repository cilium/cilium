// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mtu

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewConfiguration(t *testing.T) {
	// Add routes with no encryption or tunnel
	conf := NewConfiguration(0, false, false, false, false, 0, nil, false)
	require.NotEqual(t, 0, conf.GetDeviceMTU())
	require.Equal(t, conf.GetDeviceMTU(), conf.GetRouteMTU())

	// Add routes with no encryption or tunnel and set MTU
	conf = NewConfiguration(0, false, false, false, false, 1400, nil, false)
	require.Equal(t, 1400, conf.GetDeviceMTU())
	require.Equal(t, conf.GetDeviceMTU(), conf.GetRouteMTU())

	// Add routes with tunnel
	conf = NewConfiguration(0, false, true, false, false, 1400, nil, false)
	require.Equal(t, 1400, conf.GetDeviceMTU())
	require.Equal(t, conf.GetDeviceMTU()-TunnelOverhead, conf.GetRouteMTU())

	// Add routes with tunnel and hs-ipcache DSR
	conf = NewConfiguration(0, false, true, false, true, 1400, nil, false)
	require.Equal(t, 1400, conf.GetDeviceMTU())
	require.Equal(t, conf.GetDeviceMTU()-TunnelOverhead-DsrTunnelOverhead, conf.GetRouteMTU())

	// Add routes with tunnel and set MTU
	conf = NewConfiguration(0, false, true, false, false, 1400, nil, false)
	require.Equal(t, 1400, conf.GetDeviceMTU())
	require.Equal(t, conf.GetDeviceMTU()-TunnelOverhead, conf.GetRouteMTU())

	// Add routes with encryption and set MTU using standard 128bit, larger 256bit and smaller 96bit ICVlen keys
	conf = NewConfiguration(16, true, false, false, false, 1400, nil, false)
	require.Equal(t, 1400, conf.GetDeviceMTU())
	require.Equal(t, conf.GetDeviceMTU()-EncryptionIPsecOverhead, conf.GetRouteMTU())

	conf = NewConfiguration(32, true, false, false, false, 1400, nil, false)
	require.Equal(t, 1400, conf.GetDeviceMTU())
	require.Equal(t, conf.GetDeviceMTU()-(EncryptionIPsecOverhead+16), conf.GetRouteMTU())

	conf = NewConfiguration(12, true, false, false, false, 1400, nil, false)
	require.Equal(t, 1400, conf.GetDeviceMTU())
	require.Equal(t, conf.GetDeviceMTU()-(EncryptionIPsecOverhead-4), conf.GetRouteMTU())

	// Add routes with encryption and tunnels using standard 128bit, larger 256bit and smaller 96bit ICVlen keys
	conf = NewConfiguration(16, true, true, false, false, 1400, nil, false)
	require.Equal(t, 1400, conf.GetDeviceMTU())
	require.Equal(t, conf.GetDeviceMTU()-(TunnelOverhead+EncryptionIPsecOverhead), conf.GetRouteMTU())

	conf = NewConfiguration(32, true, true, false, false, 1400, nil, false)
	require.Equal(t, 1400, conf.GetDeviceMTU())
	require.Equal(t, conf.GetDeviceMTU()-(TunnelOverhead+EncryptionIPsecOverhead+16), conf.GetRouteMTU())

	conf = NewConfiguration(32, true, true, false, false, 1400, nil, false)
	require.Equal(t, 1400, conf.GetDeviceMTU())
	require.Equal(t, conf.GetDeviceMTU()-(TunnelOverhead+EncryptionIPsecOverhead+16), conf.GetRouteMTU())

	// Add routes with WireGuard enabled
	conf = NewConfiguration(32, false, false, true, false, 1400, nil, false)
	require.Equal(t, 1400, conf.GetDeviceMTU())
	require.Equal(t, conf.GetDeviceMTU()-WireguardOverhead, conf.GetRouteMTU())

	conf = NewConfiguration(32, false, true, true, false, 1400, nil, false)
	require.Equal(t, 1400, conf.GetDeviceMTU())
	require.Equal(t, conf.GetDeviceMTU()-(WireguardOverhead+TunnelOverhead), conf.GetRouteMTU())

	testIP1 := net.IPv4(0, 0, 0, 0)
	testIP2 := net.IPv4(127, 0, 0, 1)
	result, _ := getMTUFromIf(testIP1)
	require.Equal(t, 0, result)

	conf = NewConfiguration(0, true, true, false, false, 1400, testIP1, false)
	require.Equal(t, 1400, conf.GetDeviceMTU())

	conf = NewConfiguration(0, true, true, false, false, 0, testIP1, false)
	require.Equal(t, 1500, conf.GetDeviceMTU())

	// Assuming loopback interface always exists and has mtu=65536
	conf = NewConfiguration(0, true, true, false, false, 0, testIP2, false)
	require.Equal(t, 65536, conf.GetDeviceMTU())
}
