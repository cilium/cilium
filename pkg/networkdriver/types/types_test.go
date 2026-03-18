// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDriverType(t *testing.T) {
	t.Run("test (un)marshaling", func(t *testing.T) {
		for i := range DeviceManagerTypeUnknown {
			// make sure we handle all supported types
			str, err := i.MarshalText()
			require.NoError(t, err)
			require.NotNil(t, str)

			var unmarshaled DeviceManagerType
			require.NoError(t, unmarshaled.UnmarshalText(str))
			require.Equal(t, i, unmarshaled)

			require.NotEmpty(t, i.String())
		}

		dontExist := DeviceManagerTypeUnknown + 1
		str, err := dontExist.MarshalText()
		require.Error(t, err)
		require.Nil(t, str)

		jsonText := `\"idontexist\"`
		require.Error(t, dontExist.UnmarshalText([]byte(jsonText)))
		require.NotZero(t, dontExist)

		require.Empty(t, dontExist.String())
	})
}

func TestAddrSetJSON(t *testing.T) {
	t.Run("marshal empty AddrSet", func(t *testing.T) {
		var addrSet AddrSet
		data, err := json.Marshal(addrSet)
		require.NoError(t, err)
		require.Equal(t, "null", string(data))
	})

	t.Run("marshal AddrSet with addresses", func(t *testing.T) {
		addrSet := AddrSet{
			netip.MustParseAddr("192.168.1.1"): {},
			netip.MustParseAddr("192.168.1.2"): {},
		}
		data, err := json.Marshal(addrSet)
		require.NoError(t, err)

		// Unmarshal to verify content (order may vary due to map iteration)
		var addrs []string
		err = json.Unmarshal(data, &addrs)
		require.NoError(t, err)
		require.Len(t, addrs, 2)
		require.Contains(t, addrs, "192.168.1.1")
		require.Contains(t, addrs, "192.168.1.2")
	})

	t.Run("marshal AddrSet with IPv6 addresses", func(t *testing.T) {
		addrSet := AddrSet{
			netip.MustParseAddr("fc01::1"): {},
			netip.MustParseAddr("fc02::2"): {},
		}
		data, err := json.Marshal(addrSet)
		require.NoError(t, err)

		var addrs []string
		err = json.Unmarshal(data, &addrs)
		require.NoError(t, err)
		require.Len(t, addrs, 2)
		require.Contains(t, addrs, "fc01::1")
		require.Contains(t, addrs, "fc02::2")
	})

	t.Run("unmarshal null AddrSet", func(t *testing.T) {
		var addrSet AddrSet
		err := json.Unmarshal([]byte("null"), &addrSet)
		require.NoError(t, err)
		require.Nil(t, addrSet)
	})

	t.Run("unmarshal AddrSet from JSON", func(t *testing.T) {
		jsonData := `["192.168.1.1", "192.168.1.2"]`
		var addrSet AddrSet
		err := json.Unmarshal([]byte(jsonData), &addrSet)
		require.NoError(t, err)
		require.Len(t, addrSet, 2)
		_, ok := addrSet[netip.MustParseAddr("192.168.1.1")]
		require.True(t, ok)
		_, ok = addrSet[netip.MustParseAddr("192.168.1.2")]
		require.True(t, ok)
	})

	t.Run("unmarshal invalid address", func(t *testing.T) {
		jsonData := `["invalid-address"]`
		var addrSet AddrSet
		err := json.Unmarshal([]byte(jsonData), &addrSet)
		require.Error(t, err)
	})
}

func TestRouteSetJSON(t *testing.T) {
	t.Run("marshal empty RouteSet", func(t *testing.T) {
		var routeSet RouteSet
		data, err := json.Marshal(routeSet)
		require.NoError(t, err)
		require.Equal(t, "null", string(data))
	})

	t.Run("marshal RouteSet with routes", func(t *testing.T) {
		routeSet := RouteSet{
			netip.MustParsePrefix("1.2.3.4/32"): {
				netip.MustParseAddr("192.168.1.1"): {},
				netip.MustParseAddr("192.168.1.2"): {},
			},
			netip.MustParsePrefix("10.0.0.0/8"): {
				netip.MustParseAddr("172.16.0.1"): {},
			},
		}
		data, err := json.Marshal(routeSet)
		require.NoError(t, err)

		// Unmarshal to verify structure
		var m map[string][]string
		err = json.Unmarshal(data, &m)
		require.NoError(t, err)
		require.Len(t, m, 2)
		require.Contains(t, m, "1.2.3.4/32")
		require.Contains(t, m, "10.0.0.0/8")
		require.Len(t, m["1.2.3.4/32"], 2)
		require.Len(t, m["10.0.0.0/8"], 1)
	})

	t.Run("marshal RouteSet with IPv6 routes", func(t *testing.T) {
		routeSet := RouteSet{
			netip.MustParsePrefix("fc00::/64"): {
				netip.MustParseAddr("fc01::1"): {},
				netip.MustParseAddr("fc02::2"): {},
			},
		}
		data, err := json.Marshal(routeSet)
		require.NoError(t, err)

		var m map[string][]string
		err = json.Unmarshal(data, &m)
		require.NoError(t, err)
		require.Len(t, m, 1)
		require.Contains(t, m, "fc00::/64")
		require.Len(t, m["fc00::/64"], 2)
	})

	t.Run("unmarshal null RouteSet", func(t *testing.T) {
		var routeSet RouteSet
		err := json.Unmarshal([]byte("null"), &routeSet)
		require.NoError(t, err)
		require.Nil(t, routeSet)
	})

	t.Run("unmarshal RouteSet from JSON", func(t *testing.T) {
		jsonData := `{
			"1.2.3.4/32": ["192.168.1.1", "192.168.1.2"],
			"fc00::/64": ["fc01::1", "fc02::2"]
		}`
		var routeSet RouteSet
		err := json.Unmarshal([]byte(jsonData), &routeSet)
		require.NoError(t, err)
		require.Len(t, routeSet, 2)

		// Check IPv4 route
		prefix4 := netip.MustParsePrefix("1.2.3.4/32")
		addrSet4, ok := routeSet[prefix4]
		require.True(t, ok)
		require.Len(t, addrSet4, 2)
		_, ok = addrSet4[netip.MustParseAddr("192.168.1.1")]
		require.True(t, ok)
		_, ok = addrSet4[netip.MustParseAddr("192.168.1.2")]
		require.True(t, ok)

		// Check IPv6 route
		prefix6 := netip.MustParsePrefix("fc00::/64")
		addrSet6, ok := routeSet[prefix6]
		require.True(t, ok)
		require.Len(t, addrSet6, 2)
		_, ok = addrSet6[netip.MustParseAddr("fc01::1")]
		require.True(t, ok)
		_, ok = addrSet6[netip.MustParseAddr("fc02::2")]
		require.True(t, ok)
	})

	t.Run("unmarshal invalid prefix", func(t *testing.T) {
		jsonData := `{"invalid-prefix": ["192.168.1.1"]}`
		var routeSet RouteSet
		err := json.Unmarshal([]byte(jsonData), &routeSet)
		require.Error(t, err)
	})

	t.Run("unmarshal invalid gateway address", func(t *testing.T) {
		jsonData := `{"1.2.3.4/32": ["invalid-address"]}`
		var routeSet RouteSet
		err := json.Unmarshal([]byte(jsonData), &routeSet)
		require.Error(t, err)
	})
}

func TestDeviceConfigJSON(t *testing.T) {
	t.Run("marshal and unmarshal complete DeviceConfig", func(t *testing.T) {
		config := DeviceConfig{
			IPv4Addr: netip.MustParsePrefix("10.0.0.1/24"),
			IPv6Addr: netip.MustParsePrefix("fc00::1/64"),
			IPPool:   "test-pool",
			Routes: RouteSet{
				netip.MustParsePrefix("1.2.3.4/32"): {
					netip.MustParseAddr("192.168.1.1"): {},
					netip.MustParseAddr("192.168.1.2"): {},
				},
				netip.MustParsePrefix("fc00::/64"): {
					netip.MustParseAddr("fc01::1"): {},
				},
			},
			Vlan: 100,
		}

		// Marshal to JSON
		data, err := json.Marshal(config)
		require.NoError(t, err)

		// Unmarshal back
		var decoded DeviceConfig
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		// Verify fields
		require.Equal(t, config.IPv4Addr, decoded.IPv4Addr)
		require.Equal(t, config.IPv6Addr, decoded.IPv6Addr)
		require.Equal(t, config.IPPool, decoded.IPPool)
		require.Equal(t, config.Vlan, decoded.Vlan)
		require.Len(t, decoded.Routes, 2)
	})

	t.Run("unmarshal example JSON format", func(t *testing.T) {
		jsonData := `{
			"ip-pool": "xyz",
			"ipv4Addr": "10.0.0.1/24",
			"ipv6Addr": "fc00::1/64",
			"routes": {
				"1.2.3.4/32": ["192.168.1.1", "192.168.1.2"],
				"fc00::/64": ["fc01::1", "fc02::2"]
			}
		}`

		var config DeviceConfig
		err := json.Unmarshal([]byte(jsonData), &config)
		require.NoError(t, err)

		require.Equal(t, "xyz", config.IPPool)
		require.Equal(t, netip.MustParsePrefix("10.0.0.1/24"), config.IPv4Addr)
		require.Equal(t, netip.MustParsePrefix("fc00::1/64"), config.IPv6Addr)
		require.Len(t, config.Routes, 2)

		// Verify route structure
		prefix4 := netip.MustParsePrefix("1.2.3.4/32")
		gateways4 := config.Routes[prefix4]
		require.Len(t, gateways4, 2)

		prefix6 := netip.MustParsePrefix("fc00::/64")
		gateways6 := config.Routes[prefix6]
		require.Len(t, gateways6, 2)
	})

	t.Run("roundtrip with empty routes", func(t *testing.T) {
		config := DeviceConfig{
			IPv4Addr: netip.MustParsePrefix("10.0.0.1/24"),
			IPPool:   "test-pool",
			Routes:   nil,
		}

		data, err := json.Marshal(config)
		require.NoError(t, err)

		var decoded DeviceConfig
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)

		require.Equal(t, config.IPv4Addr, decoded.IPv4Addr)
		require.Equal(t, config.IPPool, decoded.IPPool)
		require.Nil(t, decoded.Routes)
	})
}
