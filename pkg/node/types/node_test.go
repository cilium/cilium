// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/node/addressing"
)

func TestGetNodeIP(t *testing.T) {
	n := Node{
		Name: "node-1",
		IPAddresses: []Address{
			{IP: net.ParseIP("192.0.2.3"), Type: addressing.NodeExternalIP},
		},
	}
	ip := n.GetNodeIP(false)
	// Return the only IP present
	require.Equal(t, ip, net.ParseIP("192.0.2.3"))

	n.IPAddresses = append(n.IPAddresses, Address{IP: net.ParseIP("192.0.2.3"), Type: addressing.NodeExternalIP})
	ip = n.GetNodeIP(false)
	// The next priority should be NodeExternalIP
	require.Equal(t, ip, net.ParseIP("192.0.2.3"))

	n.IPAddresses = append(n.IPAddresses, Address{IP: net.ParseIP("198.51.100.2"), Type: addressing.NodeInternalIP})
	ip = n.GetNodeIP(false)
	// The next priority should be NodeInternalIP
	require.Equal(t, ip, net.ParseIP("198.51.100.2"))

	n.IPAddresses = append(n.IPAddresses, Address{IP: net.ParseIP("2001:DB8::1"), Type: addressing.NodeExternalIP})
	ip = n.GetNodeIP(true)
	// The next priority should be NodeExternalIP and IPv6
	require.Equal(t, ip, net.ParseIP("2001:DB8::1"))

	n.IPAddresses = append(n.IPAddresses, Address{IP: net.ParseIP("2001:DB8::2"), Type: addressing.NodeInternalIP})
	ip = n.GetNodeIP(true)
	// The next priority should be NodeInternalIP and IPv6
	require.Equal(t, ip, net.ParseIP("2001:DB8::2"))

	n.IPAddresses = append(n.IPAddresses, Address{IP: net.ParseIP("198.51.100.2"), Type: addressing.NodeInternalIP})
	ip = n.GetNodeIP(false)
	// Should still return NodeInternalIP and IPv4
	require.Equal(t, ip, net.ParseIP("198.51.100.2"))
}

func TestGetIPByType(t *testing.T) {
	n := Node{
		Name: "node-1",
		IPAddresses: []Address{
			{IP: net.ParseIP("192.0.2.3"), Type: addressing.NodeExternalIP},
		},
	}

	ip := n.GetIPByType(addressing.NodeInternalIP, false)
	require.Nil(t, ip)
	ip = n.GetIPByType(addressing.NodeInternalIP, true)
	require.Nil(t, ip)

	ip = n.GetIPByType(addressing.NodeExternalIP, false)
	require.Equal(t, ip, net.ParseIP("192.0.2.3"))
	ip = n.GetIPByType(addressing.NodeExternalIP, true)
	require.Nil(t, ip)

	n = Node{
		Name: "node-2",
		IPAddresses: []Address{
			{IP: net.ParseIP("f00b::1"), Type: addressing.NodeCiliumInternalIP},
		},
	}

	ip = n.GetIPByType(addressing.NodeExternalIP, false)
	require.Nil(t, ip)
	ip = n.GetIPByType(addressing.NodeExternalIP, true)
	require.Nil(t, ip)

	ip = n.GetIPByType(addressing.NodeCiliumInternalIP, false)
	require.Nil(t, ip)
	ip = n.GetIPByType(addressing.NodeCiliumInternalIP, true)
	require.Equal(t, ip, net.ParseIP("f00b::1"))

	n = Node{
		Name: "node-3",
		IPAddresses: []Address{
			{IP: net.ParseIP("192.42.0.3"), Type: addressing.NodeExternalIP},
			{IP: net.ParseIP("f00d::1"), Type: addressing.NodeExternalIP},
		},
	}

	ip = n.GetIPByType(addressing.NodeInternalIP, false)
	require.Nil(t, ip)
	ip = n.GetIPByType(addressing.NodeInternalIP, true)
	require.Nil(t, ip)

	ip = n.GetIPByType(addressing.NodeExternalIP, false)
	require.Equal(t, ip, net.ParseIP("192.42.0.3"))
	ip = n.GetIPByType(addressing.NodeExternalIP, true)
	require.Equal(t, ip, net.ParseIP("f00d::1"))
}

func TestNodeValidate(t *testing.T) {
	tests := []struct {
		name   string
		node   Node
		assert assert.ErrorAssertionFunc
	}{
		{
			name:   "empty cluster",
			node:   Node{Name: "bar"},
			assert: assert.Error,
		},
		{
			name:   "empty name",
			node:   Node{Cluster: "foo"},
			assert: assert.Error,
		},
		{
			name:   "empty cluster ID",
			node:   Node{Cluster: "foo", Name: "bar"},
			assert: assert.NoError,
		},
		{
			name:   "valid cluster ID",
			node:   Node{Cluster: "foo", Name: "bar", ClusterID: 99},
			assert: assert.NoError,
		},
		{
			name:   "invalid cluster ID",
			node:   Node{Cluster: "foo", Name: "bar", ClusterID: 260},
			assert: assert.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.assert(t, tt.node.validate())
		})
	}
}

func TestGetIPv4AllocCIDRs(t *testing.T) {
	var (
		p1 = netip.MustParsePrefix("1.0.0.0/24")
		p2 = netip.MustParsePrefix("2.0.0.0/24")
		p3 = netip.MustParsePrefix("3.0.0.0/24")
	)

	var tests = []struct {
		// name of test
		name string
		// primary ipv4 allocation cidr
		allocCIDR Prefix
		// secondary ipv4 allocation cidrs
		secAllocCIDRs []Prefix
		// expected ipv4 cidrs
		expectedCIDRs []netip.Prefix
	}{
		{
			name:          "zero cidrs",
			allocCIDR:     Prefix{},
			secAllocCIDRs: nil,
			expectedCIDRs: make([]netip.Prefix, 0),
		},
		{
			name:          "one primary and no secondary cidrs",
			allocCIDR:     PrefixFrom(p1),
			secAllocCIDRs: nil,
			expectedCIDRs: []netip.Prefix{p1},
		},
		{
			name:          "one primary and one secondary cidr",
			allocCIDR:     PrefixFrom(p1),
			secAllocCIDRs: []Prefix{PrefixFrom(p2)},
			expectedCIDRs: []netip.Prefix{p1, p2},
		},
		{
			name:          "one primary and multiple secondary cidrs",
			allocCIDR:     PrefixFrom(p1),
			secAllocCIDRs: []Prefix{PrefixFrom(p2), PrefixFrom(p3)},
			expectedCIDRs: []netip.Prefix{p1, p2, p3},
		},
		{
			// An invalid (zero) secondary is skipped rather than surfaced as a
			// zero netip.Prefix entry.
			name:          "invalid secondary cidr is skipped",
			allocCIDR:     PrefixFrom(p1),
			secAllocCIDRs: []Prefix{{}, PrefixFrom(p2)},
			expectedCIDRs: []netip.Prefix{p1, p2},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := Node{
				Name:                    fmt.Sprintf("node-%s", tt.name),
				IPv4AllocCIDR:           tt.allocCIDR,
				IPv4SecondaryAllocCIDRs: tt.secAllocCIDRs,
			}

			actual := n.GetIPv4AllocCIDRs()
			assert.Equal(t, tt.expectedCIDRs, actual)
		})
	}
}

func TestGetIPv6AllocCIDRs(t *testing.T) {
	var (
		p2001 = netip.MustParsePrefix("2001:db8::/32")
		p2002 = netip.MustParsePrefix("2002:db8::/32")
		p2003 = netip.MustParsePrefix("2003:db8::/32")
	)

	var tests = []struct {
		// name of test
		name string
		// primary ipv6 allocation cidr
		allocCIDR Prefix
		// secondary ipv6 allocation cidrs
		secAllocCIDRs []Prefix
		// expected ipv6 cidrs
		expectedCIDRs []netip.Prefix
	}{
		{
			name:          "zero cidrs",
			allocCIDR:     Prefix{},
			secAllocCIDRs: nil,
			expectedCIDRs: make([]netip.Prefix, 0),
		},
		{
			name:          "one primary and no secondary cidrs",
			allocCIDR:     PrefixFrom(p2001),
			secAllocCIDRs: nil,
			expectedCIDRs: []netip.Prefix{p2001},
		},
		{
			name:          "one primary and one secondary cidr",
			allocCIDR:     PrefixFrom(p2001),
			secAllocCIDRs: []Prefix{PrefixFrom(p2002)},
			expectedCIDRs: []netip.Prefix{p2001, p2002},
		},
		{
			name:          "one primary and multiple secondary cidrs",
			allocCIDR:     PrefixFrom(p2001),
			secAllocCIDRs: []Prefix{PrefixFrom(p2002), PrefixFrom(p2003)},
			expectedCIDRs: []netip.Prefix{p2001, p2002, p2003},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := Node{
				Name:                    fmt.Sprintf("node-%s", tt.name),
				IPv6AllocCIDR:           tt.allocCIDR,
				IPv6SecondaryAllocCIDRs: tt.secAllocCIDRs,
			}

			actual := n.GetIPv6AllocCIDRs()
			assert.Equal(t, tt.expectedCIDRs, actual)
		})
	}
}

// TestNodeCIDRFieldsWireGolden is the core kvstore-compatibility proof for the
// migration of the alloc-CIDR fields from *cidr.CIDR to types.Prefix: the
// serialized Node must keep emitting the legacy net.IPNet object form (base64
// mask, {"IP","Mask"} key order) so independently-upgraded agents and
// kvstoremesh peers still parse it. Do not relax these to JSONEq: byte-exact
// key order and mask encoding are what old agents diff against.
func TestNodeCIDRFieldsWireGolden(t *testing.T) {
	n := Node{
		Name:                    "node-1",
		Cluster:                 "default",
		IPv4AllocCIDR:           PrefixFrom(netip.MustParsePrefix("10.244.1.0/24")),
		IPv6AllocCIDR:           PrefixFrom(netip.MustParsePrefix("fd00::/64")),
		IPv4SecondaryAllocCIDRs: []Prefix{PrefixFrom(netip.MustParsePrefix("10.244.2.0/24"))},
		IPv6SecondaryAllocCIDRs: []Prefix{PrefixFrom(netip.MustParsePrefix("fd01::/64"))},
	}

	b, err := n.Marshal()
	require.NoError(t, err)

	// json.RawMessage preserves the exact on-wire bytes of each field value.
	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(b, &raw))

	//nolint:testifylint // byte-exact wire format matters for kvstore compat, JSONEq would ignore key order.
	assert.Equal(t, `{"IP":"10.244.1.0","Mask":"////AA=="}`, string(raw["IPv4AllocCIDR"]))
	//nolint:testifylint // byte-exact wire format matters for kvstore compat, JSONEq would ignore key order.
	assert.Equal(t, `{"IP":"fd00::","Mask":"//////////8AAAAAAAAAAA=="}`, string(raw["IPv6AllocCIDR"]))
	//nolint:testifylint // byte-exact wire format matters for kvstore compat, JSONEq would ignore key order.
	assert.Equal(t, `[{"IP":"10.244.2.0","Mask":"////AA=="}]`, string(raw["IPv4SecondaryAllocCIDRs"]))
	//nolint:testifylint // byte-exact wire format matters for kvstore compat, JSONEq would ignore key order.
	assert.Equal(t, `[{"IP":"fd01::","Mask":"//////////8AAAAAAAAAAA=="}]`, string(raw["IPv6SecondaryAllocCIDRs"]))

	// An unset primary CIDR still serializes to a "null" key, matching a nil
	// *cidr.CIDR (adding omitempty/omitzero here would drop the key and change
	// the bytes).
	zero := Node{Name: "node-2", Cluster: "default"}
	zb, err := zero.Marshal()
	require.NoError(t, err)
	var zraw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(zb, &zraw))
	assert.Equal(t, "null", string(zraw["IPv4AllocCIDR"]))
	assert.Equal(t, "null", string(zraw["IPv6AllocCIDR"]))

	// Round-trip: the marshaled bytes unmarshal back into the same Node.
	var back Node
	require.NoError(t, back.Unmarshal(n.GetKeyName(), b))
	require.True(t, back.DeepEqual(&n))
}

// TestNodeCIDRFieldsUnmarshalLegacy proves a pre-migration payload (produced by
// an agent that stored *cidr.CIDR) still parses into the new types.Prefix
// fields.
func TestNodeCIDRFieldsUnmarshalLegacy(t *testing.T) {
	legacy := []byte(`{
		"Name": "node-1",
		"Cluster": "default",
		"ClusterID": 1,
		"IPv4AllocCIDR": {"IP":"10.244.1.0","Mask":"////AA=="},
		"IPv6AllocCIDR": {"IP":"fd00::","Mask":"//////////8AAAAAAAAAAA=="},
		"IPv4SecondaryAllocCIDRs": [{"IP":"10.244.2.0","Mask":"////AA=="}],
		"IPv6SecondaryAllocCIDRs": [{"IP":"fd01::","Mask":"//////////8AAAAAAAAAAA=="}]
	}`)

	var n Node
	require.NoError(t, n.Unmarshal("default/node-1", legacy))

	assert.Equal(t, netip.MustParsePrefix("10.244.1.0/24"), n.IPv4AllocCIDR.Prefix.Prefix)
	assert.Equal(t, netip.MustParsePrefix("fd00::/64"), n.IPv6AllocCIDR.Prefix.Prefix)
	require.Len(t, n.IPv4SecondaryAllocCIDRs, 1)
	assert.Equal(t, netip.MustParsePrefix("10.244.2.0/24"), n.IPv4SecondaryAllocCIDRs[0].Prefix.Prefix)
	require.Len(t, n.IPv6SecondaryAllocCIDRs, 1)
	assert.Equal(t, netip.MustParsePrefix("fd01::/64"), n.IPv6SecondaryAllocCIDRs[0].Prefix.Prefix)

	// And re-marshaling reproduces the legacy bytes for those fields.
	b, err := n.Marshal()
	require.NoError(t, err)
	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(b, &raw))
	//nolint:testifylint // byte-exact wire format matters for kvstore compat, JSONEq would ignore key order.
	assert.Equal(t, `{"IP":"10.244.1.0","Mask":"////AA=="}`, string(raw["IPv4AllocCIDR"]))
}
