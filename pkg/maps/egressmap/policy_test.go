// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressmap

import (
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestPolicyMap(t *testing.T) {
	testutils.PrivilegedTest(t)

	logger := hivetest.Logger(t)
	bpf.CheckOrMountFS(logger, "")
	assert.NoError(t, rlimit.RemoveMemlock())

	t.Run("IPv4 policies", func(t *testing.T) {
		egressPolicyMap := createPolicyMap4(hivetest.Lifecycle(t), nil, DefaultPolicyConfig, ebpf.PinNone)

		sourceIP1 := netip.MustParseAddr("1.1.1.1")
		sourceIP2 := netip.MustParseAddr("1.1.1.2")

		destCIDR1 := netip.MustParsePrefix("2.2.1.0/24")
		destCIDR2 := netip.MustParsePrefix("2.2.2.0/24")

		egressIP1 := netip.MustParseAddr("3.3.3.1")
		egressIP2 := netip.MustParseAddr("3.3.3.2")

		err := egressPolicyMap.Update(sourceIP1, destCIDR1, egressIP1, egressIP1)
		assert.NoError(t, err)

		err = egressPolicyMap.Update(sourceIP2, destCIDR2, egressIP2, egressIP2)
		assert.NoError(t, err)

		val, err := egressPolicyMap.Lookup(sourceIP1, destCIDR1)
		assert.NoError(t, err)

		assert.Equal(t, val.EgressIP.Addr(), egressIP1)
		assert.Equal(t, val.GatewayIP.Addr(), egressIP1)

		val, err = egressPolicyMap.Lookup(sourceIP2, destCIDR2)
		assert.NoError(t, err)

		assert.Equal(t, val.EgressIP.Addr(), egressIP2)
		assert.Equal(t, val.GatewayIP.Addr(), egressIP2)

		err = egressPolicyMap.Delete(sourceIP2, destCIDR2)
		assert.NoError(t, err)

		val, err = egressPolicyMap.Lookup(sourceIP1, destCIDR1)
		assert.NoError(t, err)

		assert.Equal(t, val.EgressIP.Addr(), egressIP1)
		assert.Equal(t, val.GatewayIP.Addr(), egressIP1)

		_, err = egressPolicyMap.Lookup(sourceIP2, destCIDR2)
		assert.ErrorIs(t, err, ebpf.ErrKeyNotExist)
	})

	t.Run("IPv6 policies", func(t *testing.T) {
		egressPolicyMap := createPolicyMap6(hivetest.Lifecycle(t), nil, DefaultPolicyConfig, ebpf.PinNone)

		sourceIP1 := netip.MustParseAddr("2001:db8:1::1")
		sourceIP2 := netip.MustParseAddr("2001:db8:1::2")

		destCIDR1 := netip.MustParsePrefix("2001:db8:2::/64")
		destCIDR2 := netip.MustParsePrefix("2001:db8:3::/64")

		egressIP1 := netip.MustParseAddr("2001:db8:4::1")
		egressIP2 := netip.MustParseAddr("2001:db8:4::2")

		gatewayIP1 := netip.MustParseAddr("3.3.3.1")
		gatewayIP2 := netip.MustParseAddr("3.3.3.2")

		err := egressPolicyMap.Update(sourceIP1, destCIDR1, egressIP1, gatewayIP1)
		assert.NoError(t, err)

		err = egressPolicyMap.Update(sourceIP2, destCIDR2, egressIP2, gatewayIP2)
		assert.NoError(t, err)

		val, err := egressPolicyMap.Lookup(sourceIP1, destCIDR1)
		assert.NoError(t, err)

		assert.Equal(t, val.EgressIP.Addr(), egressIP1)
		assert.Equal(t, val.GatewayIP.Addr(), gatewayIP1)

		val, err = egressPolicyMap.Lookup(sourceIP2, destCIDR2)
		assert.NoError(t, err)

		assert.Equal(t, val.EgressIP.Addr(), egressIP2)
		assert.Equal(t, val.GatewayIP.Addr(), gatewayIP2)

		err = egressPolicyMap.Delete(sourceIP2, destCIDR2)
		assert.NoError(t, err)

		val, err = egressPolicyMap.Lookup(sourceIP1, destCIDR1)
		assert.NoError(t, err)

		assert.Equal(t, val.EgressIP.Addr(), egressIP1)
		assert.Equal(t, val.GatewayIP.Addr(), gatewayIP1)

		_, err = egressPolicyMap.Lookup(sourceIP2, destCIDR2)
		assert.ErrorIs(t, err, ebpf.ErrKeyNotExist)
	})
}
