// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressmap

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/hive/hivetest"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestPolicyMap(t *testing.T) {
	testutils.PrivilegedTest(t)

	bpf.CheckOrMountFS("")
	assert.Nil(t, rlimit.RemoveMemlock())

	egressPolicyMap := createPolicyMap(hivetest.Lifecycle(t), DefaultPolicyConfig, ebpf.PinNone)

	sourceIP1, _ := netip.ParseAddr("1.1.1.1")
	sourceIP2, _ := netip.ParseAddr("1.1.1.2")

	destCIDR1, err := netip.ParsePrefix("2.2.1.0/24")
	assert.Nil(t, err)
	destCIDR2, err := netip.ParsePrefix("2.2.2.0/24")
	assert.Nil(t, err)

	egressIP1, _ := netip.ParseAddr("3.3.3.1")
	egressIP2, _ := netip.ParseAddr("3.3.3.2")

	err = egressPolicyMap.Update(sourceIP1, destCIDR1, egressIP1, egressIP1)
	assert.Nil(t, err)

	err = egressPolicyMap.Update(sourceIP2, destCIDR2, egressIP2, egressIP2)
	assert.Nil(t, err)

	val, err := egressPolicyMap.Lookup(sourceIP1, destCIDR1)
	assert.Nil(t, err)

	assert.True(t, val.EgressIP.Addr().Compare(egressIP1) == 0)
	assert.True(t, val.GatewayIP.Addr().Compare(egressIP1) == 0)

	val, err = egressPolicyMap.Lookup(sourceIP2, destCIDR2)
	assert.Nil(t, err)

	assert.True(t, val.EgressIP.Addr().Compare(egressIP2) == 0)
	assert.True(t, val.GatewayIP.Addr().Compare(egressIP2) == 0)

	err = egressPolicyMap.Delete(sourceIP2, destCIDR2)
	assert.Nil(t, err)

	val, err = egressPolicyMap.Lookup(sourceIP1, destCIDR1)
	assert.Nil(t, err)

	assert.True(t, val.EgressIP.Addr().Compare(egressIP1) == 0)
	assert.True(t, val.GatewayIP.Addr().Compare(egressIP1) == 0)

	_, err = egressPolicyMap.Lookup(sourceIP2, destCIDR2)
	assert.True(t, errors.Is(err, ebpf.ErrKeyNotExist))
}
