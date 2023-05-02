// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package egressmap

import (
	"errors"
	"net"
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

	sourceIP1 := net.ParseIP("1.1.1.1")
	sourceIP2 := net.ParseIP("1.1.1.2")

	_, destCIDR1, err := net.ParseCIDR("2.2.1.0/24")
	assert.Nil(t, err)
	_, destCIDR2, err := net.ParseCIDR("2.2.2.0/24")
	assert.Nil(t, err)

	egressIP1 := net.ParseIP("3.3.3.1")
	egressIP2 := net.ParseIP("3.3.3.2")

	err = egressPolicyMap.Update(sourceIP1, *destCIDR1, egressIP1, egressIP1)
	assert.Nil(t, err)

	err = egressPolicyMap.Update(sourceIP2, *destCIDR2, egressIP2, egressIP2)
	assert.Nil(t, err)

	val, err := egressPolicyMap.Lookup(sourceIP1, *destCIDR1)
	assert.Nil(t, err)

	assert.True(t, val.EgressIP.IP().Equal(egressIP1))
	assert.True(t, val.GatewayIP.IP().Equal(egressIP1))

	val, err = egressPolicyMap.Lookup(sourceIP2, *destCIDR2)
	assert.Nil(t, err)

	assert.True(t, val.EgressIP.IP().Equal(egressIP2))
	assert.True(t, val.GatewayIP.IP().Equal(egressIP2))

	err = egressPolicyMap.Delete(sourceIP2, *destCIDR2)
	assert.Nil(t, err)

	val, err = egressPolicyMap.Lookup(sourceIP1, *destCIDR1)
	assert.Nil(t, err)

	assert.True(t, val.EgressIP.IP().Equal(egressIP1))
	assert.True(t, val.GatewayIP.IP().Equal(egressIP1))

	_, err = egressPolicyMap.Lookup(sourceIP2, *destCIDR2)
	assert.True(t, errors.Is(err, ebpf.ErrKeyNotExist))
}
