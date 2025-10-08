// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"net"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/ipam"
)

func TestCoalesceCIDRs(t *testing.T) {
	infraIPAllocator := &infraIPAllocator{
		logger: hivetest.Logger(t),
	}

	CIDR := []string{"10.0.0.0/8"}
	expectedCIDR := []string{"10.0.0.0/8"}
	newCIDR, err := infraIPAllocator.coalesceCIDRs(CIDR)
	if err != nil || len(newCIDR) != len(expectedCIDR) || newCIDR[0] != expectedCIDR[0] {
		t.Errorf("got %v, want %v, err: %v\n", newCIDR, expectedCIDR, err)
	}

	CIDR = []string{"10.105.0.0/16", "10.0.0.0/8"}
	expectedCIDR = []string{"10.0.0.0/8"}
	newCIDR, err = infraIPAllocator.coalesceCIDRs(CIDR)
	if err != nil || len(newCIDR) != len(expectedCIDR) || newCIDR[0] != expectedCIDR[0] {
		t.Errorf("got %v, want %v, err: %v\n", newCIDR, expectedCIDR, err)
	}

	CIDR = []string{"10.105.0.0/16", "10.104.0.0/19", "10.0.0.0/8"}
	expectedCIDR = []string{"10.0.0.0/8"}
	newCIDR, err = infraIPAllocator.coalesceCIDRs(CIDR)
	if err != nil || len(newCIDR) != len(expectedCIDR) || newCIDR[0] != expectedCIDR[0] {
		t.Errorf("got %v, want %v, err: %v\n", newCIDR, expectedCIDR, err)
	}

	CIDR = []string{"10.105.0.0/16", "192.168.1.0/24"}
	expectedCIDR = []string{"10.105.0.0/16", "192.168.1.0/24"}
	newCIDR, err = infraIPAllocator.coalesceCIDRs(CIDR)
	if err != nil || len(newCIDR) != len(expectedCIDR) || newCIDR[0] != expectedCIDR[0] || newCIDR[1] != expectedCIDR[1] {
		t.Errorf("got %v, want %v, err: %v\n", newCIDR, expectedCIDR, err)
	}

	CIDR = []string{"10.105.0.0/16", "192.168.1.0/24", "10.0.0.0/8"}
	expectedCIDR = []string{"10.0.0.0/8", "192.168.1.0/24"}
	newCIDR, err = infraIPAllocator.coalesceCIDRs(CIDR)
	if err != nil || len(newCIDR) != len(expectedCIDR) || newCIDR[0] != expectedCIDR[0] || newCIDR[1] != expectedCIDR[1] {
		t.Errorf("got %v, want %v, err: %v\n", newCIDR, expectedCIDR, err)
	}

	CIDR = []string{"10.105.0.0/16", "192.168.1.0/24", "10.0.0.0/8", "f00d::a0f:0:0:0/96"}
	expectedCIDR = []string{"10.0.0.0/8", "192.168.1.0/24", "f00d::a0f:0:0:0/96"}
	newCIDR, err = infraIPAllocator.coalesceCIDRs(CIDR)
	if err != nil || len(newCIDR) != len(expectedCIDR) || newCIDR[0] != expectedCIDR[0] || newCIDR[1] != expectedCIDR[1] || newCIDR[2] != expectedCIDR[2] {
		t.Errorf("got %v, want %v, err: %v\n", newCIDR, expectedCIDR, err)
	}

	CIDR = []string{"f00d::a0f:0:0:0/96", "10.105.0.0/16", "192.168.1.0/24", "10.0.0.0/8"}
	expectedCIDR = []string{"10.0.0.0/8", "192.168.1.0/24", "f00d::a0f:0:0:0/96"}
	newCIDR, err = infraIPAllocator.coalesceCIDRs(CIDR)
	if err != nil || len(newCIDR) != len(expectedCIDR) || newCIDR[0] != expectedCIDR[0] || newCIDR[1] != expectedCIDR[1] || newCIDR[2] != expectedCIDR[2] {
		t.Errorf("got %v, want %v, err: %v\n", newCIDR, expectedCIDR, err)
	}

	CIDR = []string{"f00d::a0f:0:0:0/96"}
	expectedCIDR = []string{"f00d::a0f:0:0:0/96"}
	newCIDR, err = infraIPAllocator.coalesceCIDRs(CIDR)
	if err != nil || len(newCIDR) != len(expectedCIDR) || newCIDR[0] != expectedCIDR[0] {
		t.Errorf("got %v, want %v, err: %v\n", newCIDR, expectedCIDR, err)
	}
}

type mockIPAllocator struct {
	allocCIDR *cidr.CIDR
}

func (m *mockIPAllocator) AllocateIPWithoutSyncUpstream(ip net.IP, owner string, pool ipam.Pool) (*ipam.AllocationResult, error) {
	if !m.allocCIDR.Contains(ip) {
		return nil, fmt.Errorf("cannot allocate IP %s", ip)
	}
	return &ipam.AllocationResult{IP: ip}, nil
}

func (m *mockIPAllocator) AllocateNextFamilyWithoutSyncUpstream(family ipam.Family, owner string, pool ipam.Pool) (result *ipam.AllocationResult, err error) {
	return nil, nil
}

func (m *mockIPAllocator) ExcludeIP(ip net.IP, owner string, pool ipam.Pool) {}

func (m *mockIPAllocator) ReleaseIP(ip net.IP, pool ipam.Pool) error {
	return nil
}

var _ ipamAllocator = &mockIPAllocator{}

func TestDaemon_reallocateDatapathIPs(t *testing.T) {
	infraIPAllocator := &infraIPAllocator{
		logger: hivetest.Logger(t),
		ipAllocator: &mockIPAllocator{
			allocCIDR: cidr.MustParseCIDR("10.20.30.0/24"),
		},
	}

	fromFS := net.ParseIP("10.20.30.42")
	fromK8s := net.ParseIP("10.20.30.41")

	invalidFromFS := net.ParseIP("172.16.0.42")
	invalidFromK8s := net.ParseIP("172.16.0.41")

	// no restoration needed
	result := infraIPAllocator.reallocateDatapathIPs(nil, nil)
	assert.Nil(t, result)

	// fromK8s if fromFS is not available
	result = infraIPAllocator.reallocateDatapathIPs(fromK8s, nil)
	assert.NotNil(t, result)
	assert.Equal(t, result.IP, fromK8s)

	// fromFS if fromK8s is not available
	result = infraIPAllocator.reallocateDatapathIPs(nil, fromFS)
	assert.NotNil(t, result)
	assert.Equal(t, result.IP, fromFS)

	// fromFS should be preferred
	result = infraIPAllocator.reallocateDatapathIPs(fromK8s, fromFS)
	assert.NotNil(t, result)
	assert.Equal(t, result.IP, fromFS)

	// reject restoration if the IP is not in the allocation CIDR
	result = infraIPAllocator.reallocateDatapathIPs(invalidFromFS, invalidFromK8s)
	assert.Nil(t, result)

	// fromFS with invalid fromK8s
	result = infraIPAllocator.reallocateDatapathIPs(invalidFromK8s, fromFS)
	assert.NotNil(t, result)
	assert.Equal(t, result.IP, fromFS)

	// fromFS with invalid fromK8s
	result = infraIPAllocator.reallocateDatapathIPs(fromK8s, invalidFromFS)
	assert.NotNil(t, result)
	assert.Equal(t, result.IP, fromK8s)
}
