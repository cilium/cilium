// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"net"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/logging"
)

func TestCoalesceCIDRs(t *testing.T) {
	CIDR := []string{"10.0.0.0/8"}
	expectedCIDR := []string{"10.0.0.0/8"}
	newCIDR, err := coalesceCIDRs(CIDR)
	if err != nil || len(newCIDR) != len(expectedCIDR) || newCIDR[0] != expectedCIDR[0] {
		t.Errorf("got %v, want %v, err: %v\n", newCIDR, expectedCIDR, err)
	}

	CIDR = []string{"10.105.0.0/16", "10.0.0.0/8"}
	expectedCIDR = []string{"10.0.0.0/8"}
	newCIDR, err = coalesceCIDRs(CIDR)
	if err != nil || len(newCIDR) != len(expectedCIDR) || newCIDR[0] != expectedCIDR[0] {
		t.Errorf("got %v, want %v, err: %v\n", newCIDR, expectedCIDR, err)
	}

	CIDR = []string{"10.105.0.0/16", "10.104.0.0/19", "10.0.0.0/8"}
	expectedCIDR = []string{"10.0.0.0/8"}
	newCIDR, err = coalesceCIDRs(CIDR)
	if err != nil || len(newCIDR) != len(expectedCIDR) || newCIDR[0] != expectedCIDR[0] {
		t.Errorf("got %v, want %v, err: %v\n", newCIDR, expectedCIDR, err)
	}

	CIDR = []string{"10.105.0.0/16", "192.168.1.0/24"}
	expectedCIDR = []string{"10.105.0.0/16", "192.168.1.0/24"}
	newCIDR, err = coalesceCIDRs(CIDR)
	if err != nil || len(newCIDR) != len(expectedCIDR) || newCIDR[0] != expectedCIDR[0] || newCIDR[1] != expectedCIDR[1] {
		t.Errorf("got %v, want %v, err: %v\n", newCIDR, expectedCIDR, err)
	}

	CIDR = []string{"10.105.0.0/16", "192.168.1.0/24", "10.0.0.0/8"}
	expectedCIDR = []string{"10.0.0.0/8", "192.168.1.0/24"}
	newCIDR, err = coalesceCIDRs(CIDR)
	if err != nil || len(newCIDR) != len(expectedCIDR) || newCIDR[0] != expectedCIDR[0] || newCIDR[1] != expectedCIDR[1] {
		t.Errorf("got %v, want %v, err: %v\n", newCIDR, expectedCIDR, err)
	}

	CIDR = []string{"10.105.0.0/16", "192.168.1.0/24", "10.0.0.0/8", "f00d::a0f:0:0:0/96"}
	expectedCIDR = []string{"10.0.0.0/8", "192.168.1.0/24", "f00d::a0f:0:0:0/96"}
	newCIDR, err = coalesceCIDRs(CIDR)
	if err != nil || len(newCIDR) != len(expectedCIDR) || newCIDR[0] != expectedCIDR[0] || newCIDR[1] != expectedCIDR[1] || newCIDR[2] != expectedCIDR[2] {
		t.Errorf("got %v, want %v, err: %v\n", newCIDR, expectedCIDR, err)
	}

	CIDR = []string{"f00d::a0f:0:0:0/96", "10.105.0.0/16", "192.168.1.0/24", "10.0.0.0/8"}
	expectedCIDR = []string{"10.0.0.0/8", "192.168.1.0/24", "f00d::a0f:0:0:0/96"}
	newCIDR, err = coalesceCIDRs(CIDR)
	if err != nil || len(newCIDR) != len(expectedCIDR) || newCIDR[0] != expectedCIDR[0] || newCIDR[1] != expectedCIDR[1] || newCIDR[2] != expectedCIDR[2] {
		t.Errorf("got %v, want %v, err: %v\n", newCIDR, expectedCIDR, err)
	}

	CIDR = []string{"f00d::a0f:0:0:0/96"}
	expectedCIDR = []string{"f00d::a0f:0:0:0/96"}
	newCIDR, err = coalesceCIDRs(CIDR)
	if err != nil || len(newCIDR) != len(expectedCIDR) || newCIDR[0] != expectedCIDR[0] {
		t.Errorf("got %v, want %v, err: %v\n", newCIDR, expectedCIDR, err)
	}
}

type mockAllocateIP func(ip net.IP, owner string, pool ipam.Pool) (*ipam.AllocationResult, error)

func (m mockAllocateIP) AllocateIPWithoutSyncUpstream(ip net.IP, owner string, pool ipam.Pool) (*ipam.AllocationResult, error) {
	return m(ip, owner, pool)
}

func TestDaemon_reallocateDatapathIPs(t *testing.T) {
	level := logging.GetLevel(logging.DefaultLogger)
	logging.SetLogLevel(logrus.FatalLevel)
	logging.AddHooks()
	t.Cleanup(func() {
		logging.SetLogLevel(level)
	})

	allocCIDR := cidr.MustParseCIDR("10.20.30.0/24")
	alloc := mockAllocateIP(func(ip net.IP, owner string, pool ipam.Pool) (*ipam.AllocationResult, error) {
		if !allocCIDR.Contains(ip) {
			return nil, fmt.Errorf("cannot allocate IP %s", ip)
		}
		return &ipam.AllocationResult{IP: ip}, nil
	})

	fromFS := net.ParseIP("10.20.30.42")
	fromK8s := net.ParseIP("10.20.30.41")

	invalidFromFS := net.ParseIP("172.16.0.42")
	invalidFromK8s := net.ParseIP("172.16.0.41")

	// no restoration needed
	result := reallocateDatapathIPs(alloc, nil, nil)
	assert.Nil(t, result)

	// fromK8s if fromFS is not available
	result = reallocateDatapathIPs(alloc, fromK8s, nil)
	assert.NotNil(t, result)
	assert.Equal(t, result.IP, fromK8s)

	// fromFS if fromK8s is not available
	result = reallocateDatapathIPs(alloc, nil, fromFS)
	assert.NotNil(t, result)
	assert.Equal(t, result.IP, fromFS)

	// fromFS should be preferred
	result = reallocateDatapathIPs(alloc, fromK8s, fromFS)
	assert.NotNil(t, result)
	assert.Equal(t, result.IP, fromFS)

	// reject restoration if the IP is not in the allocation CIDR
	result = reallocateDatapathIPs(alloc, invalidFromFS, invalidFromK8s)
	assert.Nil(t, result)

	// fromFS with invalid fromK8s
	result = reallocateDatapathIPs(alloc, invalidFromK8s, fromFS)
	assert.NotNil(t, result)
	assert.Equal(t, result.IP, fromFS)

	// fromFS with invalid fromK8s
	result = reallocateDatapathIPs(alloc, fromK8s, invalidFromFS)
	assert.NotNil(t, result)
	assert.Equal(t, result.IP, fromK8s)
}
