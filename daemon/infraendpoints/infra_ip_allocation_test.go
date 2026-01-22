// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package infraendpoints

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
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
	result := infraIPAllocator.reallocateOldRouterIPs(nil, nil)
	assert.Nil(t, result)

	// fromK8s if fromFS is not available
	result = infraIPAllocator.reallocateOldRouterIPs(fromK8s, nil)
	assert.NotNil(t, result)
	assert.Equal(t, result.IP, fromK8s)

	// fromFS if fromK8s is not available
	result = infraIPAllocator.reallocateOldRouterIPs(nil, fromFS)
	assert.NotNil(t, result)
	assert.Equal(t, result.IP, fromFS)

	// fromFS should be preferred
	result = infraIPAllocator.reallocateOldRouterIPs(fromK8s, fromFS)
	assert.NotNil(t, result)
	assert.Equal(t, result.IP, fromFS)

	// reject restoration if the IP is not in the allocation CIDR
	result = infraIPAllocator.reallocateOldRouterIPs(invalidFromFS, invalidFromK8s)
	assert.Nil(t, result)

	// fromFS with invalid fromK8s
	result = infraIPAllocator.reallocateOldRouterIPs(invalidFromK8s, fromFS)
	assert.NotNil(t, result)
	assert.Equal(t, result.IP, fromFS)

	// fromFS with invalid fromK8s
	result = infraIPAllocator.reallocateOldRouterIPs(fromK8s, invalidFromFS)
	assert.NotNil(t, result)
	assert.Equal(t, result.IP, fromK8s)
}

func TestPrivilegedRemoveOldRouterState(t *testing.T) {
	testutils.PrivilegedTest(t)

	infraIPAllocator := &infraIPAllocator{
		logger: hivetest.Logger(t),
	}

	t.Run("test-1", func(t *testing.T) {
		ns := netns.NewNetNS(t)

		ns.Do(func() error {
			createDevices(t)

			// Assert that the old router IP (192.0.2.1) was removed because we are
			// restoring a different one (10.0.0.1).
			assert.NoError(t, infraIPAllocator.removeOldRouterState(false, net.ParseIP("10.0.0.1")))
			addrs, err := netlink.AddrList(&netlink.Dummy{
				LinkAttrs: netlink.LinkAttrs{
					Name: defaults.HostDevice,
				},
			}, netlink.FAMILY_V4)
			assert.NoError(t, err)
			assert.Empty(t, addrs)

			// Assert no errors in the case we have no IPs to remove from cilium_host.
			assert.NoError(t, infraIPAllocator.removeOldRouterState(false, nil))

			return nil
		})
	})

	t.Run("test-2", func(t *testing.T) {
		ns := netns.NewNetNS(t)

		ns.Do(func() error {
			createDevices(t)

			// Remove the cilium_host device and assert no error on "link not found"
			// error.
			link, err := safenetlink.LinkByName(defaults.HostDevice)
			assert.NoError(t, err)
			assert.NotNil(t, link)
			assert.NoError(t, netlink.LinkDel(link))
			assert.NoError(t, infraIPAllocator.removeOldRouterState(false, nil))

			return nil
		})
	})
}

// createDevices creates the necessary devices for this test suite. Assumes it
// is executing within the new network namespace.
func createDevices(t *testing.T) {
	t.Helper()

	hostMac, err := mac.GenerateRandMAC()
	if err != nil {
		assert.NoError(t, err)
	}
	veth := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name:         defaults.HostDevice,
			HardwareAddr: net.HardwareAddr(hostMac),
			TxQLen:       1000,
		},
	}
	if err := netlink.LinkAdd(veth); err != nil {
		assert.NoError(t, err)
	}
	ciliumHost, err := safenetlink.LinkByName(defaults.HostDevice)
	if err != nil {
		assert.NoError(t, err)
	}

	_, ipnet, _ := net.ParseCIDR("192.0.2.1/32")
	addr := &netlink.Addr{IPNet: ipnet}
	assert.NoError(t, netlink.AddrAdd(ciliumHost, addr))
}

func Test_getCiliumHostIPsFromFile(t *testing.T) {
	tmpDir := t.TempDir()
	allIPsCorrect := filepath.Join(tmpDir, "node_config.h")
	f, err := os.Create(allIPsCorrect)
	defer func(f *os.File) {
		require.NoError(t, f.Close())
	}(f)
	require.NoError(t, err)
	fmt.Fprintf(f, `/*
 cilium.v6.external.str fd01::b
 cilium.v6.internal.str f00d::a00:0:0:a4ad
 cilium.v6.nodeport.str []

 cilium.v4.external.str 192.168.60.11
 cilium.v4.internal.str 10.0.0.2
 cilium.v4.nodeport.str []

 cilium.v6.internal.raw 0xf0, 0xd, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa, 0x0, 0x0, 0x0, 0x0, 0x0, 0xa4, 0xad
 cilium.v4.internal.raw 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0xa, 0x0, 0x0, 0x2
 */

#define ENABLE_IPV4 1
#define IPV4_GATEWAY 0x100000a
#define HOST_IP 0xfd, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xb
#define HOST_ID 1
#define WORLD_ID 2
#define CILIUM_LB_MAP_MAX_ENTRIES 65536
#define ENDPOINTS_MAP_SIZE 65535
#define LPM_MAP_SIZE 16384
#define POLICY_MAP_SIZE 16384
#define IPCACHE_MAP_SIZE 512000
#define POLICY_PROG_MAP_SIZE 65535
#define TRACE_PAYLOAD_LEN 128ULL
#ifndef CILIUM_NET_MAC
#define CILIUM_NET_MAC { .addr = {0x26,0x11,0x70,0xcc,0xca,0x0c}}
#endif /* CILIUM_NET_MAC */
#define CILIUM_HOST_MAC { .addr = {0x3e,0x28,0xb4,0x4b,0x95,0x25}}
#define ENCAP_IFINDEX 358
`)

	type args struct {
		nodeConfig string
	}
	tests := []struct {
		name            string
		args            args
		wantIpv4GW      net.IP
		wantIpv6Router  net.IP
		wantIpv6Address net.IP
	}{
		{
			name: "every-ip-correct",
			args: args{
				nodeConfig: allIPsCorrect,
			},
			wantIpv4GW:      net.ParseIP("10.0.0.2"),
			wantIpv6Router:  net.ParseIP("f00d::a00:0:0:a4ad"),
			wantIpv6Address: net.ParseIP("fd01::b"),
		},
		{
			name: "file-not-present",
			args: args{
				nodeConfig: "",
			},
			wantIpv4GW:     nil,
			wantIpv6Router: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIpv4GW, gotIpv6Router := getCiliumHostIPsFromFile(tt.args.nodeConfig)
			require.Equal(t, tt.wantIpv4GW, gotIpv4GW)
			require.Equal(t, tt.wantIpv6Router, gotIpv6Router)
		})
	}
}
