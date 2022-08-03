// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"net"
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/loader"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/testutils"
)

func Test_removeOldRouterState(t *testing.T) {
	testutils.PrivilegedTest(t)

	const netnsName = "test-daemon-priv-0"

	t.Run("test-1", func(t *testing.T) {
		netns0, clean := setupNetNS(t, netnsName)
		defer clean()

		netns0.Do(func(_ ns.NetNS) error {
			createDevices(t)

			// Assert that the old router IP (192.0.2.1) was removed because we are
			// restoring a different one (10.0.0.1).
			assert.NoError(t, removeOldRouterState(false, net.ParseIP("10.0.0.1")))
			addrs, err := netlink.AddrList(&netlink.Dummy{
				LinkAttrs: netlink.LinkAttrs{
					Name: defaults.HostDevice,
				},
			}, netlink.FAMILY_V4)
			assert.NoError(t, err)
			assert.Len(t, addrs, 0)

			// Assert no errors in the case we have no IPs to remove from cilium_host.
			assert.NoError(t, removeOldRouterState(false, nil))

			return nil
		})
	})

	t.Run("test-2", func(t *testing.T) {
		netns0, clean := setupNetNS(t, netnsName)
		defer clean()

		netns0.Do(func(_ ns.NetNS) error {
			createDevices(t)

			// Remove the cilium_host device and assert no error on "link not found"
			// error.
			link, err := netlink.LinkByName(defaults.HostDevice)
			assert.NoError(t, err)
			assert.NotNil(t, link)
			assert.NoError(t, netlink.LinkDel(link))
			assert.NoError(t, removeOldRouterState(false, nil))

			return nil
		})
	})
}

// createDevices creates the necessary devices for this test suite. Assumes it
// is executing within the new network namespace.
func createDevices(t *testing.T) {
	t.Helper()

	ciliumHost, ciliumNet, err := loader.SetupBaseDevice(1500)
	assert.NoError(t, err)
	assert.NotNil(t, ciliumHost)
	assert.NotNil(t, ciliumNet)

	_, ipnet, _ := net.ParseCIDR("192.0.2.1/32")
	addr := &netlink.Addr{IPNet: ipnet}
	assert.NoError(t, netlink.AddrAdd(ciliumHost, addr))
}

func setupNetNS(t *testing.T, netnsName string) (ns.NetNS, func()) {
	t.Helper()

	netns0, err := netns.ReplaceNetNSWithName(netnsName)
	assert.NoError(t, err)
	assert.NotNil(t, netns0)

	return netns0, func() {
		assert.NoError(t, netns.RemoveNetNSWithName(netnsName))
	}
}
