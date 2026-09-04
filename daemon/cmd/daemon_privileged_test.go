// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"net"
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	fakeTypes "github.com/cilium/cilium/pkg/datapath/fake/types"
	linuxrouting "github.com/cilium/cilium/pkg/datapath/linux/routing"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/ipam"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

func TestPrivilegedRemoveOldRouterState(t *testing.T) {
	testutils.PrivilegedTest(t)

	t.Run("test-1", func(t *testing.T) {
		ns := netns.NewNetNS(t)

		ns.Do(func() error {
			createDevices(t)

			// Assert that the old router IP (192.0.2.1) was removed because we are
			// restoring a different one (10.0.0.1).
			assert.NoError(t, removeOldRouterState(hivetest.Logger(t), false, net.ParseIP("10.0.0.1")))
			addrs, err := netlink.AddrList(&netlink.Dummy{
				LinkAttrs: netlink.LinkAttrs{
					Name: defaults.HostDevice,
				},
			}, netlink.FAMILY_V4)
			assert.NoError(t, err)
			assert.Empty(t, addrs)

			// Assert no errors in the case we have no IPs to remove from cilium_host.
			assert.NoError(t, removeOldRouterState(hivetest.Logger(t), false, nil))

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
			assert.NoError(t, removeOldRouterState(hivetest.Logger(t), false, nil))

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

func TestPrivilegedRemoveStaleEPIfaces(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)

	ns.Do(func() error {
		linkAttrs := netlink.NewLinkAttrs()
		linkAttrs.Name = "lxc12345"
		veth := &netlink.Veth{
			LinkAttrs: linkAttrs,
			PeerName:  "tmp54321",
		}

		err := netlink.LinkAdd(veth)
		assert.NoError(t, err)

		_, err = safenetlink.LinkByName(linkAttrs.Name)
		assert.NoError(t, err)

		// Check that stale iface is removed
		err = clearCiliumVeths(hivetest.Logger(t))
		assert.NoError(t, err)

		_, err = safenetlink.LinkByName(linkAttrs.Name)
		assert.Error(t, err)

		return nil
	})
}

// TestPrivilegedConfigureRoutingInfoOnRestore verifies that configureRoutingInfo,
// called during endpoint restore, reconciles the egress ip rules of a restored
// endpoint to match the *current* masquerade configuration, even though those
// rules were originally installed once by CNI ADD under a potentially
// different configuration.
func TestPrivilegedConfigureRoutingInfoOnRestore(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns := netns.NewNetNS(t)
	ns.Do(func() error {
		fakeMAC, err := net.ParseMAC("00:11:22:33:44:66")
		require.NoError(t, err)
		dummy := &netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{
				Name:         "epres-test",
				HardwareAddr: fakeMAC,
			},
		}
		require.NoError(t, netlink.LinkAdd(dummy))
		defer func() {
			require.NoError(t, netlink.LinkDel(dummy))
		}()

		oldIPAM := option.Config.IPAM
		oldMasq := option.Config.EnableIPv4Masquerade
		defer func() {
			option.Config.IPAM = oldIPAM
			option.Config.EnableIPv4Masquerade = oldMasq
		}()
		option.Config.IPAM = ipamOption.IPAMENI

		result := &ipam.AllocationResult{
			IP: net.ParseIP("192.168.2.123"),
			CIDRs: []string{
				"192.168.0.0/16",
				"192.170.0.0/16",
			},
			PrimaryMAC:      fakeMAC.String(),
			GatewayIP:       "192.168.2.1",
			InterfaceNumber: "1",
		}

		d := &Daemon{
			logger:    hivetest.Logger(t),
			mtuConfig: &fakeTypes.MTU{},
		}

		// The endpoint was originally created (CNI ADD) while masquerading
		// was disabled, so an unconditional/catch-all egress rule is in place.
		option.Config.EnableIPv4Masquerade = false
		require.NoError(t, d.configureRoutingInfo(result))
		rules, err := safenetlink.RuleList(netlink.FAMILY_V4)
		require.NoError(t, err)
		catchAll, cidrSpecific := countEgressRulesForIP(rules, result.IP)
		require.Equal(t, 1, catchAll, "expected a single catch-all egress rule")
		require.Zero(t, cidrSpecific, "expected no CIDR-specific egress rules")

		// The datapath is reconfigured with masquerading enabled before the
		// agent restarts and endpoints are restored. The restore path must
		// reconcile the stale catch-all rule into per-CIDR rules.
		option.Config.EnableIPv4Masquerade = true
		require.NoError(t, d.configureRoutingInfo(result))
		rules, err = safenetlink.RuleList(netlink.FAMILY_V4)
		require.NoError(t, err)
		catchAll, cidrSpecific = countEgressRulesForIP(rules, result.IP)
		require.Zero(t, catchAll, "stale catch-all egress rule should have been removed")
		require.Equal(t, len(result.CIDRs), cidrSpecific, "expected one egress rule per CIDR")

		// The datapath is reconfigured again with masquerading disabled
		// before the next restart. The restore path must reconcile the
		// stale per-CIDR rules back into a single catch-all rule.
		option.Config.EnableIPv4Masquerade = false
		require.NoError(t, d.configureRoutingInfo(result))
		rules, err = safenetlink.RuleList(netlink.FAMILY_V4)
		require.NoError(t, err)
		catchAll, cidrSpecific = countEgressRulesForIP(rules, result.IP)
		require.Equal(t, 1, catchAll, "expected a single catch-all egress rule")
		require.Zero(t, cidrSpecific, "stale CIDR-specific egress rules should have been removed")

		addr, ok := netip.AddrFromSlice(result.IP)
		require.True(t, ok)
		require.NoError(t, linuxrouting.Delete(hivetest.Logger(t), addr.Unmap(), option.Config.EgressMultiHomeIPRuleCompat))
		return nil
	})
}

// countEgressRulesForIP returns the number of catch-all (no 'to' field) and
// CIDR-specific ('to' field set) egress rules configured for the given
// source IP.
func countEgressRulesForIP(rules []netlink.Rule, ip net.IP) (catchAll, cidrSpecific int) {
	for _, rule := range rules {
		if rule.Src == nil || !rule.Src.IP.Equal(ip) {
			continue
		}
		if rule.Dst == nil {
			catchAll++
		} else {
			cidrSpecific++
		}
	}
	return catchAll, cidrSpecific
}
