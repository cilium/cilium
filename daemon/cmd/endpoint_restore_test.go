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

	linuxrouting "github.com/cilium/cilium/pkg/datapath/linux/routing"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/ipam"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/mtu/fake"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
)

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

		restorer := &endpointRestorer{logger: hivetest.Logger(t)}
		err = restorer.clearStaleCiliumEndpointVeths()
		assert.NoError(t, err)

		// Check that stale iface is removed
		_, err = safenetlink.LinkByName(linkAttrs.Name)
		assert.Error(t, err)

		return nil
	})
}

func TestNeedsEndpointRoutingOnHost(t *testing.T) {
	oldIPAM := option.Config.IPAM
	oldInstallUplinkRoutes := option.Config.InstallUplinkRoutesForDelegatedIPAM
	defer func() {
		option.Config.IPAM = oldIPAM
		option.Config.InstallUplinkRoutesForDelegatedIPAM = oldInstallUplinkRoutes
	}()

	tests := []struct {
		name                                string
		ipam                                string
		installUplinkRoutesForDelegatedIPAM bool
		want                                bool
	}{
		{
			name: "ENI IPAM",
			ipam: ipamOption.IPAMENI,
			want: true,
		},
		{
			name: "Azure IPAM",
			ipam: ipamOption.IPAMAzure,
			want: true,
		},
		{
			name: "AlibabaCloud IPAM",
			ipam: ipamOption.IPAMAlibabaCloud,
			want: true,
		},
		{
			name: "cluster pool CIDR IPAM",
			ipam: ipamOption.IPAMKubernetes,
			want: false,
		},
		{
			name: "CRD IPAM",
			ipam: ipamOption.IPAMCRD,
			want: false,
		},
		{
			name:                                "delegated plugin without uplink routes",
			ipam:                                ipamOption.IPAMDelegatedPlugin,
			installUplinkRoutesForDelegatedIPAM: false,
			want:                                false,
		},
		{
			name:                                "delegated plugin with uplink routes",
			ipam:                                ipamOption.IPAMDelegatedPlugin,
			installUplinkRoutesForDelegatedIPAM: true,
			want:                                true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			option.Config.IPAM = tt.ipam
			option.Config.InstallUplinkRoutesForDelegatedIPAM = tt.installUplinkRoutesForDelegatedIPAM

			r := &endpointRestorer{}
			require.Equal(t, tt.want, r.needsEndpointRoutingOnHost())
		})
	}
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
		fakeMAC := "00:11:22:33:44:66"
		dummy := &netlink.Dummy{
			LinkAttrs: netlink.LinkAttrs{
				Name:         "epres-test",
				HardwareAddr: net.HardwareAddr(mac.MustParseMAC(fakeMAC)),
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
			IP: netip.MustParseAddr("192.168.2.123"),
			CIDRs: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.0/16"),
				netip.MustParsePrefix("192.170.0.0/16"),
			},
			PrimaryMAC:      fakeMAC,
			GatewayIP:       netip.MustParseAddr("192.168.2.1"),
			InterfaceNumber: "1",
		}

		restorer := &endpointRestorer{
			logger:     hivetest.Logger(t),
			mtuManager: &fake.MTU{},
		}

		// The endpoint was originally created (CNI ADD) while masquerading
		// was disabled, so an unconditional/catch-all egress rule is in place.
		option.Config.EnableIPv4Masquerade = false
		require.NoError(t, restorer.configureRoutingInfo(result))
		rules, err := safenetlink.RuleList(netlink.FAMILY_V4)
		require.NoError(t, err)
		catchAll, cidrSpecific := countEgressRulesForIP(rules, result.IP)
		require.Equal(t, 1, catchAll, "expected a single catch-all egress rule")
		require.Zero(t, cidrSpecific, "expected no CIDR-specific egress rules")

		// The datapath is reconfigured with masquerading enabled before the
		// agent restarts and endpoints are restored. The restore path must
		// reconcile the stale catch-all rule into per-CIDR rules.
		option.Config.EnableIPv4Masquerade = true
		require.NoError(t, restorer.configureRoutingInfo(result))
		rules, err = safenetlink.RuleList(netlink.FAMILY_V4)
		require.NoError(t, err)
		catchAll, cidrSpecific = countEgressRulesForIP(rules, result.IP)
		require.Zero(t, catchAll, "stale catch-all egress rule should have been removed")
		require.Equal(t, len(result.CIDRs), cidrSpecific, "expected one egress rule per CIDR")

		// The datapath is reconfigured again with masquerading disabled
		// before the next restart. The restore path must reconcile the
		// stale per-CIDR rules back into a single catch-all rule.
		option.Config.EnableIPv4Masquerade = false
		require.NoError(t, restorer.configureRoutingInfo(result))
		rules, err = safenetlink.RuleList(netlink.FAMILY_V4)
		require.NoError(t, err)
		catchAll, cidrSpecific = countEgressRulesForIP(rules, result.IP)
		require.Equal(t, 1, catchAll, "expected a single catch-all egress rule")
		require.Zero(t, cidrSpecific, "stale CIDR-specific egress rules should have been removed")

		require.NoError(t, linuxrouting.Delete(hivetest.Logger(t), result.IP))
		return nil
	})
}

// countEgressRulesForIP returns the number of catch-all (no 'to' field) and
// CIDR-specific ('to' field set) egress rules configured for the given
// source IP.
func countEgressRulesForIP(rules []netlink.Rule, ip netip.Addr) (catchAll, cidrSpecific int) {
	for _, rule := range rules {
		if rule.Src == nil || !rule.Src.IP.Equal(ip.AsSlice()) {
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
