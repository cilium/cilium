// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"net"
	"testing"

	"github.com/containernetworking/plugins/pkg/ns"
	. "github.com/onsi/gomega"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/linux/route"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/testutils"
)

func Test_cleanupUnreachableRoutes(t *testing.T) {
	testutils.PrivilegedTest(t)

	RegisterTestingT(t)

	// temporary network namespace to ensure routes don't interfere with test system
	const testNSName = "test-cilium-ipam-netns0"
	netns0, err := netns.ReplaceNetNSWithName(testNSName)
	Expect(err).To(BeNil())
	t.Cleanup(func() {
		netns0.Close()
		netns.RemoveNetNSWithName(testNSName)
	})

	parseCIDR := func(s string) *net.IPNet {
		t.Helper()
		_, cidr, err := net.ParseCIDR(s)
		Expect(err).ToNot(HaveOccurred())
		return cidr
	}

	getUnreachableRoutes := func(family int) []netlink.Route {
		t.Helper()
		routes, err := netlink.RouteListFiltered(family, &netlink.Route{
			Type: unix.RTN_UNREACHABLE,
		}, netlink.RT_FILTER_TYPE)
		Expect(err).ToNot(HaveOccurred())
		return routes
	}

	netns0.Do(func(_ ns.NetNS) error {
		for _, podIPs := range []string{
			"10.10.0.1/32", "10.10.0.2/32", "10.20.0.1/32",
			"fe80::1/128", "fe80:beef::2/128", "fe80:c0fe::3/128",
		} {
			err = netlink.RouteReplace(&netlink.Route{
				Dst:   parseCIDR(podIPs),
				Table: route.MainTable,
				Type:  unix.RTN_UNREACHABLE,
			})
			Expect(err).ToNot(HaveOccurred())
		}
		err = cleanupUnreachableRoutes("10.10.0.0/24")
		Expect(err).ToNot(HaveOccurred())

		// Ensure only first two IPv4 routes are cleaned up
		leftover := getUnreachableRoutes(netlink.FAMILY_V4)
		Expect(err).ToNot(HaveOccurred())
		Expect(leftover).To(HaveLen(1))
		Expect(leftover[0].Dst).To(Equal(parseCIDR("10.20.0.1/32")))

		// Remove remaining route
		err = cleanupUnreachableRoutes("10.20.0.0/24")
		Expect(err).ToNot(HaveOccurred())
		leftover = getUnreachableRoutes(netlink.FAMILY_V4)
		Expect(leftover).To(BeEmpty())

		// Remove IPv6 routes
		err = cleanupUnreachableRoutes("fe80::/16")
		Expect(err).ToNot(HaveOccurred())
		leftover = getUnreachableRoutes(netlink.FAMILY_V6)
		Expect(leftover).To(BeEmpty())

		return nil
	})
}
