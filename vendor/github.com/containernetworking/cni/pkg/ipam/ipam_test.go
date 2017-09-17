// Copyright 2015 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ipam

import (
	"net"
	"syscall"

	"github.com/containernetworking/cni/pkg/ns"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"

	"github.com/vishvananda/netlink"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const LINK_NAME = "eth0"

func ipNetEqual(a, b *net.IPNet) bool {
	aPrefix, aBits := a.Mask.Size()
	bPrefix, bBits := b.Mask.Size()
	if aPrefix != bPrefix || aBits != bBits {
		return false
	}
	return a.IP.Equal(b.IP)
}

var _ = Describe("IPAM Operations", func() {
	var originalNS ns.NetNS
	var ipv4, ipv6, routev4, routev6 *net.IPNet
	var ipgw4, ipgw6, routegwv4, routegwv6 net.IP
	var result *current.Result

	BeforeEach(func() {
		// Create a new NetNS so we don't modify the host
		var err error
		originalNS, err = ns.NewNS()
		Expect(err).NotTo(HaveOccurred())

		err = originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			// Add master
			err = netlink.LinkAdd(&netlink.Dummy{
				LinkAttrs: netlink.LinkAttrs{
					Name: LINK_NAME,
				},
			})
			Expect(err).NotTo(HaveOccurred())
			_, err = netlink.LinkByName(LINK_NAME)
			Expect(err).NotTo(HaveOccurred())
			return nil
		})
		Expect(err).NotTo(HaveOccurred())

		ipv4, err = types.ParseCIDR("1.2.3.30/24")
		Expect(err).NotTo(HaveOccurred())
		Expect(ipv4).NotTo(BeNil())

		_, routev4, err = net.ParseCIDR("15.5.6.8/24")
		Expect(err).NotTo(HaveOccurred())
		Expect(routev4).NotTo(BeNil())
		routegwv4 = net.ParseIP("1.2.3.5")
		Expect(routegwv4).NotTo(BeNil())

		ipgw4 = net.ParseIP("1.2.3.1")
		Expect(ipgw4).NotTo(BeNil())

		ipv6, err = types.ParseCIDR("abcd:1234:ffff::cdde/64")
		Expect(err).NotTo(HaveOccurred())
		Expect(ipv6).NotTo(BeNil())

		_, routev6, err = net.ParseCIDR("1111:dddd::aaaa/80")
		Expect(err).NotTo(HaveOccurred())
		Expect(routev6).NotTo(BeNil())
		routegwv6 = net.ParseIP("abcd:1234:ffff::10")
		Expect(routegwv6).NotTo(BeNil())

		ipgw6 = net.ParseIP("abcd:1234:ffff::1")
		Expect(ipgw6).NotTo(BeNil())

		result = &current.Result{
			Interfaces: []*current.Interface{
				{
					Name:    "eth0",
					Mac:     "00:11:22:33:44:55",
					Sandbox: "/proc/3553/ns/net",
				},
				{
					Name:    "fake0",
					Mac:     "00:33:44:55:66:77",
					Sandbox: "/proc/1234/ns/net",
				},
			},
			IPs: []*current.IPConfig{
				{
					Version:   "4",
					Interface: 0,
					Address:   *ipv4,
					Gateway:   ipgw4,
				},
				{
					Version:   "6",
					Interface: 0,
					Address:   *ipv6,
					Gateway:   ipgw6,
				},
			},
			Routes: []*types.Route{
				{Dst: *routev4, GW: routegwv4},
				{Dst: *routev6, GW: routegwv6},
			},
		}
	})

	AfterEach(func() {
		Expect(originalNS.Close()).To(Succeed())
	})

	It("configures a link with addresses and routes", func() {
		err := originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			err := ConfigureIface(LINK_NAME, result)
			Expect(err).NotTo(HaveOccurred())

			link, err := netlink.LinkByName(LINK_NAME)
			Expect(err).NotTo(HaveOccurred())
			Expect(link.Attrs().Name).To(Equal(LINK_NAME))

			v4addrs, err := netlink.AddrList(link, syscall.AF_INET)
			Expect(err).NotTo(HaveOccurred())
			Expect(len(v4addrs)).To(Equal(1))
			Expect(ipNetEqual(v4addrs[0].IPNet, ipv4)).To(Equal(true))

			v6addrs, err := netlink.AddrList(link, syscall.AF_INET6)
			Expect(err).NotTo(HaveOccurred())
			Expect(len(v6addrs)).To(Equal(2))

			var found bool
			for _, a := range v6addrs {
				if ipNetEqual(a.IPNet, ipv6) {
					found = true
					break
				}
			}
			Expect(found).To(Equal(true))

			// Ensure the v4 route, v6 route, and subnet route
			routes, err := netlink.RouteList(link, 0)
			Expect(err).NotTo(HaveOccurred())

			var v4found, v6found bool
			for _, route := range routes {
				isv4 := route.Dst.IP.To4() != nil
				if isv4 && ipNetEqual(route.Dst, routev4) && route.Gw.Equal(routegwv4) {
					v4found = true
				}
				if !isv4 && ipNetEqual(route.Dst, routev6) && route.Gw.Equal(routegwv6) {
					v6found = true
				}

				if v4found && v6found {
					break
				}
			}
			Expect(v4found).To(Equal(true))
			Expect(v6found).To(Equal(true))

			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("configures a link with routes using address gateways", func() {
		result.Routes[0].GW = nil
		result.Routes[1].GW = nil
		err := originalNS.Do(func(ns.NetNS) error {
			defer GinkgoRecover()

			err := ConfigureIface(LINK_NAME, result)
			Expect(err).NotTo(HaveOccurred())

			link, err := netlink.LinkByName(LINK_NAME)
			Expect(err).NotTo(HaveOccurred())
			Expect(link.Attrs().Name).To(Equal(LINK_NAME))

			// Ensure the v4 route, v6 route, and subnet route
			routes, err := netlink.RouteList(link, 0)
			Expect(err).NotTo(HaveOccurred())

			var v4found, v6found bool
			for _, route := range routes {
				isv4 := route.Dst.IP.To4() != nil
				if isv4 && ipNetEqual(route.Dst, routev4) && route.Gw.Equal(ipgw4) {
					v4found = true
				}
				if !isv4 && ipNetEqual(route.Dst, routev6) && route.Gw.Equal(ipgw6) {
					v6found = true
				}

				if v4found && v6found {
					break
				}
			}
			Expect(v4found).To(Equal(true))
			Expect(v6found).To(Equal(true))

			return nil
		})
		Expect(err).NotTo(HaveOccurred())
	})

	It("returns an error when the interface index doesn't match the link name", func() {
		result.IPs[0].Interface = 1
		err := originalNS.Do(func(ns.NetNS) error {
			return ConfigureIface(LINK_NAME, result)
		})
		Expect(err).To(HaveOccurred())
	})

	It("returns an error when the interface index is too big", func() {
		result.IPs[0].Interface = 2
		err := originalNS.Do(func(ns.NetNS) error {
			return ConfigureIface(LINK_NAME, result)
		})
		Expect(err).To(HaveOccurred())
	})

	It("returns an error when there are no interfaces to configure", func() {
		result.Interfaces = []*current.Interface{}
		err := originalNS.Do(func(ns.NetNS) error {
			return ConfigureIface(LINK_NAME, result)
		})
		Expect(err).To(HaveOccurred())
	})

	It("returns an error when configuring the wrong interface", func() {
		err := originalNS.Do(func(ns.NetNS) error {
			return ConfigureIface("asdfasdf", result)
		})
		Expect(err).To(HaveOccurred())
	})
})
