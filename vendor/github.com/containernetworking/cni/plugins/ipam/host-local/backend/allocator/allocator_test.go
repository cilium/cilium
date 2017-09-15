// Copyright 2016 CNI authors
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

package allocator

import (
	"fmt"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	fakestore "github.com/containernetworking/cni/plugins/ipam/host-local/backend/testing"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"net"
)

type AllocatorTestCase struct {
	subnet       string
	ipmap        map[string]string
	expectResult string
	lastIP       string
}

func (t AllocatorTestCase) run() (*current.IPConfig, []*types.Route, error) {
	subnet, err := types.ParseCIDR(t.subnet)
	if err != nil {
		return nil, nil, err
	}

	conf := IPAMConfig{
		Name:   "test",
		Type:   "host-local",
		Subnet: types.IPNet{IP: subnet.IP, Mask: subnet.Mask},
	}
	store := fakestore.NewFakeStore(t.ipmap, net.ParseIP(t.lastIP))
	alloc, err := NewIPAllocator(&conf, store)
	if err != nil {
		return nil, nil, err
	}
	res, routes, err := alloc.Get("ID")
	if err != nil {
		return nil, nil, err
	}

	return res, routes, nil
}

var _ = Describe("host-local ip allocator", func() {
	Context("when has free ip", func() {
		It("should allocate ips in round robin", func() {
			testCases := []AllocatorTestCase{
				// fresh start
				{
					subnet:       "10.0.0.0/29",
					ipmap:        map[string]string{},
					expectResult: "10.0.0.2",
					lastIP:       "",
				},
				{
					subnet:       "10.0.0.0/30",
					ipmap:        map[string]string{},
					expectResult: "10.0.0.2",
					lastIP:       "",
				},
				{
					subnet: "10.0.0.0/29",
					ipmap: map[string]string{
						"10.0.0.2": "id",
					},
					expectResult: "10.0.0.3",
					lastIP:       "",
				},
				// next ip of last reserved ip
				{
					subnet:       "10.0.0.0/29",
					ipmap:        map[string]string{},
					expectResult: "10.0.0.6",
					lastIP:       "10.0.0.5",
				},
				{
					subnet: "10.0.0.0/29",
					ipmap: map[string]string{
						"10.0.0.4": "id",
						"10.0.0.5": "id",
					},
					expectResult: "10.0.0.6",
					lastIP:       "10.0.0.3",
				},
				// round robin to the beginning
				{
					subnet: "10.0.0.0/29",
					ipmap: map[string]string{
						"10.0.0.6": "id",
					},
					expectResult: "10.0.0.2",
					lastIP:       "10.0.0.5",
				},
				// lastIP is out of range
				{
					subnet: "10.0.0.0/29",
					ipmap: map[string]string{
						"10.0.0.2": "id",
					},
					expectResult: "10.0.0.3",
					lastIP:       "10.0.0.128",
				},
				// wrap around and reserve lastIP
				{
					subnet: "10.0.0.0/29",
					ipmap: map[string]string{
						"10.0.0.2": "id",
						"10.0.0.4": "id",
						"10.0.0.5": "id",
						"10.0.0.6": "id",
					},
					expectResult: "10.0.0.3",
					lastIP:       "10.0.0.3",
				},
			}

			for _, tc := range testCases {
				res, _, err := tc.run()
				Expect(err).ToNot(HaveOccurred())
				Expect(res.Address.IP.String()).To(Equal(tc.expectResult))
			}
		})

		It("should not allocate the broadcast address", func() {
			subnet, err := types.ParseCIDR("192.168.1.0/24")
			Expect(err).ToNot(HaveOccurred())

			conf := IPAMConfig{
				Name:   "test",
				Type:   "host-local",
				Subnet: types.IPNet{IP: subnet.IP, Mask: subnet.Mask},
			}
			store := fakestore.NewFakeStore(map[string]string{}, net.ParseIP(""))
			alloc, err := NewIPAllocator(&conf, store)
			Expect(err).ToNot(HaveOccurred())

			for i := 1; i < 254; i++ {
				res, _, err := alloc.Get("ID")
				Expect(err).ToNot(HaveOccurred())
				// i+1 because the gateway address is skipped
				s := fmt.Sprintf("192.168.1.%d/24", i+1)
				Expect(s).To(Equal(res.Address.String()))
			}

			_, _, err = alloc.Get("ID")
			Expect(err).To(HaveOccurred())
		})

		It("should allocate RangeStart first", func() {
			subnet, err := types.ParseCIDR("192.168.1.0/24")
			Expect(err).ToNot(HaveOccurred())

			conf := IPAMConfig{
				Name:       "test",
				Type:       "host-local",
				Subnet:     types.IPNet{IP: subnet.IP, Mask: subnet.Mask},
				RangeStart: net.ParseIP("192.168.1.10"),
			}
			store := fakestore.NewFakeStore(map[string]string{}, net.ParseIP(""))
			alloc, err := NewIPAllocator(&conf, store)
			Expect(err).ToNot(HaveOccurred())

			res, _, err := alloc.Get("ID")
			Expect(err).ToNot(HaveOccurred())
			Expect(res.Address.String()).To(Equal("192.168.1.10/24"))

			res, _, err = alloc.Get("ID")
			Expect(err).ToNot(HaveOccurred())
			Expect(res.Address.String()).To(Equal("192.168.1.11/24"))
		})

		It("should allocate RangeEnd but not past RangeEnd", func() {
			subnet, err := types.ParseCIDR("192.168.1.0/24")
			Expect(err).ToNot(HaveOccurred())

			conf := IPAMConfig{
				Name:     "test",
				Type:     "host-local",
				Subnet:   types.IPNet{IP: subnet.IP, Mask: subnet.Mask},
				RangeEnd: net.ParseIP("192.168.1.5"),
			}
			store := fakestore.NewFakeStore(map[string]string{}, net.ParseIP(""))
			alloc, err := NewIPAllocator(&conf, store)
			Expect(err).ToNot(HaveOccurred())

			for i := 1; i < 5; i++ {
				res, _, err := alloc.Get("ID")
				Expect(err).ToNot(HaveOccurred())
				// i+1 because the gateway address is skipped
				Expect(res.Address.String()).To(Equal(fmt.Sprintf("192.168.1.%d/24", i+1)))
			}

			_, _, err = alloc.Get("ID")
			Expect(err).To(HaveOccurred())
		})

		Context("when requesting a specific IP", func() {
			It("must allocate the requested IP", func() {
				subnet, err := types.ParseCIDR("10.0.0.0/29")
				Expect(err).ToNot(HaveOccurred())
				requestedIP := net.ParseIP("10.0.0.2")
				ipmap := map[string]string{}
				conf := IPAMConfig{
					Name:   "test",
					Type:   "host-local",
					Subnet: types.IPNet{IP: subnet.IP, Mask: subnet.Mask},
					Args:   &IPAMArgs{IP: requestedIP},
				}
				store := fakestore.NewFakeStore(ipmap, nil)
				alloc, _ := NewIPAllocator(&conf, store)
				res, _, err := alloc.Get("ID")
				Expect(err).ToNot(HaveOccurred())
				Expect(res.Address.IP.String()).To(Equal(requestedIP.String()))
			})

			It("must return an error when the requested IP is after RangeEnd", func() {
				subnet, err := types.ParseCIDR("192.168.1.0/24")
				Expect(err).ToNot(HaveOccurred())
				ipmap := map[string]string{}
				conf := IPAMConfig{
					Name:     "test",
					Type:     "host-local",
					Subnet:   types.IPNet{IP: subnet.IP, Mask: subnet.Mask},
					Args:     &IPAMArgs{IP: net.ParseIP("192.168.1.50")},
					RangeEnd: net.ParseIP("192.168.1.20"),
				}
				store := fakestore.NewFakeStore(ipmap, nil)
				alloc, _ := NewIPAllocator(&conf, store)
				_, _, err = alloc.Get("ID")
				Expect(err).To(HaveOccurred())
			})

			It("must return an error when the requested IP is before RangeStart", func() {
				subnet, err := types.ParseCIDR("192.168.1.0/24")
				Expect(err).ToNot(HaveOccurred())
				ipmap := map[string]string{}
				conf := IPAMConfig{
					Name:       "test",
					Type:       "host-local",
					Subnet:     types.IPNet{IP: subnet.IP, Mask: subnet.Mask},
					Args:       &IPAMArgs{IP: net.ParseIP("192.168.1.3")},
					RangeStart: net.ParseIP("192.168.1.10"),
				}
				store := fakestore.NewFakeStore(ipmap, nil)
				alloc, _ := NewIPAllocator(&conf, store)
				_, _, err = alloc.Get("ID")
				Expect(err).To(HaveOccurred())
			})
		})

		It("RangeStart must be in the given subnet", func() {
			subnet, err := types.ParseCIDR("192.168.1.0/24")
			Expect(err).ToNot(HaveOccurred())

			conf := IPAMConfig{
				Name:       "test",
				Type:       "host-local",
				Subnet:     types.IPNet{IP: subnet.IP, Mask: subnet.Mask},
				RangeStart: net.ParseIP("10.0.0.1"),
			}
			store := fakestore.NewFakeStore(map[string]string{}, net.ParseIP(""))
			_, err = NewIPAllocator(&conf, store)
			Expect(err).To(HaveOccurred())
		})

		It("RangeEnd must be in the given subnet", func() {
			subnet, err := types.ParseCIDR("192.168.1.0/24")
			Expect(err).ToNot(HaveOccurred())

			conf := IPAMConfig{
				Name:     "test",
				Type:     "host-local",
				Subnet:   types.IPNet{IP: subnet.IP, Mask: subnet.Mask},
				RangeEnd: net.ParseIP("10.0.0.1"),
			}
			store := fakestore.NewFakeStore(map[string]string{}, net.ParseIP(""))
			_, err = NewIPAllocator(&conf, store)
			Expect(err).To(HaveOccurred())
		})

		It("RangeEnd must be after RangeStart in the given subnet", func() {
			subnet, err := types.ParseCIDR("192.168.1.0/24")
			Expect(err).ToNot(HaveOccurred())

			conf := IPAMConfig{
				Name:       "test",
				Type:       "host-local",
				Subnet:     types.IPNet{IP: subnet.IP, Mask: subnet.Mask},
				RangeStart: net.ParseIP("192.168.1.10"),
				RangeEnd:   net.ParseIP("192.168.1.3"),
			}
			store := fakestore.NewFakeStore(map[string]string{}, net.ParseIP(""))
			_, err = NewIPAllocator(&conf, store)
			Expect(err).To(HaveOccurred())
		})
	})

	Context("when out of ips", func() {
		It("returns a meaningful error", func() {
			testCases := []AllocatorTestCase{
				{
					subnet: "10.0.0.0/30",
					ipmap: map[string]string{
						"10.0.0.2": "id",
						"10.0.0.3": "id",
					},
				},
				{
					subnet: "10.0.0.0/29",
					ipmap: map[string]string{
						"10.0.0.2": "id",
						"10.0.0.3": "id",
						"10.0.0.4": "id",
						"10.0.0.5": "id",
						"10.0.0.6": "id",
						"10.0.0.7": "id",
					},
				},
			}
			for _, tc := range testCases {
				_, _, err := tc.run()
				Expect(err).To(MatchError("no IP addresses available in network: test"))
			}
		})
	})

	Context("when given an invalid subnet", func() {
		It("returns a meaningful error", func() {
			subnet, err := types.ParseCIDR("192.168.1.0/31")
			Expect(err).ToNot(HaveOccurred())

			conf := IPAMConfig{
				Name:   "test",
				Type:   "host-local",
				Subnet: types.IPNet{IP: subnet.IP, Mask: subnet.Mask},
			}
			store := fakestore.NewFakeStore(map[string]string{}, net.ParseIP(""))
			_, err = NewIPAllocator(&conf, store)
			Expect(err).To(HaveOccurred())
		})
	})
})
