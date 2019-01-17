// Copyright 2016-2018 Authors of Cilium
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
//
// +build darwin

package node

import (
	"net"

	"github.com/vishvananda/netlink"
)

func firstGlobalV4Addr(intf string) (net.IP, error) {
	return net.IP{}, nil
}

func findIPv6NodeAddr() net.IP {
	return net.IP{}
}

// getCiliumHostIPsFromNetDev returns the first IPv4 link local and returns
// it
func getCiliumHostIPsFromNetDev(devName string) (ipv4GW, ipv6Router net.IP) {
	return net.IP{}, net.IP{}
}

// firstLinkWithv6 returns the first network interface that contains the given
// IPv6 address.
func firstLinkWithv6(ip net.IP) (netlink.Link, error) {
	return nil, nil
}

func SetInternalIPv4From(_ string) error {
	return nil
}
