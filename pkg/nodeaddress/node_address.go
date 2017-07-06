// Copyright 2016-2017 Authors of Cilium
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

package nodeaddress

import (
	"encoding/hex"
	"fmt"
	"net"

	"github.com/cilium/cilium/pkg/node"

	log "github.com/Sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/client-go/pkg/api/v1"
)

var (
	ipv4Address    net.IP
	ipv6Address    net.IP
	ipv4AllocRange *net.IPNet
	ipv6AllocRange *net.IPNet
)

func firstGlobalV4Addr(intf string) (net.IP, error) {
	var link netlink.Link
	var err error

	if intf != "" && intf != "undefined" {
		link, err = netlink.LinkByName(intf)
		if err != nil {
			return firstGlobalV4Addr("")
		}
	}

	addr, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return nil, err
	}

	for _, a := range addr {
		if a.Scope == unix.RT_SCOPE_UNIVERSE {
			if len(a.IP) >= 4 {
				return a.IP, nil
			}
		}
	}

	return nil, fmt.Errorf("No address found")
}

// InitDefaultPrefix initializes the node address and allocation prefixes with
// default values derived from the system. device can be set to the primary
// network device of the system in which case the first address with global
// scope will be regarded as the system's node address.
func InitDefaultPrefix(device string) {
	ip, err := firstGlobalV4Addr(device)
	if err == nil {
		ipv4Address = ip

		v4range := fmt.Sprintf(DefaultIPv4Prefix+"/%d",
			ip.To4()[3], DefaultIPv4PrefixLen)
		_, ip4net, err := net.ParseCIDR(v4range)
		if err != nil {
			log.Panicf("BUG: Invalid default prefix '%s': %s", v4range, err)
		}

		ipv4AllocRange = ip4net

		v6range := fmt.Sprintf("%s%02x%02x:%02x%02x:0:0/%d",
			DefaultIPv6Prefix, ip[0], ip[1], ip[2], ip[3],
			DefaultIPv6PrefixLen)

		ip6, ip6net, err := net.ParseCIDR(v6range)
		if err != nil {
			log.Panicf("BUG: Invalid default prefix '%s': %s", v6range, err)
		}

		ip6[14] = 0xff
		ip6[15] = 0xff

		ipv6Address = ip6
		ipv6AllocRange = ip6net
	}
}

func init() {
	InitDefaultPrefix("")
}

// GetIPv4ClusterRange returns the IPv4 prefix of the cluster
func GetIPv4ClusterRange() *net.IPNet {
	mask := net.CIDRMask(DefaultIPv4ClusterPrefixLen, 32)
	return &net.IPNet{
		IP:   ipv4AllocRange.IP.Mask(mask),
		Mask: mask,
	}
}

// GetIPv4AllocRange returns the IPv4 allocation prefix of this node
func GetIPv4AllocRange() *net.IPNet {
	return ipv4AllocRange
}

// GetIPv6ClusterRange returns the IPv6 prefix of the clustr
func GetIPv6ClusterRange() *net.IPNet {
	mask := net.CIDRMask(DefaultIPv6ClusterPrefixLen, 128)
	return &net.IPNet{
		IP:   ipv6AllocRange.IP.Mask(mask),
		Mask: mask,
	}
}

// GetIPv6AllocRange returns the IPv6 allocation prefix of this node
func GetIPv6AllocRange() *net.IPNet {
	return ipv6AllocRange
}

// SetIPv4 sets the IPv4 address of the node
func SetIPv4(ip net.IP) {
	ipv4Address = ip
}

// GetIPv4 returns the IPv4 address of the node
func GetIPv4() net.IP {
	return ipv4Address
}

// SetIPv4AllocRange sets the IPv4 address pool to use when allocating
// addresses for local endpoints
func SetIPv4AllocRange(net *net.IPNet) {
	ipv4AllocRange = net
}

// SetIPv6AllocRange sets the IPv6 address pool to use when allocating
// addresses for local endpoints
func SetIPv6AllocRange(net *net.IPNet) {
	ipv6AllocRange = net
}

// SetIPv6 sets the IPv6 address of the node
func SetIPv6(ip net.IP) {
	ipv6Address = ip
}

// GetIPv6 returns the IPv6 address of the node
func GetIPv6() net.IP {
	return ipv6Address
}

// GetIPv6NoZeroComp is similar to String but without generating zero
// compression in the address dump.
func GetIPv6NoZeroComp() string {
	const maxLen = len("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
	out := make([]byte, 0, maxLen)
	raw := ipv6Address

	if len(ipv6Address) != 16 {
		return ""
	}

	for i := 0; i < 16; i += 2 {
		if i > 0 {
			out = append(out, ':')
		}
		src := []byte{raw[i], raw[i+1]}
		tmp := make([]byte, hex.EncodedLen(len(src)))
		hex.Encode(tmp, src)
		if tmp[0] == tmp[1] && tmp[2] == tmp[3] &&
			tmp[0] == tmp[2] && tmp[0] == '0' {
			out = append(out, tmp[0])
		} else {
			out = append(out, tmp[0], tmp[1], tmp[2], tmp[3])
		}
	}

	return string(out)
}

// GetIPv6NodeRoute returns a route pointing to the IPv6 node address
func GetIPv6NodeRoute() net.IPNet {
	return net.IPNet{
		IP:   ipv6Address,
		Mask: net.CIDRMask(128, 128),
	}
}

// GetIPv4NodeRoute returns a route pointing to the IPv6 node address
func GetIPv4NodeRoute() net.IPNet {
	return net.IPNet{
		IP:   ipv4Address,
		Mask: net.CIDRMask(32, 32),
	}
}

// GetNode returns the identity and node spec for the local node
func GetNode() (node.Identity, *node.Node) {
	range4, range6 := ipv4AllocRange, ipv6AllocRange

	n := node.Node{
		Name: nodeName,
		IPAddresses: []node.Address{
			{
				AddressType: v1.NodeInternalIP,
				IP:          ipv4Address,
			},
			{
				AddressType: v1.NodeInternalIP,
				IP:          ipv4Address,
			},
		},
		IPv4AllocCIDR: range4,
		IPv6AllocCIDR: range6,
	}

	return node.Identity{Name: nodeName}, &n
}
