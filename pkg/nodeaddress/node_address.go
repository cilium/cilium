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
	// EnableIPv4 can be set to false to disable Ipv4
	EnableIPv4 = true

	ipv4ClusterCidrMaskSize = DefaultIPv4ClusterPrefixLen

	ipv4ExternalAddress net.IP
	ipv4InternalAddress net.IP
	ipv6Address         net.IP
	ipv6RouterAddress   net.IP
	ipv4AllocRange      *net.IPNet
	ipv6AllocRange      *net.IPNet

	addressDevice = ""
)

func makeIPv6HostIP(ip net.IP) net.IP {
	// Derive prefix::1 as the IPv6 host address
	ip[12] = 0
	ip[13] = 0
	ip[14] = 0
	ip[15] = 1
	return ip
}

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
				if link != nil {
					addressDevice = link.Attrs().Name
				}
				return a.IP, nil
			}
		}
	}

	return nil, fmt.Errorf("No address found")
}

func findIPv6NodeAddr() net.IP {
	addr, err := netlink.AddrList(nil, netlink.FAMILY_V6)
	if err != nil {
		return nil
	}

	// prefer global scope address
	for _, a := range addr {
		if a.Scope == unix.RT_SCOPE_UNIVERSE {
			if len(a.IP) >= 16 {
				return a.IP
			}
		}
	}

	// fall back to anything wider than link (site, custom, ...)
	for _, a := range addr {
		if a.Scope < unix.RT_SCOPE_LINK {
			if len(a.IP) >= 16 {
				return a.IP
			}
		}
	}

	return nil
}

// SetIPv4ClusterCidrMaskSize sets the size of the mask of the IPv4 cluster prefix
func SetIPv4ClusterCidrMaskSize(size int) {
	ipv4ClusterCidrMaskSize = size
}

// InitDefaultPrefix initializes the node address and allocation prefixes with
// default values derived from the system. device can be set to the primary
// network device of the system in which case the first address with global
// scope will be regarded as the system's node address.
func InitDefaultPrefix(device string) {
	// Find a IPv6 node address first
	ipv6Address = findIPv6NodeAddr()

	ip, err := firstGlobalV4Addr(device)
	if err == nil {
		ipv4ExternalAddress = ip

		v4range := fmt.Sprintf(DefaultIPv4Prefix+"/%d",
			ip.To4()[3], DefaultIPv4PrefixLen)
		_, ip4net, err := net.ParseCIDR(v4range)
		if err != nil {
			log.Panicf("BUG: Invalid default prefix '%s': %s", v4range, err)
		}

		ipv4AllocRange = ip4net

		v6range := fmt.Sprintf("%s%02x%02x:%02x%02x:0:0/%d",
			DefaultIPv6Prefix, ip[0], ip[1], ip[2], ip[3],
			IPv6NodePrefixLen)

		_, ip6net, err := net.ParseCIDR(v6range)
		if err != nil {
			log.Panicf("BUG: Invalid default prefix '%s': %s", v6range, err)
		}

		ipv6AllocRange = ip6net
	}
}

func init() {
	InitDefaultPrefix("")
}

// GetIPv4ClusterRange returns the IPv4 prefix of the cluster
func GetIPv4ClusterRange() *net.IPNet {
	mask := net.CIDRMask(ipv4ClusterCidrMaskSize, 32)
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
	mask := net.CIDRMask(IPv6NodeAllocPrefixLen, 128)
	return &net.IPNet{
		IP:   ipv6AllocRange.IP.Mask(mask),
		Mask: mask,
	}
}

// GetIPv6NodeRange returns the IPv6 allocation prefix of this node
func GetIPv6NodeRange() *net.IPNet {
	return ipv6AllocRange
}

// SetExternalIPv4 sets the external IPv4 node address. It must be reachable on the network.
func SetExternalIPv4(ip net.IP) {
	ipv4ExternalAddress = ip
}

// GetExternalIPv4 returns the external IPv4 node address
func GetExternalIPv4() net.IP {
	return ipv4ExternalAddress
}

// SetInternalIPv4 sets the internal IPv4 node address, it is allocated from the node prefix
func SetInternalIPv4(ip net.IP) {
	ipv4InternalAddress = ip
}

// GetInternalIPv4 returns the internal IPv4 node address
func GetInternalIPv4() net.IP {
	return ipv4InternalAddress
}

// SetIPv4AllocRange sets the IPv4 address pool to use when allocating
// addresses for local endpoints
func SetIPv4AllocRange(net *net.IPNet) {
	ipv4AllocRange = net
}

// SetIPv6NodeRange sets the IPv6 address pool to be used on this node
func SetIPv6NodeRange(net *net.IPNet) error {
	if ones, _ := net.Mask.Size(); ones != IPv6NodePrefixLen {
		return fmt.Errorf("prefix length must be /%d", IPv6NodePrefixLen)
	}

	copy := *net
	ipv6AllocRange = &copy

	return nil
}

// AutoComplete completes the parts of addressing that can be auto derived
func AutoComplete() error {
	if ipv6AllocRange == nil {
		return fmt.Errorf("IPv6 per node allocation prefix is not configured. Please specificy --ipv6-range")
	}

	if ipv6Address == nil {
		ipv6Address = makeIPv6HostIP(ipv6AllocRange.IP)
	}

	return nil
}

// ValidatePostInit validates the entire addressing setup and completes it as
// required
func ValidatePostInit() error {
	if ipv4ExternalAddress == nil {
		return fmt.Errorf("External IPv4 node address could not be derived, please configure via --ipv4-node")
	}

	if EnableIPv4 {
		if ipv4InternalAddress == nil {
			return fmt.Errorf("BUG: Internal IPv4 node address was not configured")
		}

		ones, _ := ipv4AllocRange.Mask.Size()
		if ipv4ClusterCidrMaskSize > ones {
			return fmt.Errorf("IPv4 per node allocation prefix (%s) must be inside cluster prefix (%s)",
				ipv4AllocRange, GetIPv4ClusterRange())
		}
	}

	return nil
}

// SetIPv6 sets the IPv6 address of the node
func SetIPv6(ip net.IP) {
	ipv6Address = ip
}

// GetIPv6 returns the IPv6 address of the node
func GetIPv6() net.IP {
	return ipv6Address
}

// GetIPv6Router returns the IPv6 address of the node
func GetIPv6Router() net.IP {
	return ipv6RouterAddress
}

// SetIPv6Router returns the IPv6 address of the node
func SetIPv6Router(ip net.IP) {
	ipv6RouterAddress = ip
}

// GetIPv6NoZeroComp is similar to String but without generating zero
// compression in the address dump.
func GetIPv6NoZeroComp() string {
	const maxLen = len("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
	out := make([]byte, 0, maxLen)
	raw := ipv6RouterAddress

	if len(raw) != 16 {
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
		IP:   ipv6RouterAddress,
		Mask: net.CIDRMask(128, 128),
	}
}

// GetIPv4NodeRoute returns a route pointing to the IPv4 node address
func GetIPv4NodeRoute() net.IPNet {
	return net.IPNet{
		IP:   ipv4InternalAddress,
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
				IP:          ipv4ExternalAddress,
			},
		},
		IPv4AllocCIDR: range4,
		IPv6AllocCIDR: range6,
	}

	return node.Identity{Name: nodeName}, &n
}

// UseNodeCIDR sets the ipv4-range and ipv6-range values values from the
// addresses defined in the given node.
func UseNodeCIDR(node *node.Node) error {
	if node.IPv4AllocCIDR != nil {
		log.Infof("Retrieved %s for node %s. Using it for ipv4-range", node.IPv4AllocCIDR, node.Name)
		SetIPv4AllocRange(node.IPv4AllocCIDR)
	}
	if node.IPv6AllocCIDR != nil {
		log.Infof("Retrieved %s for node %s. Using it for ipv6-range", node.IPv6AllocCIDR, node.Name)
		if err := SetIPv6NodeRange(node.IPv6AllocCIDR); err != nil {
			log.Warningf("k8s: Can't use CIDR '%s' from kubernetes: %s", node.IPv6AllocCIDR, err)
		}
	}

	return nil
}

// UseNodeAddresses sets the local ipv4-node and ipv6-node values from the
// addresses defined in the given node.
func UseNodeAddresses(node *node.Node) error {
	nodeIP4 := node.GetNodeIP(false)
	if nodeIP4 != nil {
		log.Infof("Automatically retrieved %s for node %s. Using it for ipv4-node", nodeIP4, node.Name)
		SetExternalIPv4(nodeIP4)
	}
	nodeIP6 := node.GetNodeIP(true)
	if nodeIP6 != nil {
		log.Infof("Automatically retrieved %s for node %s. Using it for ipv6-node", nodeIP6, node.Name)
		SetIPv6(nodeIP6)
	}

	return nil
}

// GetAddressDevice returns the name of the link where the node address is
// configured on
func GetAddressDevice() (string, error) {
	if addressDevice != "" {
		return addressDevice, nil
	}

	links, err := netlink.LinkList()
	if err != nil {
		return "", err
	}

	for _, link := range links {
		addrList, err := netlink.AddrList(link, netlink.FAMILY_V4)
		if err != nil {
			return "", err
		}

		for _, a := range addrList {
			if ipv4ExternalAddress.Equal(a.IP) {
				addressDevice = link.Attrs().Name
				return addressDevice, nil
			}
		}
	}

	return "disabled", nil
}
