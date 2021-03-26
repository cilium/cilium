// Copyright 2019-2020 Authors of Cilium
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

package cidr

import (
	"bytes"
	"fmt"
	"github.com/vishvananda/netlink"
	"net"
)

// NewCIDR returns a new CIDR using a net.IPNet
func NewCIDR(ipnet *net.IPNet) *CIDR {
	if ipnet == nil {
		return nil
	}

	return &CIDR{ipnet}
}

// CIDR is a network CIDR representation based on net.IPNet
type CIDR struct {
	*net.IPNet
}

// DeepEqual is an deepequal function, deeply comparing the receiver with other.
// in must be non-nil.
func (in *CIDR) DeepEqual(other *CIDR) bool {
	if other == nil {
		return false
	}

	if (in.IPNet == nil) != (other.IPNet == nil) {
		return false
	} else if in.IPNet != nil {
		if !in.IPNet.IP.Equal(other.IPNet.IP) {
			return false
		}
		inOnes, inBits := in.IPNet.Mask.Size()
		otherOnes, otherBits := other.IPNet.Mask.Size()
		return inOnes == otherOnes && inBits == otherBits
	}

	return true
}

// DeepCopy creates a deep copy of a CIDR
func (n *CIDR) DeepCopy() *CIDR {
	if n == nil {
		return nil
	}
	out := new(CIDR)
	n.DeepCopyInto(out)
	return out
}

// DeepCopyInto is a deepcopy function, copying the receiver, writing into out. in must be non-nil.
func (in *CIDR) DeepCopyInto(out *CIDR) {
	*out = *in
	if in.IPNet == nil {
		return
	}
	out.IPNet = new(net.IPNet)
	*out.IPNet = *in.IPNet
	if in.IPNet.IP != nil {
		in, out := &in.IPNet.IP, &out.IPNet.IP
		*out = make(net.IP, len(*in))
		copy(*out, *in)
	}
	if in.IPNet.Mask != nil {
		in, out := &in.IPNet.Mask, &out.IPNet.Mask
		*out = make(net.IPMask, len(*in))
		copy(*out, *in)
	}
	return
}

// AvailableIPs returns the number of IPs available in a CIDR
func (n *CIDR) AvailableIPs() int {
	ones, bits := n.Mask.Size()
	return 1 << (bits - ones)
}

// Equal returns true if the receiver's CIDR equals the other CIDR.
func (n *CIDR) Equal(o *CIDR) bool {
	if n == nil || o == nil {
		return n == o
	}
	return Equal(n.IPNet, o.IPNet)
}

// Equal returns true if the n and o net.IPNet CIDRs arr Equal.
func Equal(n, o *net.IPNet) bool {
	if n == nil || o == nil {
		return n == o
	}
	if n == o {
		return true
	}
	return n.IP.Equal(o.IP) &&
		bytes.Equal(n.Mask, o.Mask)
}

// ContainsAll returns true if 'ipNets1' contains all net.IPNet of 'ipNets2'
func ContainsAll(ipNets1, ipNets2 []*net.IPNet) bool {
	for _, n := range ipNets2 {
		if !Contains(ipNets1, n) {
			return false
		}
	}
	return true
}

// Contains returns true if 'ipNets' contains ipNet.
func Contains(ipNets []*net.IPNet, ipNet *net.IPNet) bool {
	for _, n := range ipNets {
		if Equal(n, ipNet) {
			return true
		}
	}
	return false
}

// ParseCIDR parses the CIDR string using net.ParseCIDR
func ParseCIDR(str string) (*CIDR, error) {
	_, ipnet, err := net.ParseCIDR(str)
	if err != nil {
		return nil, err
	}
	return NewCIDR(ipnet), nil
}

// MustParseCIDR parses the CIDR string using net.ParseCIDR and panics if the
// CIDR cannot be parsed
func MustParseCIDR(str string) *CIDR {
	c, err := ParseCIDR(str)
	if err != nil {
		panic(fmt.Sprintf("Unable to parse CIDR '%s': %s", str, err))
	}
	return c
}

// Version returns the IP version for an IP, or 0 if the IP is not valid.
func IPVersion(i *net.IP) int {
	if i.To4() != nil {
		return 4
	} else if len(*i) == net.IPv6len {
		return 6
	}
	return 0
}

// matchCIDRs matchs an IP address against a list of cidrs.
// If the list is empty, it always matches.
func matchCIDRs(ip net.IP, cidrs []*net.IPNet) bool {
	if len(cidrs) == 0 {
		return true
	}
	for _, cidr := range cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

func DetectCIDRByCIDR(cidr *CIDR, version int) (netlink.Link, net.IP, *net.IPNet, error) {
	netIfaces, err := netlink.LinkList()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Can't detect the CIDR: Failed to enumerate interfaces: %w", err)
	}

	cidrs := []*net.IPNet{cidr.IPNet}
	// Loop through interfaces filtering on the CIDR
	for idx := len(netIfaces) - 1; idx >= 0; idx-- {
		iface := netIfaces[idx]
		addrs, err := netlink.AddrList(iface, netlink.FAMILY_ALL)
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ip := addr.IP
			ipNet := addr.IPNet
			if IPVersion(&ip) == version && ip.IsGlobalUnicast() && matchCIDRs(ip, cidrs) {
				return iface, ip, ipNet, nil
			}
		}
	}
	return nil, nil, nil, fmt.Errorf("no valid IPv%d addresses found on the host interfaces", version)
}
