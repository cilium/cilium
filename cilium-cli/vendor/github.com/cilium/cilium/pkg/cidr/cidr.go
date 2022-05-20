// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cidr

import (
	"bytes"
	"fmt"
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

// RemoveAll removes all cidrs specified in 'toRemove' from 'ipNets'. ipNets
// is clobbered (to ensure removed CIDRs can be garbage collected) and
// must not be used after this function has been called.
// Example usage:
//   cidrs = cidr.RemoveAll(cidrs, toRemove)
func RemoveAll(ipNets, toRemove []*net.IPNet) []*net.IPNet {
	newIPNets := ipNets[:0]
	for _, n := range ipNets {
		if !Contains(toRemove, n) {
			newIPNets = append(newIPNets, n)
		}
	}
	for i := len(newIPNets); i < len(ipNets); i++ {
		ipNets[i] = nil // or the zero value of T
	}
	return newIPNets
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
