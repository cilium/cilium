// Copyright 2017 Authors of Cilium
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

package ip

import (
	"bytes"
	"fmt"
	"net"
	"sort"
)

const (
	ipv4BitLen = 8 * net.IPv4len
	ipv6BitLen = 8 * net.IPv6len
)

// NetsByMask is used to sort a list of IP networks by the size of their masks.
// Implements sort.Interface.
type NetsByMask []*net.IPNet

func (s NetsByMask) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s NetsByMask) Less(i, j int) bool {
	iPrefixSize, _ := s[i].Mask.Size()
	jPrefixSize, _ := s[j].Mask.Size()
	if iPrefixSize == jPrefixSize {
		byteArrComp := bytes.Compare(s[i].IP, s[j].IP)
		if byteArrComp < 0 {
			return true
		}
		return false
	}
	return iPrefixSize < jPrefixSize
}

func (s NetsByMask) Len() int {
	return len(s)
}

// Assert that NetsByMask implements sort.Interface.
var _ sort.Interface = NetsByMask{}

// RemoveCIDRs removes the specified CIDRs from another set of CIDRs. If a CIDR to remove is not
// contained within the CIDR, the CIDR to remove is ignored. A slice of CIDRs is
// returned which contains the set of CIDRs provided minus the set of CIDRs which
// were removed. Both input slices may be modified by calling this function.
func RemoveCIDRs(allowCIDRs, removeCIDRs []*net.IPNet) ([]*net.IPNet, error) {

	// Ensure that we iterate through the provided CIDRs in order of largest
	// subnet first.
	sort.Sort(NetsByMask(removeCIDRs))

PreLoop:
	// Remove CIDRs which are contained within CIDRs that we want to remove;
	// such CIDRs are redundant.
	for j, removeCIDR := range removeCIDRs {
		for i, removeCIDR2 := range removeCIDRs {
			if i == j {
				continue
			}
			if removeCIDR.Contains(removeCIDR2.IP) {
				removeCIDRs = append(removeCIDRs[:i], removeCIDRs[i+1:]...)
				// Re-trigger loop since we have modified the slice we are iterating over.
				goto PreLoop
			}
		}
	}

	for _, remove := range removeCIDRs {
	Loop:
		for i, allowCIDR := range allowCIDRs {

			// Don't allow comparison of different address spaces.
			if allowCIDR.IP.To4() != nil && remove.IP.To4() == nil ||
				allowCIDR.IP.To4() == nil && remove.IP.To4() != nil {
				return nil, fmt.Errorf("cannot mix IP addresses of different IP protocol versions")
			}

			// Only remove CIDR if it is contained in the subnet we are allowing.
			if allowCIDR.Contains(remove.IP.Mask(remove.Mask)) {
				nets, err := removeCIDR(allowCIDR, remove)
				if err != nil {
					return nil, err
				}

				// Remove CIDR that we have just processed and append new CIDRs
				// that we computed from removing the CIDR to remove.
				allowCIDRs = append(allowCIDRs[:i], allowCIDRs[i+1:]...)
				allowCIDRs = append(allowCIDRs, nets...)
				goto Loop
			} else if remove.Contains(allowCIDR.IP.Mask(allowCIDR.Mask)) {
				// If a CIDR that we want to remove contains a CIDR in the list
				// that is allowed, then we can just remove the CIDR to allow.
				allowCIDRs = append(allowCIDRs[:i], allowCIDRs[i+1:]...)
				goto Loop
			}
		}
	}

	return allowCIDRs, nil
}

func getNetworkPrefix(ipNet *net.IPNet) *net.IP {
	var mask net.IP

	if ipNet.IP.To4() == nil {
		mask = make(net.IP, net.IPv6len)
		for i := 0; i < len(ipNet.Mask); i++ {
			mask[net.IPv6len-i-1] = ipNet.IP[net.IPv6len-i-1] & ^ipNet.Mask[i]
		}
	} else {
		mask = make(net.IP, net.IPv4len)
		for i := 0; i < net.IPv4len; i++ {
			mask[net.IPv4len-i-1] = ipNet.IP[net.IPv6len-i-1] & ^ipNet.Mask[i]
		}
	}

	return &mask
}

func removeCIDR(allowCIDR, removeCIDR *net.IPNet) ([]*net.IPNet, error) {
	var allows []*net.IPNet
	var allowIsIpv4, removeIsIpv4 bool
	var allowBitLen int

	if allowCIDR.IP.To4() != nil {
		allowIsIpv4 = true
		allowBitLen = ipv4BitLen
	} else {
		allowBitLen = ipv6BitLen
	}

	if removeCIDR.IP.To4() != nil {
		removeIsIpv4 = true
	}

	if removeIsIpv4 != allowIsIpv4 {
		return nil, fmt.Errorf("cannot mix IP addresses of different IP protocol versions")
	}

	// Get size of each CIDR mask.
	allowSize, _ := allowCIDR.Mask.Size()
	removeSize, _ := removeCIDR.Mask.Size()

	if allowSize >= removeSize {
		return nil, fmt.Errorf("allow CIDR prefix must be a superset of " +
			"remove CIDR prefix")
	}

	allowFirstIPMasked := allowCIDR.IP.Mask(allowCIDR.Mask)
	removeFirstIPMasked := removeCIDR.IP.Mask(removeCIDR.Mask)

	ipv4Ipv6Slice := []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff}

	// Convert to IPv4 in IPv6 addresses if needed.
	if allowIsIpv4 {
		allowFirstIPMasked = append(ipv4Ipv6Slice, allowFirstIPMasked...)
	}

	if removeIsIpv4 {
		removeFirstIPMasked = append(ipv4Ipv6Slice, removeFirstIPMasked...)
	}

	allowFirstIP := &allowFirstIPMasked
	removeFirstIP := &removeFirstIPMasked

	// Create CIDR prefixes with mask size of Y+1, Y+2 ... X where Y is the mask
	// length of the CIDR prefix B from which we are excluding a CIDR prefix A
	// with mask length X.
	for i := (allowBitLen - allowSize - 1); i >= (allowBitLen - removeSize); i-- {
		// The mask for each CIDR prefix is simply the ith bit flipped, and then
		// zero'ing out all subsequent bits (the host identifier part of the
		// prefix).
		newMaskSize := allowBitLen - i
		newIP := (*net.IP)(flipNthBit((*[]byte)(removeFirstIP), uint(i)))
		for k := range *allowFirstIP {
			(*newIP)[k] = (*allowFirstIP)[k] | (*newIP)[k]
		}

		newMask := net.CIDRMask(newMaskSize, allowBitLen)
		newIPMasked := newIP.Mask(newMask)

		newIPNet := net.IPNet{IP: newIPMasked, Mask: newMask}
		allows = append(allows, &newIPNet)
	}

	return allows, nil
}

func getByteIndexOfBit(bit uint) uint {
	return net.IPv6len - (bit / 8) - 1
}

func getNthBit(ip *net.IP, bitNum uint) uint8 {
	byteNum := getByteIndexOfBit(bitNum)
	bits := (*ip)[byteNum]
	b := uint8(bits)
	return b >> (bitNum % 8) & 1
}

func flipNthBit(ip *[]byte, bitNum uint) *[]byte {
	ipCopy := make([]byte, len(*ip))
	copy(ipCopy, *ip)
	byteNum := getByteIndexOfBit(bitNum)
	ipCopy[byteNum] = ipCopy[byteNum] ^ 1<<(bitNum%8)

	return &ipCopy
}
