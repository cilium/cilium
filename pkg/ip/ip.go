// Copyright 2017-2020 Authors of Cilium
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
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"sort"
)

const (
	ipv4BitLen = 8 * net.IPv4len
	ipv6BitLen = 8 * net.IPv6len
)

// CountIPsInCIDR takes a RFC4632/RFC4291-formatted IPv4/IPv6 CIDR and
// determines how many IP addresses reside within that CIDR.
// Returns 0 if the input CIDR cannot be parsed.
func CountIPsInCIDR(ipnet *net.IPNet) *big.Int {
	subnet, size := ipnet.Mask.Size()
	if subnet == size {
		return big.NewInt(1)
	}
	return big.NewInt(0).
		Sub(
			big.NewInt(2).Exp(big.NewInt(2),
				big.NewInt(int64(size-subnet)), nil),
			big.NewInt(1),
		)
}

var (
	// v4Mappedv6Prefix is the RFC2765 IPv4-mapped address prefix.
	v4Mappedv6Prefix  = []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff}
	ipv4LeadingZeroes = []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
	defaultIPv4       = []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0x0, 0x0, 0x0, 0x0}
	defaultIPv6       = []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
	upperIPv4         = []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 255, 255, 255, 255}
	upperIPv6         = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
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
		return bytes.Compare(s[i].IP, s[j].IP) < 0
	}
	return iPrefixSize < jPrefixSize
}

func (s NetsByMask) Len() int {
	return len(s)
}

// Assert that NetsByMask implements sort.Interface.
var _ sort.Interface = NetsByMask{}
var _ sort.Interface = NetsByRange{}

// NetsByRange is used to sort a list of ranges, first by their last IPs, then by
// their first IPs
// Implements sort.Interface.
type NetsByRange []*netWithRange

func (s NetsByRange) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s NetsByRange) Less(i, j int) bool {
	// First compare by last IP.
	lastComparison := bytes.Compare(*s[i].Last, *s[j].Last)
	if lastComparison < 0 {
		return true
	} else if lastComparison > 0 {
		return false
	}

	// Then compare by first IP.
	firstComparison := bytes.Compare(*s[i].First, *s[i].First)
	if firstComparison < 0 {
		return true
	} else if firstComparison > 0 {
		return false
	}

	// First and last IPs are the same, so thus are equal, and s[i]
	// is not less than s[j].
	return false
}

func (s NetsByRange) Len() int {
	return len(s)
}

// RemoveCIDRs removes the specified CIDRs from another set of CIDRs. If a CIDR
// to remove is not contained within the CIDR, the CIDR to remove is ignored. A
// slice of CIDRs is returned which contains the set of CIDRs provided minus
// the set of CIDRs which  were removed. Both input slices may be modified by
// calling this function.
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

	// Convert to IPv4 in IPv6 addresses if needed.
	if allowIsIpv4 {
		allowFirstIPMasked = append(v4Mappedv6Prefix, allowFirstIPMasked...)
	}

	if removeIsIpv4 {
		removeFirstIPMasked = append(v4Mappedv6Prefix, removeFirstIPMasked...)
	}

	allowFirstIP := &allowFirstIPMasked
	removeFirstIP := &removeFirstIPMasked

	// Create CIDR prefixes with mask size of Y+1, Y+2 ... X where Y is the mask
	// length of the CIDR prefix B from which we are excluding a CIDR prefix A
	// with mask length X.
	allows := make([]*net.IPNet, 0, removeSize-allowSize)
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

func ipNetToRange(ipNet net.IPNet) netWithRange {
	firstIP := make(net.IP, len(ipNet.IP))
	lastIP := make(net.IP, len(ipNet.IP))

	copy(firstIP, ipNet.IP)
	copy(lastIP, ipNet.IP)

	firstIP = firstIP.Mask(ipNet.Mask)
	lastIP = lastIP.Mask(ipNet.Mask)

	if firstIP.To4() != nil {
		firstIP = append(v4Mappedv6Prefix, firstIP...)
		lastIP = append(v4Mappedv6Prefix, lastIP...)
	}

	lastIPMask := make(net.IPMask, len(ipNet.Mask))
	copy(lastIPMask, ipNet.Mask)
	for i := range lastIPMask {
		lastIPMask[len(lastIPMask)-i-1] = ^lastIPMask[len(lastIPMask)-i-1]
		lastIP[net.IPv6len-i-1] = lastIP[net.IPv6len-i-1] | lastIPMask[len(lastIPMask)-i-1]
	}

	return netWithRange{First: &firstIP, Last: &lastIP, Network: &ipNet}
}

func getPreviousIP(ip net.IP) net.IP {
	// Cannot go lower than zero!
	if ip.Equal(net.IP(defaultIPv4)) || ip.Equal(net.IP(defaultIPv6)) {
		return ip
	}

	previousIP := make(net.IP, len(ip))
	copy(previousIP, ip)

	var overflow bool
	var lowerByteBound int
	if ip.To4() != nil {
		lowerByteBound = net.IPv6len - net.IPv4len
	} else {
		lowerByteBound = 0
	}
	for i := len(ip) - 1; i >= lowerByteBound; i-- {
		if overflow || i == len(ip)-1 {
			previousIP[i]--
		}
		// Track if we have overflowed and thus need to continue subtracting.
		if ip[i] == 0 && previousIP[i] == 255 {
			overflow = true
		} else {
			overflow = false
		}
	}
	return previousIP
}

// GetNextIP returns the next IP from the given IP address. If the given IP is
// the last IP of a v4 or v6 range, the same IP is returned.
func GetNextIP(ip net.IP) net.IP {
	if ip.Equal(upperIPv4) || ip.Equal(upperIPv6) {
		return ip
	}

	nextIP := make(net.IP, len(ip))
	switch len(ip) {
	case net.IPv4len:
		ipU32 := binary.BigEndian.Uint32(ip)
		ipU32++
		binary.BigEndian.PutUint32(nextIP, ipU32)
		return nextIP
	case net.IPv6len:
		ipU64 := binary.BigEndian.Uint64(ip[net.IPv6len/2:])
		ipU64++
		binary.BigEndian.PutUint64(nextIP[net.IPv6len/2:], ipU64)
		if ipU64 == 0 {
			ipU64 = binary.BigEndian.Uint64(ip[:net.IPv6len/2])
			ipU64++
			binary.BigEndian.PutUint64(nextIP[:net.IPv6len/2], ipU64)
		} else {
			copy(nextIP[:net.IPv6len/2], ip[:net.IPv6len/2])
		}
		return nextIP
	default:
		return ip
	}
}

func createSpanningCIDR(r netWithRange) net.IPNet {
	// Don't want to modify the values of the provided range, so make copies.
	lowest := *r.First
	highest := *r.Last

	var isIPv4 bool
	var spanningMaskSize, bitLen, byteLen int
	if lowest.To4() != nil {
		isIPv4 = true
		bitLen = ipv4BitLen
		byteLen = net.IPv4len
	} else {
		bitLen = ipv6BitLen
		byteLen = net.IPv6len
	}

	if isIPv4 {
		spanningMaskSize = ipv4BitLen
	} else {
		spanningMaskSize = ipv6BitLen
	}

	// Convert to big Int so we can easily do bitshifting on the IP addresses,
	// since golang only provides up to 64-bit unsigned integers.
	lowestBig := big.NewInt(0).SetBytes(lowest)
	highestBig := big.NewInt(0).SetBytes(highest)

	// Starting from largest mask / smallest range possible, apply a mask one bit
	// larger in each iteration to the upper bound in the range  until we have
	// masked enough to pass the lower bound in the range. This
	// gives us the size of the prefix for the spanning CIDR to return as
	// well as the IP for the CIDR prefix of the spanning CIDR.
	for spanningMaskSize > 0 && lowestBig.Cmp(highestBig) < 0 {
		spanningMaskSize--
		mask := big.NewInt(1)
		mask = mask.Lsh(mask, uint(bitLen-spanningMaskSize))
		mask = mask.Mul(mask, big.NewInt(-1))
		highestBig = highestBig.And(highestBig, mask)
	}

	// If ipv4, need to append 0s because math.Big gets rid of preceding zeroes.
	if isIPv4 {
		highest = append(ipv4LeadingZeroes, highestBig.Bytes()...)
	} else {
		highest = highestBig.Bytes()
	}

	// Int does not store leading zeroes.
	if len(highest) == 0 {
		highest = make([]byte, byteLen)
	}

	newNet := net.IPNet{IP: highest, Mask: net.CIDRMask(spanningMaskSize, bitLen)}
	return newNet
}

type netWithRange struct {
	First   *net.IP
	Last    *net.IP
	Network *net.IPNet
}

func mergeAdjacentCIDRs(ranges []*netWithRange) []*netWithRange {
	// Sort the ranges. This sorts first by the last IP, then first IP, then by
	// the IP network in the list itself
	sort.Sort(NetsByRange(ranges))

	// Merge adjacent CIDRs if possible.
	for i := len(ranges) - 1; i > 0; i-- {
		first1 := getPreviousIP(*ranges[i].First)

		// Since the networks are sorted, we know that if a network in the list
		// is adjacent to another one in the list, it will be the network next
		// to it in the list. If the previous IP of the current network we are
		// processing overlaps with the last IP of the previous network in the
		// list, then we can merge the two ranges together.
		if bytes.Compare(first1, *ranges[i-1].Last) <= 0 {
			// Pick the minimum of the first two IPs to represent the start
			// of the new range.
			var minFirstIP *net.IP
			if bytes.Compare(*ranges[i-1].First, *ranges[i].First) < 0 {
				minFirstIP = ranges[i-1].First
			} else {
				minFirstIP = ranges[i].First
			}

			// Always take the last IP of the ith IP.
			newRangeLast := make(net.IP, len(*ranges[i].Last))
			copy(newRangeLast, *ranges[i].Last)

			newRangeFirst := make(net.IP, len(*minFirstIP))
			copy(newRangeFirst, *minFirstIP)

			// Can't set the network field because since we are combining a
			// range of IPs, and we don't yet know what CIDR prefix(es) represent
			// the new range.
			ranges[i-1] = &netWithRange{First: &newRangeFirst, Last: &newRangeLast, Network: nil}

			// Since we have combined ranges[i] with the preceding item in the
			// ranges list, we can delete ranges[i] from the slice.
			ranges = append(ranges[:i], ranges[i+1:]...)
		}
	}
	return ranges
}

// coalesceRanges converts ranges into an equivalent list of net.IPNets.
// All IPs in ranges should be of the same address family (IPv4 or IPv6).
func coalesceRanges(ranges []*netWithRange) []*net.IPNet {
	coalescedCIDRs := []*net.IPNet{}
	// Create CIDRs from ranges that were combined if needed.
	for _, netRange := range ranges {
		// If the Network field of netWithRange wasn't modified, then we can
		// add it to the list which we will return, as it cannot be joined with
		// any other CIDR in the list.
		if netRange.Network != nil {
			coalescedCIDRs = append(coalescedCIDRs, netRange.Network)
		} else {
			// We have joined two ranges together, so we need to find the new CIDRs
			// that represent this range.
			rangeCIDRs := rangeToCIDRs(*netRange.First, *netRange.Last)
			coalescedCIDRs = append(coalescedCIDRs, rangeCIDRs...)
		}
	}

	return coalescedCIDRs
}

// CoalesceCIDRs transforms the provided list of CIDRs into the most-minimal
// equivalent set of IPv4 and IPv6 CIDRs.
// It removes CIDRs that are subnets of other CIDRs in the list, and groups
// together CIDRs that have the same mask size into a CIDR of the same mask
// size provided that they share the same number of most significant
// mask-size bits.
//
// Note: this algorithm was ported from the Python library netaddr.
// https://github.com/drkjam/netaddr .
func CoalesceCIDRs(cidrs []*net.IPNet) ([]*net.IPNet, []*net.IPNet) {

	ranges4 := []*netWithRange{}
	ranges6 := []*netWithRange{}

	for _, network := range cidrs {
		newNetToRange := ipNetToRange(*network)
		if network.IP.To4() != nil {
			ranges4 = append(ranges4, &newNetToRange)
		} else {
			ranges6 = append(ranges6, &newNetToRange)
		}
	}

	return coalesceRanges(mergeAdjacentCIDRs(ranges4)), coalesceRanges(mergeAdjacentCIDRs(ranges6))
}

// rangeToCIDRs converts the range of IPs covered by firstIP and lastIP to
// a list of CIDRs that contains all of the IPs covered by the range.
func rangeToCIDRs(firstIP, lastIP net.IP) []*net.IPNet {

	// First, create a CIDR that spans both IPs.
	spanningCIDR := createSpanningCIDR(netWithRange{&firstIP, &lastIP, nil})
	spanningRange := ipNetToRange(spanningCIDR)
	firstIPSpanning := spanningRange.First
	lastIPSpanning := spanningRange.Last

	cidrList := []*net.IPNet{}

	// If the first IP of the spanning CIDR passes the lower bound (firstIP),
	// we need to split the spanning CIDR and only take the IPs that are
	// greater than the value which we split on, as we do not want the lesser
	// values since they are less than the lower-bound (firstIP).
	if bytes.Compare(*firstIPSpanning, firstIP) < 0 {
		// Split on the previous IP of the first IP so that the right list of IPs
		// of the partition includes the firstIP.
		prevFirstRangeIP := getPreviousIP(firstIP)
		var bitLen int
		if prevFirstRangeIP.To4() != nil {
			bitLen = ipv4BitLen
		} else {
			bitLen = ipv6BitLen
		}
		_, _, right := partitionCIDR(spanningCIDR, net.IPNet{IP: prevFirstRangeIP, Mask: net.CIDRMask(bitLen, bitLen)})

		// Append all CIDRs but the first, as this CIDR includes the upper
		// bound of the spanning CIDR, which we still need to partition on.
		cidrList = append(cidrList, right...)
		spanningCIDR = *right[0]
		cidrList = cidrList[1:]
	}

	// Conversely, if the last IP of the spanning CIDR passes the upper bound
	// (lastIP), we need to split the spanning CIDR and only take the IPs that
	// are greater than the value which we split on, as we do not want the greater
	// values since they are greater than the upper-bound (lastIP).
	if bytes.Compare(*lastIPSpanning, lastIP) > 0 {
		// Split on the next IP of the last IP so that the left list of IPs
		// of the partition include the lastIP.
		nextFirstRangeIP := GetNextIP(lastIP)
		var bitLen int
		if nextFirstRangeIP.To4() != nil {
			bitLen = ipv4BitLen
		} else {
			bitLen = ipv6BitLen
		}
		left, _, _ := partitionCIDR(spanningCIDR, net.IPNet{IP: nextFirstRangeIP, Mask: net.CIDRMask(bitLen, bitLen)})
		cidrList = append(cidrList, left...)
	} else {
		// Otherwise, there is no need to partition; just use add the spanning
		// CIDR to the list of networks.
		cidrList = append(cidrList, &spanningCIDR)
	}
	return cidrList
}

// partitionCIDR returns a list of IP Networks partitioned upon excludeCIDR.
// The first list contains the networks to the left of the excludeCIDR in the
// partition,  the second is a list containing the excludeCIDR itself if it is
// contained within the targetCIDR (nil otherwise), and the
// third is a list containing the networks to the right of the excludeCIDR in
// the partition.
func partitionCIDR(targetCIDR net.IPNet, excludeCIDR net.IPNet) ([]*net.IPNet, []*net.IPNet, []*net.IPNet) {
	var targetIsIPv4 bool
	if targetCIDR.IP.To4() != nil {
		targetIsIPv4 = true
	}

	targetIPRange := ipNetToRange(targetCIDR)
	excludeIPRange := ipNetToRange(excludeCIDR)

	targetFirstIP := *targetIPRange.First
	targetLastIP := *targetIPRange.Last

	excludeFirstIP := *excludeIPRange.First
	excludeLastIP := *excludeIPRange.Last

	targetMaskSize, _ := targetCIDR.Mask.Size()
	excludeMaskSize, _ := excludeCIDR.Mask.Size()

	if bytes.Compare(excludeLastIP, targetFirstIP) < 0 {
		return nil, nil, []*net.IPNet{&targetCIDR}
	} else if bytes.Compare(targetLastIP, excludeFirstIP) < 0 {
		return []*net.IPNet{&targetCIDR}, nil, nil
	}

	if targetMaskSize >= excludeMaskSize {
		return nil, []*net.IPNet{&targetCIDR}, nil
	}

	left := []*net.IPNet{}
	right := []*net.IPNet{}

	newPrefixLen := targetMaskSize + 1

	targetFirstCopy := make(net.IP, len(targetFirstIP))
	copy(targetFirstCopy, targetFirstIP)

	iLowerOld := make(net.IP, len(targetFirstCopy))
	copy(iLowerOld, targetFirstCopy)

	// Since golang only supports up to unsigned 64-bit integers, and we need
	// to perform addition on addresses, use math/big library, which allows
	// for manipulation of large integers.

	// Used to track the current lower and upper bounds of the ranges to compare
	// to excludeCIDR.
	iLower := big.NewInt(0)
	iUpper := big.NewInt(0)
	iLower = iLower.SetBytes(targetFirstCopy)

	var bitLen int

	if targetIsIPv4 {
		bitLen = ipv4BitLen
	} else {
		bitLen = ipv6BitLen
	}
	shiftAmount := (uint)(bitLen - newPrefixLen)

	targetIPInt := big.NewInt(0)
	targetIPInt.SetBytes(targetFirstIP.To16())

	exp := big.NewInt(0)

	// Use left shift for exponentiation
	exp = exp.Lsh(big.NewInt(1), shiftAmount)
	iUpper = iUpper.Add(targetIPInt, exp)

	matched := big.NewInt(0)

	for excludeMaskSize >= newPrefixLen {
		// Append leading zeros to IPv4 addresses, as math.Big.Int does not
		// append them when the IP address is copied from a byte array to
		// math.Big.Int. Leading zeroes are required for parsing IPv4 addresses
		// for use with net.IP / net.IPNet.
		var iUpperBytes, iLowerBytes []byte
		if targetIsIPv4 {
			iUpperBytes = append(ipv4LeadingZeroes, iUpper.Bytes()...)
			iLowerBytes = append(ipv4LeadingZeroes, iLower.Bytes()...)
		} else {
			iUpperBytesLen := len(iUpper.Bytes())
			// Make sure that the number of bytes in the array matches what net
			// package expects, as big package doesn't append leading zeroes.
			if iUpperBytesLen != net.IPv6len {
				numZeroesToAppend := net.IPv6len - iUpperBytesLen
				zeroBytes := make([]byte, numZeroesToAppend)
				iUpperBytes = append(zeroBytes, iUpper.Bytes()...)
			} else {
				iUpperBytes = iUpper.Bytes()

			}

			iLowerBytesLen := len(iLower.Bytes())
			if iLowerBytesLen != net.IPv6len {
				numZeroesToAppend := net.IPv6len - iLowerBytesLen
				zeroBytes := make([]byte, numZeroesToAppend)
				iLowerBytes = append(zeroBytes, iLower.Bytes()...)
			} else {
				iLowerBytes = iLower.Bytes()

			}
		}
		// If the IP we are excluding over is of a higher value than the current
		// CIDR prefix we are generating, add the CIDR prefix to the set of IPs
		// to the left of the exclude CIDR
		if bytes.Compare(excludeFirstIP, iUpperBytes) >= 0 {
			left = append(left, &net.IPNet{IP: iLowerBytes, Mask: net.CIDRMask(newPrefixLen, bitLen)})
			matched = matched.Set(iUpper)
		} else {
			// Same as above, but opposite.
			right = append(right, &net.IPNet{IP: iUpperBytes, Mask: net.CIDRMask(newPrefixLen, bitLen)})
			matched = matched.Set(iLower)
		}

		newPrefixLen++

		if newPrefixLen > bitLen {
			break
		}

		iLower = iLower.Set(matched)
		iUpper = iUpper.Add(matched, big.NewInt(0).Lsh(big.NewInt(1), uint(bitLen-newPrefixLen)))

	}
	excludeList := []*net.IPNet{&excludeCIDR}

	return left, excludeList, right
}

// KeepUniqueIPs transforms the provided multiset of IPs into a single set,
// lexicographically sorted via a byte-wise comparison of the IP slices (i.e.
// IPv4 addresses show up before IPv6).
// The slice is manipulated in-place destructively.
//
// 1- Sort the slice by comparing the IPs as bytes
// 2- For every unseen unique IP in the sorted slice, move it to the end of
// the return slice.
// Note that the slice is always large enough and, because it is sorted, we
// will not overwrite a valid element with another. To overwrite an element i
// with j, i must have come before j AND we decided it was a duplicate of the
// element at i-1.
func KeepUniqueIPs(ips []net.IP) []net.IP {
	sort.Slice(ips, func(i, j int) bool {
		return bytes.Compare(ips[i], ips[j]) == -1
	})

	returnIPs := ips[:0] // len==0 but cap==cap(ips)
	for readIdx, ip := range ips {
		if len(returnIPs) == 0 || !returnIPs[len(returnIPs)-1].Equal(ips[readIdx]) {
			returnIPs = append(returnIPs, ip)
		}
	}

	return returnIPs
}

var privateIPBlocks []*net.IPNet

func initPrivatePrefixes() {
	// We only care about global scope prefixes here.
	for _, cidr := range []string{
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"fc00::/7",       // IPv6 ULA
	} {
		_, block, _ := net.ParseCIDR(cidr)
		privateIPBlocks = append(privateIPBlocks, block)
	}
}

func init() {
	initPrivatePrefixes()
}

// IsExcluded returns whether a given IP is must be excluded
// due to coming from blacklisted device.
func IsExcluded(excludeList []net.IP, ip net.IP) bool {
	for _, e := range excludeList {
		if e.Equal(ip) {
			return true
		}
	}
	return false
}

// IsPublicAddr returns whether a given global IP is from
// a public range.
func IsPublicAddr(ip net.IP) bool {
	for _, block := range privateIPBlocks {
		if block.Contains(ip) {
			return false
		}
	}
	return true
}

// GetCIDRPrefixesFromIPs returns all of the ips as a slice of *net.IPNet.
func GetCIDRPrefixesFromIPs(ips []net.IP) []*net.IPNet {
	if len(ips) == 0 {
		return nil
	}
	res := make([]*net.IPNet, 0, len(ips))
	for _, ip := range ips {
		res = append(res, IPToPrefix(ip))
	}
	return res
}

// IPToPrefix returns the corresponding IPNet for the given IP.
func IPToPrefix(ip net.IP) *net.IPNet {
	bits := net.IPv6len * 8
	if ip.To4() != nil {
		ip = ip.To4()
		bits = net.IPv4len * 8
	}
	prefix := &net.IPNet{
		IP:   ip,
		Mask: net.CIDRMask(bits, bits),
	}
	return prefix
}

// IsIPv4 returns true if the given IP is an IPv4
func IsIPv4(ip net.IP) bool {
	return ip.To4() != nil
}
