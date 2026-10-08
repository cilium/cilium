// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ip

import (
	"bytes"
	"encoding/binary"
	"math/big"
	"net"
	"net/netip"
	"slices"

	"go4.org/netipx"
)

const (
	ipv4BitLen = 8 * net.IPv4len
	ipv6BitLen = 8 * net.IPv6len
)

// CountIPsInCIDR takes a RFC4632/RFC4291-formatted IPv4/IPv6 CIDR and
// determines how many IP addresses reside within that CIDR.
// The first and the last (base and broadcast) IPs are excluded.
//
// Returns 0 if the input CIDR cannot be parsed.
func CountIPsInCIDR(ipnet *net.IPNet) *big.Int {
	subnet, size := ipnet.Mask.Size()
	if subnet == size {
		return big.NewInt(0)
	}
	return big.NewInt(0).
		Sub(
			big.NewInt(2).Exp(big.NewInt(2),
				big.NewInt(int64(size-subnet)), nil),
			big.NewInt(2),
		)
}

var (
	// v4Mappedv6Prefix is the RFC2765 IPv4-mapped address prefix.
	v4Mappedv6Prefix  = []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff}
	ipv4LeadingZeroes = []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}
	upperIPv4         = []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 255, 255, 255, 255}
	upperIPv6         = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
)

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

// PrefixCeil converts the given number of IPs to the minimum number of prefixes needed to host those IPs.
// multiple indicates the number of IPs in a single prefix.
func PrefixCeil(numIPs int, multiple int) int {
	if numIPs == 0 {
		return 0
	}
	quotient := numIPs / multiple
	rem := numIPs % multiple
	if rem > 0 {
		return quotient + 1
	}
	return quotient
}

// PrefixToIps converts the given prefix to an array containing IPs in the provided
// prefix/CIDR block. When maxIPs is set to 0, the returned array will contain all IPs
// in the given prefix. Otherwise, the returned array of IPs will be limited to the
// value of maxIPs starting at the first IP in the provided CIDR. For example, when
// providing 192.168.1.0/28 as a CIDR with 4 maxIPs, 192.168.1.0, 192.168.1.1,
// 192.168.1.2, 192.168.1.3 will be returned.
func PrefixToIps(prefixCidr string, maxIPs int) ([]string, error) {
	var prefixIps []string
	_, ipNet, err := net.ParseCIDR(prefixCidr)
	if err != nil {
		return prefixIps, err
	}
	netWithRange := ipNetToRange(*ipNet)
	// Ensure last IP in the prefix is included
	for ip := *netWithRange.First; len(prefixIps) < maxIPs || maxIPs == 0; ip = getNextIP(ip) {
		prefixIps = append(prefixIps, ip.String())
		if ip.Equal(*netWithRange.Last) {
			break
		}
	}

	return prefixIps, nil
}

// getNextIP returns the next IP from the given IP address. If the given IP is
// the last IP of a v4 or v6 range, the same IP is returned.
func getNextIP(ip net.IP) net.IP {
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

type netWithRange struct {
	First   *net.IP
	Last    *net.IP
	Network *net.IPNet
}

// PartitionCIDR returns a list of IP Networks partitioned upon excludeCIDR.
// The first list contains the networks to the left of the excludeCIDR in the
// partition,  the second is a list containing the excludeCIDR itself if it is
// contained within the targetCIDR (nil otherwise), and the
// third is a list containing the networks to the right of the excludeCIDR in
// the partition.
func PartitionCIDR(targetCIDR net.IPNet, excludeCIDR net.IPNet) ([]*net.IPNet, []*net.IPNet, []*net.IPNet) {
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

// KeepUniqueAddrs transforms the provided multiset of IP addresses into a
// single set, lexicographically sorted via comparison of the addresses using
// netip.Addr.Compare (i.e. IPv4 addresses show up before IPv6).
// The slice is manipulated in-place destructively; it does not create a new slice.
func KeepUniqueAddrs(addrs []netip.Addr) []netip.Addr {
	SortAddrList(addrs)
	return slices.Compact(addrs)
}

var privateIPBlocks []*net.IPNet

func initPrivatePrefixes() {
	// We only care about global scope prefixes here.
	for _, cidr := range []string{
		"0.0.0.0/8",       // RFC1122 - IPv4 Host on this network
		"10.0.0.0/8",      // RFC1918 - IPv4 Private-Use Networks
		"100.64.0.0/10",   // RFC6598 - IPv4 Shared address space
		"127.0.0.0/8",     // RFC1122 - IPv4 Loopback
		"169.254.0.0/16",  // RFC3927 - IPv4 Link-Local
		"172.16.0.0/12",   // RFC1918 - IPv4 Private-Use Networks
		"192.0.0.0/24",    // RFC6890 - IPv4 IETF Assignments
		"192.0.2.0/24",    // RFC5737 - IPv4 TEST-NET-1
		"192.168.0.0/16",  // RFC1918 - IPv4 Private-Use Networks
		"198.18.0.0/15",   // RFC2544 - IPv4 Interconnect Benchmarks
		"198.51.100.0/24", // RFC5737 - IPv4 TEST-NET-2
		"203.0.113.0/24",  // RFC5737 - IPv4 TEST-NET-3
		"224.0.0.0/4",     // RFC5771 - IPv4 Multicast
		"::/128",          // RFC4291 - IPv6 Unspecified
		"::1/128",         // RFC4291 - IPv6 Loopback
		"100::/64",        // RFC6666 - IPv6 Discard-Only Prefix
		"2001:2::/48",     // RFC5180 - IPv6 Benchmarking
		"2001:db8::/48",   // RFC3849 - IPv6 Documentation
		"fc00::/7",        // RFC4193 - IPv6 Unique-Local
		"fe80::/10",       // RFC4291 - IPv6 Link-Local
		"ff00::/8",        // RFC4291 - IPv6 Multicast
	} {
		_, block, _ := net.ParseCIDR(cidr)
		privateIPBlocks = append(privateIPBlocks, block)
	}
}

func init() {
	initPrivatePrefixes()
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

// ListContainsIP returns whether a list of IPs contains a given IP.
func ListContainsIP(ipList []net.IP, ip net.IP) bool {
	for _, e := range ipList {
		if e.Equal(ip) {
			return true
		}
	}
	return false
}

func SortAddrList(ipList []netip.Addr) {
	slices.SortFunc(ipList, netip.Addr.Compare)
}

// AddrFromIP converts a net.IP to netip.Addr, returning the zero value for nil.
// This is useful when the net.IP may be nil (e.g., from optional configuration).
func AddrFromIP(ip net.IP) netip.Addr {
	addr, _ := netipx.FromStdIP(ip)
	return addr
}

// CompareUnMap unmap 2 addresses before comparing
func CompareUnmap(addr1, addr2 netip.Addr) int {
	return addr1.Unmap().Compare(addr2.Unmap())
}
