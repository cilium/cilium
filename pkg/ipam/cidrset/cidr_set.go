// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
// Copyright The Kubernetes Authors.

package cidrset

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"math/bits"
	"net/netip"

	"go4.org/netipx"

	"github.com/cilium/cilium/pkg/lock"
)

// CidrSet manages a set of CIDR ranges from which blocks of IPs can
// be allocated from.
type CidrSet struct {
	lock.Mutex
	// clusterPrefix is the CIDR assigned to the cluster.
	clusterPrefix netip.Prefix
	// nodeMaskSize is the mask size, in bits, assigned to the nodes
	nodeMaskSize int
	// maxCIDRs is the maximum number of CIDRs that can be allocated
	maxCIDRs int
	// allocatedCIDRs counts the number of CIDRs allocated
	allocatedCIDRs int
	// nextCandidate points to the next CIDR that should be free
	nextCandidate int
	// used is a bitmap used to track the CIDRs allocated
	used big.Int
}

const (
	// The subnet mask size cannot be greater than 16 more than the cluster mask size
	// TODO: https://github.com/kubernetes/kubernetes/issues/44918
	// clusterSubnetMaxDiff limited to 16 due to the uncompressed bitmap
	// Due to this limitation the subnet mask for IPv6 cluster cidr needs to be >= 48
	// as default mask size for IPv6 is 64.
	clusterSubnetMaxDiff = 16
	// halfIPv6Bytes is the half of the IPv6 byte length.
	halfIPv6Bytes = 8
	// ipv6Bits is the total number of bits in an IPv6 address.
	ipv6Bits = 128
	// the default subnet mask should be lower or equal to the max ipv4 netmask
	maxSubNetMaskSizeIPv4 = 32
	// the default subnet mask should be lower or equal to the max ipv6 netmask
	maxSubNetMaskSizeIPv6 = 128
)

var (
	// ErrCIDRRangeNoCIDRsRemaining occurs when there is no more space
	// to allocate CIDR ranges.
	ErrCIDRRangeNoCIDRsRemaining = errors.New(
		"CIDR allocation failed; there are no remaining CIDRs left to allocate in the accepted range")
	// ErrCIDRSetSubNetTooBig occurs when the subnet mask size is too
	// big compared to the CIDR mask size.
	ErrCIDRSetSubNetTooBig = errors.New(
		"New CIDR set failed; the node CIDR size is too big")
	// ErrSubNetMaskSizeInvalid occurs when the subnet mask size  is invalid:
	// bigger than 32 for IPv4 and bigger than 128 for IPv6
	ErrSubNetMaskSizeInvalid = fmt.Errorf(
		"SubNetMask is invalid, should be lower or equal to %d for IPv4 and to %d for IPv6",
		maxSubNetMaskSizeIPv4, maxSubNetMaskSizeIPv6)
)

// NewCIDRSet creates a new CidrSet.
func NewCIDRSet(clusterPrefix netip.Prefix, subNetMaskSize int) (*CidrSet, error) {
	clusterPrefix = clusterPrefix.Masked()
	clusterMaskSize := clusterPrefix.Bits()

	if clusterPrefix.Addr().Is6() {
		if subNetMaskSize > maxSubNetMaskSizeIPv6 {
			return nil, ErrSubNetMaskSizeInvalid
		}
		if subNetMaskSize-clusterMaskSize > clusterSubnetMaxDiff {
			return nil, ErrCIDRSetSubNetTooBig
		}
	} else if subNetMaskSize > maxSubNetMaskSizeIPv4 {
		return nil, ErrSubNetMaskSizeInvalid
	}
	maxCIDRs := 1 << uint32(subNetMaskSize-clusterMaskSize)
	return &CidrSet{
		clusterPrefix: clusterPrefix,
		maxCIDRs:      maxCIDRs,
		nodeMaskSize:  subNetMaskSize,
	}, nil
}

func (s *CidrSet) String() string {
	return fmt.Sprintf("clusterCIDR: %s, nodeMask: %d", s.clusterPrefix, s.nodeMaskSize)
}

func (s *CidrSet) indexToCIDRBlock(index int) netip.Prefix {
	if s.clusterPrefix.Addr().Is4() {
		clusterBytes := s.clusterPrefix.Addr().As4()
		j := uint32(index) << uint32(32-s.nodeMaskSize)
		ipInt := binary.BigEndian.Uint32(clusterBytes[:]) | j
		var ipBytes [4]byte
		binary.BigEndian.PutUint32(ipBytes[:], ipInt)
		return netip.PrefixFrom(netip.AddrFrom4(ipBytes), s.nodeMaskSize)
	}

	// leftClusterIP      |     rightClusterIP
	// 2001:0DB8:1234:0000:0000:0000:0000:0000
	const halfV6NBits = ipv6Bits / 2
	clusterBytes := s.clusterPrefix.Addr().As16()
	leftClusterIP := binary.BigEndian.Uint64(clusterBytes[:halfIPv6Bytes])
	rightClusterIP := binary.BigEndian.Uint64(clusterBytes[halfIPv6Bytes:])

	if s.nodeMaskSize <= halfV6NBits {
		// We only care about left side IP
		leftClusterIP |= uint64(index) << uint(halfV6NBits-s.nodeMaskSize)
	} else {
		if s.clusterPrefix.Bits() < halfV6NBits {
			// see how many bits are needed to reach the left side
			btl := uint(s.nodeMaskSize - halfV6NBits)
			indexMaxBit := uint(64 - bits.LeadingZeros64(uint64(index)))
			if indexMaxBit > btl {
				leftClusterIP |= uint64(index) >> btl
			}
		}
		// the right side will be calculated the same way either the
		// subNetMaskSize affects both left and right sides
		rightClusterIP |= uint64(index) << uint(ipv6Bits-s.nodeMaskSize)
	}

	var ipBytes [16]byte
	binary.BigEndian.PutUint64(ipBytes[:halfIPv6Bytes], leftClusterIP)
	binary.BigEndian.PutUint64(ipBytes[halfIPv6Bytes:], rightClusterIP)
	return netip.PrefixFrom(netip.AddrFrom16(ipBytes), s.nodeMaskSize)
}

// IsFull returns true if CidrSet does not have any more available CIDRs.
func (s *CidrSet) IsFull() bool {
	s.Lock()
	defer s.Unlock()
	return s.allocatedCIDRs == s.maxCIDRs
}

// AllocateNext allocates the next free CIDR range. This will set the range
// as occupied and return the allocated range.
func (s *CidrSet) AllocateNext() (netip.Prefix, error) {
	s.Lock()
	defer s.Unlock()

	if s.allocatedCIDRs == s.maxCIDRs {
		return netip.Prefix{}, ErrCIDRRangeNoCIDRsRemaining
	}
	candidate := s.nextCandidate
	for range s.maxCIDRs {
		if s.used.Bit(candidate) == 0 {
			break
		}
		candidate = (candidate + 1) % s.maxCIDRs
	}

	s.nextCandidate = (candidate + 1) % s.maxCIDRs
	s.used.SetBit(&s.used, candidate, 1)
	s.allocatedCIDRs++

	return s.indexToCIDRBlock(candidate), nil
}

// InRange returns true if the given prefix is inside the range of the allocatable
// CidrSet.
func (s *CidrSet) InRange(prefix netip.Prefix) bool {
	return s.clusterPrefix.Contains(prefix.Addr()) || prefix.Contains(s.clusterPrefix.Addr())
}

// IsClusterCIDR returns true if the given prefix is equal to this CidrSet's cluster CIDR.
func (s *CidrSet) IsClusterCIDR(prefix netip.Prefix) bool {
	return prefix == s.clusterPrefix
}

// Prefix returns the CidrSet's prefix.
func (s *CidrSet) Prefix() netip.Prefix {
	return s.clusterPrefix
}

func (s *CidrSet) getBeginningAndEndIndices(prefix netip.Prefix) (begin, end int, err error) {
	begin, end = 0, s.maxCIDRs-1

	if !s.InRange(prefix) {
		return -1, -1, fmt.Errorf("cidr %v is out the range of cluster cidr %v", prefix, s.clusterPrefix)
	}

	if s.clusterPrefix.Bits() < prefix.Bits() {
		// Align the prefix start to node-level granularity.
		beginAddr := netip.PrefixFrom(prefix.Addr(), s.nodeMaskSize).Masked().Addr()
		begin, err = s.getIndexForAddr(beginAddr)
		if err != nil {
			return -1, -1, err
		}

		// Compute the last address of the prefix, then align to node-level.
		endAddr := netipx.PrefixLastIP(prefix)
		endAddr = netip.PrefixFrom(endAddr, s.nodeMaskSize).Masked().Addr()
		end, err = s.getIndexForAddr(endAddr)
		if err != nil {
			return -1, -1, err
		}
	}
	return begin, end, nil
}

// IsAllocated verifies if the given prefix is allocated.
func (s *CidrSet) IsAllocated(prefix netip.Prefix) (bool, error) {
	begin, end, err := s.getBeginningAndEndIndices(prefix)
	if err != nil {
		return false, err
	}
	s.Lock()
	defer s.Unlock()
	for i := begin; i <= end; i++ {
		if s.used.Bit(i) == 0 {
			return false, nil
		}
	}
	return true, nil
}

// Release releases the given prefix range.
func (s *CidrSet) Release(prefix netip.Prefix) error {
	begin, end, err := s.getBeginningAndEndIndices(prefix)
	if err != nil {
		return err
	}
	s.Lock()
	defer s.Unlock()
	for i := begin; i <= end; i++ {
		// Only change the counters if we change the bit to prevent
		// double counting.
		if s.used.Bit(i) != 0 {
			s.used.SetBit(&s.used, i, 0)
			s.allocatedCIDRs--
		}
	}
	return nil
}

// Occupy marks the given prefix range as used. Occupy succeeds even if the prefix
// range was previously used.
func (s *CidrSet) Occupy(prefix netip.Prefix) (err error) {
	begin, end, err := s.getBeginningAndEndIndices(prefix)
	if err != nil {
		return err
	}
	s.Lock()
	defer s.Unlock()
	for i := begin; i <= end; i++ {
		// Only change the counters if we change the bit to prevent
		// double counting.
		if s.used.Bit(i) == 0 {
			s.used.SetBit(&s.used, i, 1)
			s.allocatedCIDRs++
		}
	}

	return nil
}

func (s *CidrSet) getIndexForAddr(addr netip.Addr) (int, error) {
	if addr.Is4() {
		clusterBytes := s.clusterPrefix.Addr().As4()
		addrBytes := addr.As4()
		cidrIndex := (binary.BigEndian.Uint32(clusterBytes[:]) ^ binary.BigEndian.Uint32(addrBytes[:])) >> uint32(32-s.nodeMaskSize)
		if cidrIndex >= uint32(s.maxCIDRs) {
			return 0, fmt.Errorf("CIDR: %v/%v is out of the range of CIDR allocator", addr, s.nodeMaskSize)
		}
		return int(cidrIndex), nil
	}
	clusterBytes := s.clusterPrefix.Addr().As16()
	addrBytes := addr.As16()
	bigIP := big.NewInt(0).SetBytes(clusterBytes[:])
	bigIP = bigIP.Xor(bigIP, big.NewInt(0).SetBytes(addrBytes[:]))
	cidrIndexBig := bigIP.Rsh(bigIP, uint(ipv6Bits-s.nodeMaskSize))
	cidrIndex := cidrIndexBig.Uint64()
	if cidrIndex >= uint64(s.maxCIDRs) {
		return 0, fmt.Errorf("CIDR: %v/%v is out of the range of CIDR allocator", addr, s.nodeMaskSize)
	}
	return int(cidrIndex), nil
}
