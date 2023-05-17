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
	"net"

	"github.com/cilium/cilium/pkg/lock"
)

// CidrSet manages a set of CIDR ranges from which blocks of IPs can
// be allocated from.
type CidrSet struct {
	lock.Mutex
	// clusterCIDR is the CIDR assigned to the cluster
	clusterCIDR *net.IPNet
	// clusterMaskSize is the mask size, in bits, assigned to the cluster
	// caches the mask size to avoid the penalty of calling clusterCIDR.Mask.Size()
	clusterMaskSize int
	// nodeMask is the network mask assigned to the nodes
	nodeMask net.IPMask
	// nodeMaskSize is the mask size, in bits,assigned to the nodes
	// caches the mask size to avoid the penalty of calling nodeMask.Size()
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
	// halfIPv6Len is the half of the IPv6 length
	halfIPv6Len = net.IPv6len / 2
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
func NewCIDRSet(clusterCIDR *net.IPNet, subNetMaskSize int) (*CidrSet, error) {
	clusterMask := clusterCIDR.Mask
	clusterMaskSize, bits := clusterMask.Size()

	if clusterCIDR.IP.To4() == nil {
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
		clusterCIDR:     clusterCIDR,
		nodeMask:        net.CIDRMask(subNetMaskSize, bits),
		clusterMaskSize: clusterMaskSize,
		maxCIDRs:        maxCIDRs,
		nodeMaskSize:    subNetMaskSize,
	}, nil
}

func (s *CidrSet) String() string {
	return fmt.Sprintf("clusterCIDR: %s, nodeMask: %d", s.clusterCIDR.String(), s.nodeMaskSize)
}

func (s *CidrSet) indexToCIDRBlock(index int) *net.IPNet {
	var ip []byte
	switch /*v4 or v6*/ {
	case s.clusterCIDR.IP.To4() != nil:
		{
			j := uint32(index) << uint32(32-s.nodeMaskSize)
			ipInt := (binary.BigEndian.Uint32(s.clusterCIDR.IP)) | j
			ip = make([]byte, net.IPv4len)
			binary.BigEndian.PutUint32(ip, ipInt)
		}
	case s.clusterCIDR.IP.To16() != nil:
		{
			// leftClusterIP      |     rightClusterIP
			// 2001:0DB8:1234:0000:0000:0000:0000:0000
			const v6NBits = 128
			const halfV6NBits = v6NBits / 2
			leftClusterIP := binary.BigEndian.Uint64(s.clusterCIDR.IP[:halfIPv6Len])
			rightClusterIP := binary.BigEndian.Uint64(s.clusterCIDR.IP[halfIPv6Len:])

			ip = make([]byte, net.IPv6len)

			if s.nodeMaskSize <= halfV6NBits {
				// We only care about left side IP
				leftClusterIP |= uint64(index) << uint(halfV6NBits-s.nodeMaskSize)
			} else {
				if s.clusterMaskSize < halfV6NBits {
					// see how many bits are needed to reach the left side
					btl := uint(s.nodeMaskSize - halfV6NBits)
					indexMaxBit := uint(64 - bits.LeadingZeros64(uint64(index)))
					if indexMaxBit > btl {
						leftClusterIP |= uint64(index) >> btl
					}
				}
				// the right side will be calculated the same way either the
				// subNetMaskSize affects both left and right sides
				rightClusterIP |= uint64(index) << uint(v6NBits-s.nodeMaskSize)
			}
			binary.BigEndian.PutUint64(ip[:halfIPv6Len], leftClusterIP)
			binary.BigEndian.PutUint64(ip[halfIPv6Len:], rightClusterIP)
		}
	}
	return &net.IPNet{
		IP:   ip,
		Mask: s.nodeMask,
	}
}

// IsFull returns true if CidrSet does not have any more available CIDRs.
func (s *CidrSet) IsFull() bool {
	s.Lock()
	defer s.Unlock()
	return s.allocatedCIDRs == s.maxCIDRs
}

// AllocateNext allocates the next free CIDR range. This will set the range
// as occupied and return the allocated range.
func (s *CidrSet) AllocateNext() (*net.IPNet, error) {
	s.Lock()
	defer s.Unlock()

	if s.allocatedCIDRs == s.maxCIDRs {
		return nil, ErrCIDRRangeNoCIDRsRemaining
	}
	candidate := s.nextCandidate
	var i int
	for i = 0; i < s.maxCIDRs; i++ {
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

// InRange returns true if the given CIDR is inside the range of the allocatable
// CidrSet.
func (s *CidrSet) InRange(cidr *net.IPNet) bool {
	return s.clusterCIDR.Contains(cidr.IP.Mask(s.clusterCIDR.Mask)) || cidr.Contains(s.clusterCIDR.IP.Mask(cidr.Mask))
}

func (s *CidrSet) getBeginningAndEndIndices(cidr *net.IPNet) (begin, end int, err error) {
	if cidr == nil {
		return -1, -1, fmt.Errorf("error getting indices for cluster cidr %v, cidr is nil", s.clusterCIDR)
	}
	begin, end = 0, s.maxCIDRs-1
	cidrMask := cidr.Mask
	maskSize, _ := cidrMask.Size()
	var ipSize int

	if !s.InRange(cidr) {
		return -1, -1, fmt.Errorf("cidr %v is out the range of cluster cidr %v", cidr, s.clusterCIDR)
	}

	if s.clusterMaskSize < maskSize {

		ipSize = net.IPv4len
		if cidr.IP.To4() == nil {
			ipSize = net.IPv6len
		}
		begin, err = s.getIndexForIP(cidr.IP.Mask(s.nodeMask))
		if err != nil {
			return -1, -1, err
		}
		ip := make([]byte, ipSize)
		if cidr.IP.To4() != nil {
			ipInt := binary.BigEndian.Uint32(cidr.IP) | (^binary.BigEndian.Uint32(cidr.Mask))
			binary.BigEndian.PutUint32(ip, ipInt)
		} else {
			// ipIntLeft          |         ipIntRight
			// 2001:0DB8:1234:0000:0000:0000:0000:0000
			ipIntLeft := binary.BigEndian.Uint64(cidr.IP[:net.IPv6len/2]) | (^binary.BigEndian.Uint64(cidr.Mask[:net.IPv6len/2]))
			ipIntRight := binary.BigEndian.Uint64(cidr.IP[net.IPv6len/2:]) | (^binary.BigEndian.Uint64(cidr.Mask[net.IPv6len/2:]))
			binary.BigEndian.PutUint64(ip[:net.IPv6len/2], ipIntLeft)
			binary.BigEndian.PutUint64(ip[net.IPv6len/2:], ipIntRight)
		}
		end, err = s.getIndexForIP(net.IP(ip).Mask(s.nodeMask))
		if err != nil {
			return -1, -1, err
		}
	}
	return begin, end, nil
}

// IsAllocated verifies if the given CIDR is allocated
func (s *CidrSet) IsAllocated(cidr *net.IPNet) (bool, error) {
	begin, end, err := s.getBeginningAndEndIndices(cidr)
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

// Release releases the given CIDR range.
func (s *CidrSet) Release(cidr *net.IPNet) error {
	begin, end, err := s.getBeginningAndEndIndices(cidr)
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

// Occupy marks the given CIDR range as used. Occupy succeeds even if the CIDR
// range was previously used.
func (s *CidrSet) Occupy(cidr *net.IPNet) (err error) {
	begin, end, err := s.getBeginningAndEndIndices(cidr)
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

func (s *CidrSet) getIndexForIP(ip net.IP) (int, error) {
	if ip.To4() != nil {
		cidrIndex := (binary.BigEndian.Uint32(s.clusterCIDR.IP) ^ binary.BigEndian.Uint32(ip.To4())) >> uint32(32-s.nodeMaskSize)
		if cidrIndex >= uint32(s.maxCIDRs) {
			return 0, fmt.Errorf("CIDR: %v/%v is out of the range of CIDR allocator", ip, s.nodeMaskSize)
		}
		return int(cidrIndex), nil
	}
	if ip.To16() != nil {
		bigIP := big.NewInt(0).SetBytes(s.clusterCIDR.IP)
		bigIP = bigIP.Xor(bigIP, big.NewInt(0).SetBytes(ip))
		cidrIndexBig := bigIP.Rsh(bigIP, uint(net.IPv6len*8-s.nodeMaskSize))
		cidrIndex := cidrIndexBig.Uint64()
		if cidrIndex >= uint64(s.maxCIDRs) {
			return 0, fmt.Errorf("CIDR: %v/%v is out of the range of CIDR allocator", ip, s.nodeMaskSize)
		}
		return int(cidrIndex), nil
	}

	return 0, fmt.Errorf("invalid IP: %v", ip)
}
