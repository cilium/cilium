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

package ip

import (
	//"encoding/binary"
	"fmt"
	"net"
	"sort"
	//"math/big"
	//"math/big"
	//"encoding/binary"
	"bytes"
)

const (
	ipv4BitLen = 8 * net.IPv4len
	ipv6BitLen = 8 * net.IPv6len
)

// Im
type ByMask []*net.IPNet

func (s ByMask) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s ByMask) Less(i, j int) bool {
	iPrefixSize, _ := s[i].Mask.Size()
	jPrefixSize, _ := s[j].Mask.Size()
	if iPrefixSize == jPrefixSize {
		byteArrComp := bytes.Compare(s[i].IP, s[j].IP)
		if byteArrComp < 0 {
			return true
		} else {
			return false
		}
	}
	return iPrefixSize < jPrefixSize
}

func (s ByMask) Len() int {
	return len(s)
}

func RemoveCIDRs(allowCIDRs, removeCIDRs []*net.IPNet) *[]*net.IPNet {

	sort.Sort(ByMask(removeCIDRs))

PreLoop:
	for j, removeCIDR := range removeCIDRs {
		for i, removeCIDR2 := range removeCIDRs {
			if i == j {
				continue
			}
			if removeCIDR.Contains(removeCIDR2.IP) {
				//fmt.Printf("removeCIDR %s contains removeCIDR2 %s\n", removeCIDR, removeCIDR2.IP)
				removeCIDRs = append(removeCIDRs[:i], removeCIDRs[i+1:]...)
				// Re-trigger loop since we have modified the slice we are iterating over.
				goto PreLoop
			}
		}
	}


Loop:
	for j, remove := range removeCIDRs {
		for i, allowCIDR := range allowCIDRs {

			// Only remove CIDR if it is contained in the block of IPs we are trying to allow
			if allowCIDR.Contains(remove.IP) {
				//fmt.Printf("allowCIDR %s contains removeCIDR %s\n", allowCIDR, remove )
				nets, err := removeCIDR(allowCIDR, remove)
				//fmt.Printf("produced subnets: %s\n", nets)
				if err != nil {
					fmt.Printf("error: %s\n", err)
					continue
				}
				allowCIDRs = append(allowCIDRs[:i], allowCIDRs[i+1:]...)
				allowCIDRs = append(allowCIDRs, nets...)
				goto Loop
			} else if remove.Contains(allowCIDR.IP.Mask(allowCIDR.Mask)) {
				//fmt.Printf("remove CIDR %s contains allow CIDR %s", remove, allowCIDR)
				allowCIDRs = append(allowCIDRs[:i], allowCIDRs[i+1:]...)
				goto Loop
			}
		}
		//fmt.Printf("removing CIDR: %s\n", remove)
		removeCIDRs = append(removeCIDRs[:j], removeCIDRs[j+1:]...)
		goto Loop
	}

	//fmt.Println("all allowed CIDRs:")
	/*for _, v := range allowCIDRs {
		maskSize, _ := v.Mask.Size()
		//fmt.Printf("%s/%d\n", v.IP, maskSize)
	}*/

PostLoop:
	for j, allowCIDR := range allowCIDRs {
		for i, allowCIDR2 := range allowCIDRs {
			if i == j {
				continue
			}
			//fmt.Printf("allowCIDR2: %s, allowCIDR2.IP.Mask(allowCIDR2.Mask): %s\n", allowCIDR2, allowCIDR2.IP.Mask(allowCIDR2.Mask))
			if allowCIDR.Contains(allowCIDR2.IP.Mask(allowCIDR2.Mask)) {
				//fmt.Printf("allowCIDR %s contains first IP from CIDR allowCIDR2: %s\n", allowCIDR, allowCIDR2.IP.Mask(allowCIDR2.Mask))
				allowCIDRs = append(allowCIDRs[:i], allowCIDRs[i+1:]...)
				// Re-trigger loop since we have modified the slice we are iterating over.
				goto PostLoop
			}
		}
	}

	//fmt.Printf("after postloop allowedCIDRs: %s\n", allowCIDRs)

	return &allowCIDRs
}

func getFirstIP(ipNet *net.IPNet) *net.IP {
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
	//fmt.Printf("\n\n\n\n\n\n")
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
		//removeBitLen = ipv4BitLen
	}

	//fmt.Printf("allowBitLen: %d\n", allowBitLen)
	//fmt.Printf("removeBitLen: %d\n", removeBitLen)

	// Get size of each CIDR mask.
	allowSize, _ := allowCIDR.Mask.Size()

	removeSize, _ := removeCIDR.Mask.Size()

	if allowSize >= removeSize {
		return nil, fmt.Errorf("allow CIDR must be a superset of remove CIDR")
	}

	allowFirstIPMasked := allowCIDR.IP.Mask(allowCIDR.Mask)
	removeFirstIPMasked := removeCIDR.IP.Mask(removeCIDR.Mask)
	//fmt.Printf("removeFirstIPMasked before append 1: %s\n", removeFirstIPMasked)

	ipv4Ipv6Slice := []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff}

	// Convert to IPv4 in IPv6 addresses if needed.
	if allowIsIpv4 {
		//fmt.Printf("allowIsIpv4\n")
		//fmt.Printf("allowFirstIPMasked before append: %s\n", allowFirstIPMasked)
		allowFirstIPMasked = append(ipv4Ipv6Slice, allowFirstIPMasked...)
		//fmt.Printf("allowFirstIPMasked after append: %s\n", allowFirstIPMasked)
	}

	if removeIsIpv4 {
		//fmt.Printf("removeIsIPv4\n")
		//fmt.Printf("removeFirstIPMasked before append: %s\n", removeFirstIPMasked)
		removeFirstIPMasked = append(ipv4Ipv6Slice, removeFirstIPMasked...)
		//fmt.Printf("removeFirstIPMasked after append: %s\n", removeFirstIPMasked)
	}
	//fmt.Printf("removeFirstIPMasked: %s\n", removeFirstIPMasked)

	allowFirstIP := &allowFirstIPMasked
	removeFirstIP := &removeFirstIPMasked

	//fmt.Printf("removeFirstIP: %s\n", removeFirstIP)






	// Create CIDR's with mask size of Y+1, Y+2 ... X where Y is the mask length of the CIDR B
	// from which we are exluding a CIDR A with mask length X.
	for i := (allowBitLen - allowSize - 1); i >= (allowBitLen - removeSize); i-- {
		//fmt.Printf("i: %d\n", i)


		newMaskSize := allowBitLen - i
		//fmt.Printf("creating CIDR of size: %d\n", newMaskSize)
		//newMask := net.CIDRMask(newMaskSize, allowBitLen)
		//byteNum := getByteIndexOfBit(uint(i))
		//fmt.Printf("byteNum: %d\n", byteNum)

		//numBitsToCheck := i - allowSize

		//fmt.Printf("flipping %dth bit\n", i)
		//fmt.Printf("removeFirstIP before call to flipNthBit: %08b\n", removeFirstIP)
		newIP := flipNthBit(removeFirstIP, uint(i))
		/*fmt.Printf("newIPNet[%d]: \t%08b\n", byteNum, (*newIP)[byteNum])
		fmt.Printf("removeFirstIP[%d]: \t%08b\n", byteNum, (*removeFirstIP)[byteNum])

		fmt.Printf("removeFirstIP: %s\n", removeFirstIP)
		fmt.Printf("newIP: %s\n", newIP)
		fmt.Printf("newIP Bytes: %08b\n", newIP)*/

		// Create IP that we will use for this new allowed CIDR.



		//fmt.Printf("allowFirstIp: %08b\n", allowFirstIP)
		for k, _ := range *allowFirstIP {
			(*newIP)[k] = (*allowFirstIP)[k] | (*newIP)[k]
		}

		newMask := net.CIDRMask(newMaskSize, allowBitLen)
		newIPMasked := newIP.Mask(newMask)

		/*fmt.Printf("newIP: %08b\n", newIP)
		fmt.Printf("newIPMasked: %08b\n", newIPMasked)
		fmt.Printf("newIP: %s\n", newIP)*/
		//fmt.Printf("newIPMasked: %s\n", newIPMasked)



		newIpNet := net.IPNet{IP: newIPMasked, Mask: newMask}
		/*foo, _ := newIpNet.Mask.Size()
		fmt.Printf("newIpNet: %s/%d\n", newIpNet.IP, foo)*/
		allows = append(allows, &newIpNet)
		//fmt.Printf("\n\n\n\n\n\n\n\n\n\n")
	}

	return allows, nil

}

func getByteIndexOfBit(bit uint) uint {
	return net.IPv6len - (bit/8) -1 

}

func getNthBit(ip *net.IP, bitNum uint) uint8 {
	byteNum := getByteIndexOfBit(bitNum)
	bits := (*ip)[byteNum]
	b := uint8(bits)
	return b >> (bitNum % 8) & 1
}

func flipNthBit(ip *net.IP, bitNum uint) *net.IP {
	ipCopy := make(net.IP, len(*ip))
	copy(ipCopy, *ip)
	//fmt.Printf("provided IP: %08b\n", ip)
	//fmt.Printf("copy of provided IP: %08b\n", ipCopy)
	byteNum := getByteIndexOfBit(bitNum)
	//fmt.Printf("modifying byte number %d\n", byteNum)
	ipCopy[byteNum] = ipCopy[byteNum] ^ 1 << (bitNum % 8)
	return &ipCopy
}
