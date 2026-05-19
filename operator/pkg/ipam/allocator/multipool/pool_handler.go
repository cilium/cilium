// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package multipool

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	cilium_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

const (
	poolKeyIPv4CIDRs    = "ipv4-cidrs"
	poolKeyIPv4MaskSize = "ipv4-mask-size"
	poolKeyIPv6CIDRs    = "ipv6-cidrs"
	poolKeyIPv6MaskSize = "ipv6-mask-size"
)

// ParsePoolSpec parses a pool spec string in the form
// "ipv4-cidrs:172.16.0.0/16,172.17.0.0/16;ipv4-mask-size:24".
func ParsePoolSpec(poolString string) (*cilium_v2alpha1.IPv4PoolSpec, *cilium_v2alpha1.IPv6PoolSpec, error) {
	fields := strings.FieldsFunc(strings.ReplaceAll(poolString, " ", ""), func(c rune) bool {
		return c == ';'
	})

	var ipv4CIDRs, ipv6CIDRs []cilium_v2alpha1.PoolCIDR
	var ipv4MaskSize, ipv6MaskSize uint8

	for _, field := range fields {
		key, value, ok := strings.Cut(field, ":")
		if !ok {
			return nil, nil, fmt.Errorf("invalid number of key delimiters in pool spec %s", poolString)
		}
		switch key {
		case poolKeyIPv4CIDRs:
			for cidr := range strings.SplitSeq(value, ",") {
				_, err := netip.ParsePrefix(cidr)
				if err != nil {
					return nil, nil, fmt.Errorf("invalid value for key %q: %w", poolKeyIPv4CIDRs, err)
				}
				ipv4CIDRs = append(ipv4CIDRs, cilium_v2alpha1.PoolCIDR(cidr))
			}
		case poolKeyIPv4MaskSize:
			mask, err := strconv.ParseUint(value, 10, 8)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid value for key %q: %w", poolKeyIPv4MaskSize, err)
			}
			ipv4MaskSize = uint8(mask)
		case poolKeyIPv6CIDRs:
			for cidr := range strings.SplitSeq(value, ",") {
				_, err := netip.ParsePrefix(cidr)
				if err != nil {
					return nil, nil, fmt.Errorf("invalid value for key %q: %w", poolKeyIPv6CIDRs, err)
				}
				ipv6CIDRs = append(ipv6CIDRs, cilium_v2alpha1.PoolCIDR(cidr))
			}
		case poolKeyIPv6MaskSize:
			mask, err := strconv.ParseUint(value, 10, 8)
			if err != nil {
				return nil, nil, fmt.Errorf("invalid value for key %q: %w", poolKeyIPv6MaskSize, err)
			}
			ipv6MaskSize = uint8(mask)
		}
	}

	var (
		v4PoolSpec *cilium_v2alpha1.IPv4PoolSpec
		v6PoolSpec *cilium_v2alpha1.IPv6PoolSpec
	)
	if len(ipv4CIDRs) > 0 {
		v4PoolSpec = &cilium_v2alpha1.IPv4PoolSpec{
			CIDRs:    ipv4CIDRs,
			MaskSize: ipv4MaskSize,
		}
	}
	if len(ipv6CIDRs) > 0 {
		v6PoolSpec = &cilium_v2alpha1.IPv6PoolSpec{
			CIDRs:    ipv6CIDRs,
			MaskSize: ipv6MaskSize,
		}
	}

	return v4PoolSpec, v6PoolSpec, nil
}

func UpsertPool(allocator *PoolAllocator, name string, v4Spec *cilium_v2alpha1.IPv4PoolSpec, v6Spec *cilium_v2alpha1.IPv6PoolSpec) error {
	var ipv4CIDRs, ipv6CIDRs []string
	var ipv4MaskSize, ipv6MaskSize int

	if v4Spec != nil {
		ipv4MaskSize = int(v4Spec.MaskSize)
		ipv4CIDRs = make([]string, len(v4Spec.CIDRs))
		for i, cidr := range v4Spec.CIDRs {
			ipv4CIDRs[i] = string(cidr)
		}
	}

	if v6Spec != nil {
		ipv6MaskSize = int(v6Spec.MaskSize)
		ipv6CIDRs = make([]string, len(v6Spec.CIDRs))
		for i, cidr := range v6Spec.CIDRs {
			ipv6CIDRs[i] = string(cidr)
		}
	}

	return allocator.UpsertPool(
		name,
		ipv4CIDRs,
		ipv4MaskSize,
		ipv6CIDRs,
		ipv6MaskSize,
	)
}

func DeletePool(allocator *PoolAllocator, name string) error {
	return allocator.DeletePool(name)
}
