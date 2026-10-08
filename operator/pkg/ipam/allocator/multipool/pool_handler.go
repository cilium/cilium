// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package multipool

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"go4.org/netipx"

	iputil "github.com/cilium/cilium/pkg/ip"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

const (
	poolKeyIPv4CIDRs    = "ipv4-cidrs"
	poolKeyIPv4MaskSize = "ipv4-mask-size"
	poolKeyIPv6CIDRs    = "ipv6-cidrs"
	poolKeyIPv6MaskSize = "ipv6-mask-size"
	poolKeyAllowFirstIP = "allow-first-ip"
	poolKeyAllowLastIP  = "allow-last-ip"
)

type ParsedPoolSpec struct {
	IPv4         *v2.IPv4PoolSpec
	IPv6         *v2.IPv6PoolSpec
	AllowFirstIP bool
	AllowLastIP  bool
}

// ParsePoolSpec parses a pool spec string in the form
// "ipv4-cidrs:172.16.0.0/16,172.17.0.0/16;ipv4-mask-size:24".
func ParsePoolSpec(poolString string) (*ParsedPoolSpec, error) {
	fields := strings.FieldsFunc(strings.ReplaceAll(poolString, " ", ""), func(c rune) bool {
		return c == ';'
	})

	var ipv4CIDRs, ipv6CIDRs []iputil.Prefix
	var ipv4MaskSize, ipv6MaskSize uint8
	var allowFirstIP, allowLastIP bool

	for _, field := range fields {
		key, value, ok := strings.Cut(field, ":")
		if !ok {
			return nil, fmt.Errorf("invalid number of key delimiters in pool spec %s", poolString)
		}
		switch key {
		case poolKeyIPv4CIDRs:
			for cidr := range strings.SplitSeq(value, ",") {
				prefix, err := netip.ParsePrefix(cidr)
				if err != nil {
					return nil, fmt.Errorf("invalid value for key %q: %w", poolKeyIPv4CIDRs, err)
				}
				ipv4CIDRs = append(ipv4CIDRs, iputil.PrefixFrom(prefix))
			}
		case poolKeyIPv4MaskSize:
			mask, err := strconv.ParseUint(value, 10, 8)
			if err != nil {
				return nil, fmt.Errorf("invalid value for key %q: %w", poolKeyIPv4MaskSize, err)
			}
			ipv4MaskSize = uint8(mask)
		case poolKeyIPv6CIDRs:
			for cidr := range strings.SplitSeq(value, ",") {
				prefix, err := netip.ParsePrefix(cidr)
				if err != nil {
					return nil, fmt.Errorf("invalid value for key %q: %w", poolKeyIPv6CIDRs, err)
				}
				ipv6CIDRs = append(ipv6CIDRs, iputil.PrefixFrom(prefix))
			}
		case poolKeyIPv6MaskSize:
			mask, err := strconv.ParseUint(value, 10, 8)
			if err != nil {
				return nil, fmt.Errorf("invalid value for key %q: %w", poolKeyIPv6MaskSize, err)
			}
			ipv6MaskSize = uint8(mask)
		case poolKeyAllowFirstIP:
			parsed, err := strconv.ParseBool(value)
			if err != nil {
				return nil, fmt.Errorf("invalid value for key %q: %w", poolKeyAllowFirstIP, err)
			}
			allowFirstIP = parsed
		case poolKeyAllowLastIP:
			parsed, err := strconv.ParseBool(value)
			if err != nil {
				return nil, fmt.Errorf("invalid value for key %q: %w", poolKeyAllowLastIP, err)
			}
			allowLastIP = parsed
		}
	}

	var (
		v4PoolSpec *v2.IPv4PoolSpec
		v6PoolSpec *v2.IPv6PoolSpec
	)
	if len(ipv4CIDRs) > 0 {
		v4PoolSpec = &v2.IPv4PoolSpec{
			CIDRs:    ipv4CIDRs,
			MaskSize: ipv4MaskSize,
		}
	}
	if len(ipv6CIDRs) > 0 {
		v6PoolSpec = &v2.IPv6PoolSpec{
			CIDRs:    ipv6CIDRs,
			MaskSize: ipv6MaskSize,
		}
	}

	return &ParsedPoolSpec{
		IPv4:         v4PoolSpec,
		IPv6:         v6PoolSpec,
		AllowFirstIP: allowFirstIP,
		AllowLastIP:  allowLastIP,
	}, nil
}

func UpsertPool(allocator *PoolAllocator, name string, v4Spec *v2.IPv4PoolSpec, v6Spec *v2.IPv6PoolSpec, allowFirstIP, allowLastIP bool) error {
	var ipv4CIDRs, ipv6CIDRs []poolCIDRConfig
	var ipv4MaskSize, ipv6MaskSize int
	var err error

	if v4Spec != nil {
		ipv4MaskSize = int(v4Spec.MaskSize)
		ipv4CIDRs, err = buildPoolCIDRConfigs(v4Spec.CIDRs, v4Spec.Pool)
		if err != nil {
			return fmt.Errorf("invalid IPv4 CIDR config: %w", err)
		}
	}

	if v6Spec != nil {
		ipv6MaskSize = int(v6Spec.MaskSize)
		ipv6CIDRs, err = buildPoolCIDRConfigs(v6Spec.CIDRs, v6Spec.Pool)
		if err != nil {
			return fmt.Errorf("invalid IPv6 CIDR config: %w", err)
		}
	}

	var opts []PoolOption
	if allowFirstIP {
		opts = append(opts, WithAllowFirstIP())
	}
	if allowLastIP {
		opts = append(opts, WithAllowLastIP())
	}

	return allocator.UpsertPool(
		name,
		ipv4CIDRs,
		ipv4MaskSize,
		ipv6CIDRs,
		ipv6MaskSize,
		opts...,
	)
}

func DeletePool(allocator *PoolAllocator, name string) error {
	return allocator.DeletePool(name)
}

func buildPoolCIDRConfigs(cidrs []iputil.Prefix, pool []v2.PoolCIDRConfig) ([]poolCIDRConfig, error) {
	configByCIDR := make(map[iputil.Prefix]v2.PoolCIDRConfig, len(pool))
	for _, cfg := range pool {
		configByCIDR[cfg.CIDR] = cfg
	}

	configs := make([]poolCIDRConfig, 0, len(cidrs))
	for _, cidr := range cidrs {
		prefix := cidr.Prefix.Masked()

		reservedRanges, err := parseReservedRanges(prefix, configByCIDR[cidr].ReservedRanges)
		if err != nil {
			return nil, err
		}

		configs = append(configs, poolCIDRConfig{
			cidr:           prefix,
			reservedRanges: reservedRanges,
		})
	}

	return configs, nil
}

func parseReservedRanges(poolCIDR netip.Prefix, ranges []v2.ReservedRange) ([]netipx.IPRange, error) {
	reserved := make([]netipx.IPRange, 0, len(ranges))
	for _, rr := range ranges {
		start, err := netip.ParseAddr(rr.Start)
		if err != nil {
			return nil, fmt.Errorf("invalid reserved range start %q in pool CIDR %s: %w", rr.Start, poolCIDR, err)
		}

		end, err := netip.ParseAddr(rr.End)
		if err != nil {
			return nil, fmt.Errorf("invalid reserved range end %q in pool CIDR %s: %w", rr.End, poolCIDR, err)
		}

		r := netipx.IPRangeFrom(start, end)
		if !r.IsValid() {
			return nil, fmt.Errorf("invalid reserved range %s-%s in pool CIDR %s", start, end, poolCIDR)
		}

		if !poolCIDR.Contains(start) || !poolCIDR.Contains(end) {
			return nil, fmt.Errorf("reserved range %s-%s is outside pool CIDR %s", start, end, poolCIDR)
		}

		reserved = append(reserved, r)
	}

	return reserved, nil
}
