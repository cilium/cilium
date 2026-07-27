// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package topology provides parsing of the subnet-topology configuration
// string into platform-neutral entries.
//
// It is intentionally free of statedb, BPF, and other Linux-only
// dependencies so it can be imported by tools (e.g. cilium-cli) that need
// to interpret the topology string on any platform.
package topology

import (
	"fmt"
	"net/netip"
	"strings"
)

// Entry is a single subnet/identity mapping decoded from a topology string.
type Entry struct {
	// Key is the subnet prefix.
	Key netip.Prefix

	// Value is the identity (group ID) associated with the subnet.
	Value uint32
}

// Decode parses a subnet-topology string into a slice of Entry.
//
// Subnets within a group are separated by commas; groups are separated by
// semicolons. Each group is assigned a 1-based identity matching its
// position in the input.
//
// Example: data=10.0.0.1/24,10.10.0.1/24;10.20.0.1/24;2001:0db8:85a3::/64
// would decode into four entries:
//
//	| Key                 | Value |
//	|---------------------|-------|
//	| 10.0.0.1/24         | 1     |
//	| 10.10.0.1/24        | 1     |
//	| 10.20.0.1/24        | 2     |
//	| 2001:0db8:85a3::/64 | 3     |
func Decode(data string) ([]Entry, error) {
	data = strings.TrimSpace(data)
	if data == "" {
		return []Entry{}, nil
	}

	var entries []Entry

	groups := strings.Split(data, ";")

	for groupID, group := range groups {
		group = strings.TrimSpace(group)
		if group == "" {
			continue
		}

		subnets := strings.SplitSeq(group, ",")

		for subnet := range subnets {
			subnet = strings.TrimSpace(subnet)
			if subnet == "" {
				continue
			}

			// Validate CIDR format
			prefix, err := netip.ParsePrefix(subnet)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", subnet, err)
			}

			// Identity is groupID + 1 to avoid using identity 0.
			entries = append(entries, Entry{
				Key:   prefix,
				Value: uint32(groupID + 1),
			})
		}
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("no valid subnets found in data")
	}

	return entries, nil
}
