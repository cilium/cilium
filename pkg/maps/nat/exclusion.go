// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nat

import (
	"fmt"
	"log/slog"
	"sync"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/cidrmap"
)

const (
	// Default map names and max entries.
	SourceExclusionMapNameIPv4 = "cilium_nat_src_exclusion_v4"
	SourceExclusionMapNameIPv6 = "cilium_nat_src_exclusion_v6"
	SourceExclusionMaxEntries  = 16384
)

// SourceExclusionMaps represents a pair of CIDRMaps for IPv4 and IPv6 NAT source exclusion.
// These maps store CIDRs that source IPs are compared against and excluded
// from NAT if they match.
type SourceExclusionMaps struct {
	IPv4 *cidrmap.CIDRMap
	IPv6 *cidrmap.CIDRMap
}

var (
	defaultOnce sync.Once
	defaultMaps *SourceExclusionMaps
	defaultErr  error
)

// NewSourceExclusionMaps creates a new instance of SourceExclusionMaps.
func NewSourceExclusionMaps(logger *slog.Logger, ipv4Name, ipv6Name string, maxEntries uint32) (*SourceExclusionMaps, error) {
	var ipv4Map *cidrmap.CIDRMap
	var ipv6Map *cidrmap.CIDRMap
	var err error

	if ipv4Name == "" && ipv6Name == "" {
		err = fmt.Errorf("failed to create exclusion maps: ipv4Name and ipv6Name cannot both be empty")
		return nil, err
	}
	if maxEntries <= 0 {
		maxEntries = SourceExclusionMaxEntries
	}
	if ipv4Name != "" {
		ipv4Map, err = cidrmap.OpenMapElems(
			logger,
			bpf.MapPath(logger, ipv4Name),
			32,
			true,
			maxEntries,
		)
		if err != nil {
			return nil, err
		}
	}
	if ipv6Name != "" {
		ipv6Map, err = cidrmap.OpenMapElems(
			logger,
			bpf.MapPath(logger, ipv6Name),
			128,
			true,
			maxEntries,
		)
		if err != nil {
			return nil, err
		}
	}

	return &SourceExclusionMaps{
		IPv4: ipv4Map,
		IPv6: ipv6Map,
	}, nil
}

// EnsureDefaultSourceExclusionMaps initialises exclusion maps with the default names.
// It will only do this once and return the same instance on subsequent calls.
func EnsureDefaultSourceExclusionMaps(logger *slog.Logger) (*SourceExclusionMaps, error) {
	defaultOnce.Do(func() {
		defaultMaps, defaultErr = NewSourceExclusionMaps(
			logger, SourceExclusionMapNameIPv4, SourceExclusionMapNameIPv6, SourceExclusionMaxEntries)
	})
	return defaultMaps, defaultErr
}
