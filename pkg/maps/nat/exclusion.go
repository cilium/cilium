// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nat

import (
	"log/slog"
	"sync"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/cidrmap"
)

const (
	NatExclusionMapNameIPv4 = "cilium_nat_exclusion_v4"
	NatExclusionMapNameIPv6 = "cilium_nat_exclusion_v6"
	NatExclusionMaxEntries = 16384
)

var (
	NatExclusionMapIPv4 *cidrmap.CIDRMap
	NatExclusionMapIPv6 *cidrmap.CIDRMap

	initOnce sync.Once
	initErr error
)

func InitNatExclusionMaps(logger *slog.Logger) error {
	initOnce.Do(func() {
		var err error

		NatExclusionMapIPv4, err = cidrmap.OpenMapElems(
			logger,
			bpf.MapPath(logger, NatExclusionMapNameIPv4),
			32,
			true,
			NatExclusionMaxEntries,
		)
		if err != nil {
			initErr = err
			return
		}

		NatExclusionMapIPv6, err = cidrmap.OpenMapElems(
			logger,
			bpf.MapPath(logger, NatExclusionMapNameIPv6),
			128,
			true,
			NatExclusionMaxEntries,
		)
		initErr = err
	})
	return initErr
}
