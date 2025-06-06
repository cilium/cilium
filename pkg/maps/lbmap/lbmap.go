// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbmap

import (
	"github.com/cilium/cilium/pkg/metrics"
)

const DefaultMaxEntries = 65536

var (
	// MaxEntries contains the maximum number of entries that are allowed
	// in Cilium LB service, backend and affinity maps.
	ServiceMapMaxEntries        = DefaultMaxEntries
	ServiceBackEndMapMaxEntries = DefaultMaxEntries
	RevNatMapMaxEntries         = DefaultMaxEntries
	AffinityMapMaxEntries       = DefaultMaxEntries
	SourceRangeMapMaxEntries    = DefaultMaxEntries
	MaglevMapMaxEntries         = DefaultMaxEntries
)

// Init updates the map info defaults for sock rev nat {4,6} and LB maps and
// then initializes all LB-related maps.
func Init(registry *metrics.Registry, params InitParams) {
	if params.MaxSockRevNatMapEntries != 0 {
		MaxSockRevNat4MapEntries = params.MaxSockRevNatMapEntries
		MaxSockRevNat6MapEntries = params.MaxSockRevNatMapEntries
	}

	MaglevMapMaxEntries = params.MaglevMapMaxEntries

	initSVC(registry, params)
	initAffinity(registry, params)
	initSourceRange(registry, params)
}

// InitParams represents the parameters to be passed to Init().
type InitParams struct {
	IPv4, IPv6 bool

	MaxSockRevNatMapEntries                                         int
	ServiceMapMaxEntries, BackEndMapMaxEntries, RevNatMapMaxEntries int
	AffinityMapMaxEntries                                           int
	SourceRangeMapMaxEntries                                        int
	MaglevMapMaxEntries                                             int
	PerSvcLbEnabled                                                 bool
}
