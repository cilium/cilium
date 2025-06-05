// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lbmap

import (
	"github.com/cilium/cilium/pkg/bpf"
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

func BackendMap(key BackendKey) *bpf.Map {
	switch key.(type) {
	case *Backend4Key:
		return Backend4Map
	case *Backend4KeyV3:
		return Backend4MapV3
	case *Backend6Key:
		return Backend6Map
	case *Backend6KeyV3:
		return Backend6MapV3
	default:
		return nil
	}
}

func ServiceMap(key ServiceKey) *bpf.Map {
	switch key.(type) {
	case *Service4Key:
		return Service4MapV2
	case *Service6Key:
		return Service6MapV2
	default:
		return nil
	}
}

func RevNatMap(key RevNatKey) *bpf.Map {
	switch key.(type) {
	case *RevNat4Key:
		return RevNat4Map
	case *RevNat6Key:
		return RevNat6Map
	default:
		return nil
	}
}
