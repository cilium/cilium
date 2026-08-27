// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

// LRPType identifies the matcher used by a Local Redirect Policy.
type LRPType int

const (
	LRPTypeNone LRPType = iota
	LRPTypeAddressMatcher
	LRPTypeServiceMatcher
)

func (t LRPType) String() string {
	switch t {
	case LRPTypeNone:
		return "none"
	case LRPTypeAddressMatcher:
		return "address"
	case LRPTypeServiceMatcher:
		return "service"
	default:
		return "unknown"
	}
}

// FrontendType identifies how a Local Redirect Policy selects frontends.
type FrontendType int

const (
	FrontendTypeUnknown FrontendType = iota
	// FrontendTypeServiceAll selects the ClusterIP and all ports of a Service.
	FrontendTypeServiceAll
	// FrontendTypeServiceNamedPorts selects named ports of a Service.
	FrontendTypeServiceNamedPorts
	// FrontendTypeServiceSinglePort selects a single port of a Service.
	FrontendTypeServiceSinglePort
	// FrontendTypeAddressSinglePort selects a single address and port.
	FrontendTypeAddressSinglePort
	// FrontendTypeAddressNamedPorts selects named ports on an address.
	FrontendTypeAddressNamedPorts
)

func (t FrontendType) String() string {
	switch t {
	case FrontendTypeServiceAll:
		return "all"
	case FrontendTypeServiceNamedPorts:
		return "named-ports"
	case FrontendTypeServiceSinglePort:
		return "svc-single-port"
	case FrontendTypeAddressSinglePort:
		return "addr-single-port"
	case FrontendTypeAddressNamedPorts:
		return "addr-named-ports"
	default:
		return "unknown"
	}
}
