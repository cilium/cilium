// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package linuxrouting

import (
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/cilium/cilium/pkg/mac"
)

// RoutingInfo represents information required to enable connectivity via local
// policy rules and route tables.
// The information in this struct is used to create rules and routes which direct
// traffic out of the interface (egress).
//
// This struct is mostly derived from the `ipam.AllocationResult` as the
// information comes from IPAM.
type RoutingInfo struct {
	// Gateway is the gateway where outbound/egress IPv4/IPv6 traffic is directed.
	Gateway net.IP

	// CIDRs is a list of CIDRs which the interface has access to. In most
	// cases, it'll at least contain the CIDR of the IPv4Gateway IP address.
	CIDRs []net.IPNet

	// MasterIfMAC is the MAC address of the master interface that egress
	// traffic is directed to. This is the MAC of the interface itself which
	// corresponds to the IPv4Gateway IP addr.
	MasterIfMAC mac.MAC

	// Masquerade represents whether masquerading is enabled or not.
	Masquerade bool

	// InterfaceNumber is the provider-specific number of the master interface
	// that egress traffic is directed to. It is used to compute the
	// per-interface route table when the compatibility scheme is disabled.
	InterfaceNumber int

	mtu       *int
	linkState *bool

	// compatEgressPriority determines whether to use the new or old style egress rule.
	compatEgressPriority bool
}

func (info *RoutingInfo) GetCIDRs() []net.IPNet {
	return info.CIDRs
}

type RoutingInfoOption func(*RoutingInfo) error

// WithOptions applies functional options to info.
func (info *RoutingInfo) WithOptions(opts ...RoutingInfoOption) error {
	for _, opt := range opts {
		if err := opt(info); err != nil {
			return err
		}
	}
	return nil
}

// WithCIDRsAndMasquerade configures the directly reachable CIDRs and whether
// masquerading is enabled.
func WithCIDRsAndMasquerade(cidrs []string, masquerade bool) RoutingInfoOption {
	return func(info *RoutingInfo) error {
		if len(cidrs) == 0 && masquerade {
			return errors.New("empty cidrs")
		}

		parsedCIDRs := make([]net.IPNet, 0, len(cidrs))
		for _, cidr := range cidrs {
			_, parsed, err := net.ParseCIDR(cidr)
			if err != nil {
				return fmt.Errorf("invalid cidr: %s", cidr)
			}
			parsedCIDRs = append(parsedCIDRs, *parsed)
		}

		info.CIDRs = parsedCIDRs
		info.Masquerade = masquerade
		return nil
	}
}

// WithLinkState configures whether the master interface should be brought up
// or down before routes and rules are installed.
func WithLinkState(up bool) RoutingInfoOption {
	return func(info *RoutingInfo) error {
		info.linkState = &up
		return nil
	}
}

// WithMTU configures the MTU to apply to the master interface before routes
// and rules are installed.
func WithMTU(mtu int) RoutingInfoOption {
	return func(info *RoutingInfo) error {
		info.mtu = &mtu
		return nil
	}
}

// WithCompatEgressPriority selects the legacy egress priority and ifindex-based
// route table scheme used by Azure IPAM.
func WithCompatEgressPriority() RoutingInfoOption {
	return func(info *RoutingInfo) error {
		info.compatEgressPriority = true
		return nil
	}
}

// NewRoutingInfo parses the required routing information and applies opts. By
// default, using the returned information does not change link state or MTU.
func NewRoutingInfo(gateway string, masterIfMAC mac.MAC, ifaceNum string, opts ...RoutingInfoOption) (*RoutingInfo, error) {
	ip := net.ParseIP(gateway)
	if ip == nil {
		return nil, fmt.Errorf("invalid gateway: %s", gateway)
	}

	// The MAC of the master interface is what the routes and rules are keyed
	// on, so an unset one cannot be worked around here.
	if !masterIfMAC.IsValid() {
		return nil, errors.New("empty mac")
	}

	parsedIfaceNum, err := strconv.Atoi(ifaceNum)
	if err != nil {
		return nil, fmt.Errorf("invalid interface number: %s", ifaceNum)
	}

	info := &RoutingInfo{
		Gateway:         ip,
		MasterIfMAC:     masterIfMAC,
		InterfaceNumber: parsedIfaceNum,
	}
	if err := info.WithOptions(opts...); err != nil {
		return nil, err
	}
	return info, nil
}
