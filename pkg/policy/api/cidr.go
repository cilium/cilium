// Copyright 2016-2018 Authors of Cilium
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

package api

import (
	"net"

	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/labels"
)

// CIDR specifies a block of IP addresses.
// Example: 192.0.2.1/32
type CIDR string

// CIDRMatchAll is a []CIDR that matches everything
var CIDRMatchAll = []CIDR{CIDR("0.0.0.0/0"), CIDR("::/0")}

// MatchesAll determines whether the CIDR matches all traffic.
func (c *CIDR) MatchesAll() bool {
	for _, wildcard := range CIDRMatchAll {
		if *c == wildcard {
			return true
		}
	}
	return false
}

// CIDRRule is a rule that specifies a CIDR prefix to/from which outside
// communication  is allowed, along with an optional list of subnets within that
// CIDR prefix to/from which outside communication is not allowed.
type CIDRRule struct {
	// CIDR is a CIDR prefix / IP Block.
	//
	Cidr CIDR `json:"cidr"`

	// ExceptCIDRs is a list of IP blocks which the endpoint subject to the rule
	// is not allowed to initiate connections to. These CIDR prefixes should be
	// contained within Cidr. These exceptions are only applied to the Cidr in
	// this CIDRRule, and do not apply to any other CIDR prefixes in any other
	// CIDRRules.
	//
	// +optional
	ExceptCIDRs []CIDR `json:"except,omitempty"`

	// Generated indicates whether the rule was generated based on other rules
	// or provided by user
	Generated bool `json:"-"`
}

// CIDRSlice is a slice of CIDRs. It allows receiver methods to be defined for
// transforming the slice into other convenient forms such as
// EndpointSelectorSlice.
type CIDRSlice []CIDR

// GetAsEndpointSelectors returns the provided CIDR slice as a slice of
// endpoint selectors
func (s CIDRSlice) GetAsEndpointSelectors() EndpointSelectorSlice {
	// If multiple CIDRs representing reserved:world are in this CIDRSlice,
	// we only have to add the EndpointSelector representing reserved:world
	// once.
	var hasWorldBeenAdded bool
	slice := EndpointSelectorSlice{}
	for _, cidr := range s {
		if cidr.MatchesAll() && !hasWorldBeenAdded {
			hasWorldBeenAdded = true
			slice = append(slice, ReservedEndpointSelectors[labels.IDNameWorld])
		}
		lbl, err := labels.IPStringToLabel(string(cidr))
		if err == nil {
			slice = append(slice, NewESFromLabels(lbl))
		}
		// TODO: Log the error?
	}

	return slice
}

// StringSlice returns the CIDR slice as a slice of strings.
func (s CIDRSlice) StringSlice() []string {
	result := make([]string, 0, len(s))
	for _, c := range s {
		result = append(result, string(c))
	}
	return result
}

// CIDRRuleSlice is a slice of CIDRRules. It allows receiver methods to be
// defined for transforming the slice into other convenient forms such as
// EndpointSelectorSlice.
type CIDRRuleSlice []CIDRRule

// GetAsEndpointSelectors returns the provided CIDRRule slice as a slice of
// endpoint selectors
func (s CIDRRuleSlice) GetAsEndpointSelectors() EndpointSelectorSlice {
	cidrs := ComputeResultantCIDRSet(s)
	return cidrs.GetAsEndpointSelectors()
}

// ComputeResultantCIDRSet converts a slice of CIDRRules into a slice of
// individual CIDRs. This expands the cidr defined by each CIDRRule, applies
// the CIDR exceptions defined in "ExceptCIDRs", and forms a minimal set of
// CIDRs that cover all of the CIDRRules.
//
// Assumes no error checking is necessary as CIDRRule.Sanitize already does this.
func ComputeResultantCIDRSet(cidrs CIDRRuleSlice) CIDRSlice {
	var allResultantAllowedCIDRs CIDRSlice
	for _, s := range cidrs {
		_, allowNet, _ := net.ParseCIDR(string(s.Cidr))

		var removeSubnets []*net.IPNet
		for _, t := range s.ExceptCIDRs {
			_, removeSubnet, _ := net.ParseCIDR(string(t))
			removeSubnets = append(removeSubnets, removeSubnet)
		}
		resultantAllowedCIDRs, _ := ip.RemoveCIDRs([]*net.IPNet{allowNet}, removeSubnets)

		for _, u := range resultantAllowedCIDRs {
			allResultantAllowedCIDRs = append(allResultantAllowedCIDRs, CIDR(u.String()))
		}
	}
	return allResultantAllowedCIDRs
}
