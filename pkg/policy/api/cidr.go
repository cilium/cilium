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
)

// CIDR specifies a block of IP addresses.
// Example: 192.0.2.1/32
type CIDR string

// CIDRMatchAll is a []CIDR that matches everything
var CIDRMatchAll = []CIDR{CIDR("0.0.0.0/0"), CIDR("::/0")}

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

// ComputeResultantCIDRSet converts a slice of CIDRRules into a slice of
// individual CIDRs. This expands the cidr defined by each CIDRRule, applies
// the CIDR exceptions defined in "ExceptCIDRs", and forms a minimal set of
// CIDRs that cover all of the CIDRRules.
func ComputeResultantCIDRSet(cidrs []CIDRRule) []CIDR {
	var allResultantAllowedCIDRs []CIDR
	for _, s := range cidrs {
		// No need for error checking, as CIDRRule.Sanitize() already does.
		_, allowNet, _ := net.ParseCIDR(string(s.Cidr))

		var removeSubnets []*net.IPNet
		for _, t := range s.ExceptCIDRs {
			// No need for error checking, as CIDRRule.Sanitize() already
			// does.
			_, removeSubnet, _ := net.ParseCIDR(string(t))
			removeSubnets = append(removeSubnets, removeSubnet)
		}
		// No need for error checking, as have already validated that none of
		// the possible error cases can occur in ip.RemoveCIDRs
		resultantAllowedCIDRs, _ := ip.RemoveCIDRs([]*net.IPNet{allowNet}, removeSubnets)

		for _, u := range resultantAllowedCIDRs {
			allResultantAllowedCIDRs = append(allResultantAllowedCIDRs, CIDR(u.String()))
		}
	}
	return allResultantAllowedCIDRs
}
