// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"net"
	"net/netip"
	"strings"

	"github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/labels"
	cidrpkg "github.com/cilium/cilium/pkg/labels/cidr"
)

// +kubebuilder:validation:Pattern=`^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([0-9]|[1-2][0-9]|3[0-2])$|^s*((([0-9A-Fa-f]{1,4}:){7}(:|([0-9A-Fa-f]{1,4})))|(([0-9A-Fa-f]{1,4}:){6}:([0-9A-Fa-f]{1,4})?)|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){0,1}):([0-9A-Fa-f]{1,4})?))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){0,2}):([0-9A-Fa-f]{1,4})?))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){0,3}):([0-9A-Fa-f]{1,4})?))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){0,4}):([0-9A-Fa-f]{1,4})?))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){0,5}):([0-9A-Fa-f]{1,4})?))|(:(:|((:[0-9A-Fa-f]{1,4}){1,7}))))(%.+)?s*/([0-9]|[1-9][0-9]|1[0-1][0-9]|12[0-8])$`

// CIDR specifies a block of IP addresses.
// Example: 192.0.2.1/32
type CIDR string

// CIDRMatchAll is a []CIDR that matches everything
var CIDRMatchAll = []CIDR{CIDR("0.0.0.0/0"), CIDR("::/0")}

// MatchesAll determines whether the CIDR matches all traffic.
func (c CIDR) MatchesAll() bool {
	for _, wildcard := range CIDRMatchAll {
		if c == wildcard {
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
	// +kubebuilder:validation:Required
	Cidr CIDR `json:"cidr"`

	// ExceptCIDRs is a list of IP blocks which the endpoint subject to the rule
	// is not allowed to initiate connections to. These CIDR prefixes should be
	// contained within Cidr. These exceptions are only applied to the Cidr in
	// this CIDRRule, and do not apply to any other CIDR prefixes in any other
	// CIDRRules.
	//
	// +kubebuilder:validation:Optional
	ExceptCIDRs []CIDR `json:"except,omitempty"`

	// Generated indicates whether the rule was generated based on other rules
	// or provided by user
	Generated bool `json:"-"`
}

// String converts the CIDRRule into a human-readable string.
func (r CIDRRule) String() string {
	exceptCIDRs := ""
	if len(r.ExceptCIDRs) > 0 {
		exceptCIDRs = "-" + CIDRSlice(r.ExceptCIDRs).String()
	}
	return string(r.Cidr) + exceptCIDRs
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
		lbl, err := cidrpkg.IPStringToLabel(string(cidr))
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

// String converts the CIDRSlice into a human-readable string.
func (s CIDRSlice) String() string {
	if len(s) == 0 {
		return ""
	}
	return "[" + strings.Join(s.StringSlice(), ",") + "]"
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

// StringSlice returns the CIDRRuleSlice as a slice of strings.
func (s CIDRRuleSlice) StringSlice() []string {
	result := make([]string, 0, len(s))
	for _, c := range s {
		result = append(result, c.String())
	}
	return result
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
		resultantAllowedCIDRs := ip.RemoveCIDRs([]*net.IPNet{allowNet}, removeSubnets)

		for _, u := range resultantAllowedCIDRs {
			allResultantAllowedCIDRs = append(allResultantAllowedCIDRs, CIDR(u.String()))
		}
	}
	return allResultantAllowedCIDRs
}

// addrsToCIDRRules generates CIDRRules for the IPs passed in.
// This function will mark the rule to Generated true by default.
func addrsToCIDRRules(addrs []netip.Addr) []CIDRRule {
	cidrRules := make([]CIDRRule, 0, len(addrs))
	for _, addr := range addrs {
		rule := CIDRRule{ExceptCIDRs: make([]CIDR, 0)}
		rule.Generated = true
		if addr.Is4() {
			rule.Cidr = CIDR(addr.String() + "/32")
		} else {
			rule.Cidr = CIDR(addr.String() + "/128")
		}
		cidrRules = append(cidrRules, rule)
	}
	return cidrRules
}
