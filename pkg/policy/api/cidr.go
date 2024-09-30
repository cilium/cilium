// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"net/netip"
	"strings"

	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
)

// CIDR specifies a block of IP addresses.
// Example: 192.0.2.1/32
//
// +kubebuilder:validation:Format=cidr
type CIDR string

var (
	ipv4All = CIDR("0.0.0.0/0")
	ipv6All = CIDR("::/0")

	worldLabelNonDualStack = labels.Label{Source: labels.LabelSourceReserved, Key: labels.IDNameWorld}
	worldLabelV4           = labels.Label{Source: labels.LabelSourceReserved, Key: labels.IDNameWorldIPv4}
	worldLabelV6           = labels.Label{Source: labels.LabelSourceReserved, Key: labels.IDNameWorldIPv6}
)

// CIDRRule is a rule that specifies a CIDR prefix to/from which outside
// communication  is allowed, along with an optional list of subnets within that
// CIDR prefix to/from which outside communication is not allowed.
type CIDRRule struct {
	// CIDR is a CIDR prefix / IP Block.
	//
	// +kubebuilder:validation:OneOf
	Cidr CIDR `json:"cidr,omitempty"`

	// CIDRGroupRef is a reference to a CiliumCIDRGroup object.
	// A CiliumCIDRGroup contains a list of CIDRs that the endpoint, subject to
	// the rule, can (Ingress/Egress) or cannot (IngressDeny/EgressDeny) receive
	// connections from.
	//
	// +kubebuilder:validation:OneOf
	CIDRGroupRef CIDRGroupRef `json:"cidrGroupRef,omitempty"`

	// CIDRGroupSelector selects CiliumCIDRGroups by their labels,
	// rather than by name.
	//
	// +kubebuilder:validation:OneOf
	CIDRGroupSelector *slim_metav1.LabelSelector `json:"cidrGroupSelector,omitempty"`

	// ExceptCIDRs is a list of IP blocks which the endpoint subject to the rule
	// is not allowed to initiate connections to. These CIDR prefixes should be
	// contained within Cidr, using ExceptCIDRs together with CIDRGroupRef is not
	// supported yet.
	// These exceptions are only applied to the Cidr in this CIDRRule, and do not
	// apply to any other CIDR prefixes in any other CIDRRules.
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
	var hasIPv4AllBeenAdded, hasIPv6AllBeenAdded bool
	slice := EndpointSelectorSlice{}
	for _, cidr := range s {
		if cidr == ipv4All {
			hasIPv4AllBeenAdded = true
		}
		if cidr == ipv6All {
			hasIPv6AllBeenAdded = true
		}
		lbl, err := labels.IPStringToLabel(string(cidr))
		if err == nil {
			slice = append(slice, NewESFromLabels(lbl))
		}
		// TODO: Log the error?
	}

	if option.Config.IsDualStack() {
		// If Cilium is in dual-stack mode then world-ipv4 and
		// world-ipv6 need to be distinguished from one another.
		if hasIPv4AllBeenAdded && hasIPv6AllBeenAdded {
			slice = append(slice, ReservedEndpointSelectors[labels.IDNameWorld])
		}
		if hasIPv4AllBeenAdded {
			slice = append(slice, ReservedEndpointSelectors[labels.IDNameWorldIPv4])
		}
		if hasIPv6AllBeenAdded {
			slice = append(slice, ReservedEndpointSelectors[labels.IDNameWorldIPv6])
		}
	} else if option.Config.EnableIPv4 && hasIPv4AllBeenAdded {
		slice = append(slice, ReservedEndpointSelectors[labels.IDNameWorld])
	} else if option.Config.EnableIPv6 && hasIPv6AllBeenAdded {
		slice = append(slice, ReservedEndpointSelectors[labels.IDNameWorld])
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
//
// The ExceptCIDRs block is inserted as a negative match. Specifically, the
// DoesNotExist qualifier. For example, the CIDRRule
//
//	cidr: 1.1.1.0/24
//	exceptCIDRs: ["1.1.1.1/32"]
//
// results in the selector equivalent to "cidr:1.1.1.0/24 !cidr:1.1.1.1/32".
//
// This works because the label selectors will select numeric identities belonging only
// to the shorter prefixes. However, longer prefixes will have a different numeric
// identity, as the bpf ipcache is an LPM lookup. This essentially acts as a
// "carve-out", using the LPM mechanism to exlude subsets of a larger prefix.
func (s CIDRRuleSlice) GetAsEndpointSelectors() EndpointSelectorSlice {
	ces := make(EndpointSelectorSlice, 0, len(s))

	for _, r := range s {
		ls := slim_metav1.LabelSelector{
			MatchExpressions: make([]slim_metav1.LabelSelectorRequirement, 0, 1+len(r.ExceptCIDRs)),
		}

		// add the "main" label:
		// either a CIDR, CIDRGroupRef, or CIDRGroupSelector
		if r.Cidr != "" {
			var lbl labels.Label
			switch r.Cidr {
			case ipv4All:
				if option.Config.IsDualStack() {
					lbl = worldLabelV4
				} else {
					lbl = worldLabelNonDualStack
				}
			case ipv6All:
				if option.Config.IsDualStack() {
					lbl = worldLabelV6
				} else {
					lbl = worldLabelNonDualStack
				}
			default:
				lbl, _ = labels.IPStringToLabel(string(r.Cidr))
			}
			ls.MatchExpressions = append(ls.MatchExpressions, slim_metav1.LabelSelectorRequirement{
				Key:      lbl.GetExtendedKey(),
				Operator: slim_metav1.LabelSelectorOpExists,
			})
		} else if r.CIDRGroupRef != "" {
			lbl := LabelForCIDRGroupRef(string(r.CIDRGroupRef))
			ls.MatchExpressions = append(ls.MatchExpressions, slim_metav1.LabelSelectorRequirement{
				Key:      lbl.GetExtendedKey(),
				Operator: slim_metav1.LabelSelectorOpExists,
			})
		} else if r.CIDRGroupSelector != nil {
			ls = *NewESFromK8sLabelSelector(labels.LabelSourceCIDRGroupKeyPrefix, r.CIDRGroupSelector).LabelSelector
		} else {
			// should never be hit, but paranoia
			continue
		}

		// exclude any excepted CIDRs.
		// Do so by inserting a "DoesNotExist" requirement for the given prefix key
		for _, exceptCIDR := range r.ExceptCIDRs {
			lbl, _ := labels.IPStringToLabel(string(exceptCIDR))
			ls.MatchExpressions = append(ls.MatchExpressions, slim_metav1.LabelSelectorRequirement{
				Key:      lbl.GetExtendedKey(),
				Operator: slim_metav1.LabelSelectorOpDoesNotExist,
			})
		}

		ces = append(ces, NewESFromK8sLabelSelector("", &ls))
	}

	return ces
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

// +kubebuilder:validation:MaxLength=253
// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`
//
// CIDRGroupRef is a reference to a CIDR Group.
// A CIDR Group is a list of CIDRs whose IP addresses should be considered as a
// same entity when applying fromCIDRGroupRefs policies on incoming network traffic.
type CIDRGroupRef string

const LabelPrefixGroupName = "io.cilium.policy.cidrgroupname"

func LabelForCIDRGroupRef(ref string) labels.Label {
	var key strings.Builder
	key.Grow(len(LabelPrefixGroupName) + len(ref) + 1)
	key.WriteString(LabelPrefixGroupName)
	key.WriteString("/")
	key.WriteString(ref)
	return labels.NewLabel(
		key.String(),
		"",
		labels.LabelSourceCIDRGroup,
	)
}
