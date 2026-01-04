// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"errors"
	"fmt"

	"github.com/cilium/cilium/pkg/option"
)

const (
	maxPorts      = 40
	maxICMPFields = 40
)

var (
	ErrFromToNodesRequiresNodeSelectorOption = fmt.Errorf("FromNodes/ToNodes rules can only be applied when the %q flag is set", option.EnableNodeSelectorLabels)

	errUnsupportedICMPWithToPorts = errors.New("the ICMPs block may only be present without ToPorts. Define a separate rule to use ToPorts")
	errEmptyServerName            = errors.New("empty server name is not allowed")

	enableDefaultDenyDefault = true
)

func countL7Rules(ports []PortRule) map[string]int {
	result := make(map[string]int)
	for _, port := range ports {
		if !port.Rules.IsEmpty() {
			result["DNS"] += len(port.Rules.DNS)
			result["HTTP"] += len(port.Rules.HTTP)
			result["Kafka"] += len(port.Rules.Kafka)
		}
	}
	return result
}

// countNonGeneratedRules counts the number of CIDRRule items which are not
// `Generated`, i.e. were directly provided by the user.
// The `Generated` field is currently only set by the `ToServices`
// implementation, which extracts service endpoints and translates them as
// ToCIDRSet rules before the CNP is passed to the policy repository.
// Therefore, we want to allow the combination of ToCIDRSet and ToServices
// rules, if (and only if) the ToCIDRSet only contains `Generated` entries.
func countNonGeneratedCIDRRules(s CIDRRuleSlice) int {
	n := 0
	for _, c := range s {
		if !c.Generated {
			n++
		}
	}
	return n
}

// countNonGeneratedEndpoints counts the number of EndpointSelector items which are not
// `Generated`, i.e. were directly provided by the user.
// The `Generated` field is currently only set by the `ToServices`
// implementation, which extracts service endpoints and translates them as
// ToEndpoints rules before the CNP is passed to the policy repository.
// Therefore, we want to allow the combination of ToEndpoints and ToServices
// rules, if (and only if) the ToEndpoints only contains `Generated` entries.
func countNonGeneratedEndpoints(s []EndpointSelector) int {
	n := 0
	for _, c := range s {
		if !c.Generated {
			n++
		}
	}
	return n
}

func (e *EgressRule) l3Members() map[string]int {
	l3Members := e.EgressCommonRule.l3Members()
	l3Members["ToFQDNs"] = len(e.ToFQDNs)
	return l3Members
}

func (e *EgressRule) l3DependentL4Support() map[string]bool {
	l3DependentL4Support := e.EgressCommonRule.l3DependentL4Support()
	l3DependentL4Support["ToFQDNs"] = true
	return l3DependentL4Support
}

func (e *EgressDenyRule) l3Members() map[string]int {
	return e.EgressCommonRule.l3Members()
}

func (e *EgressDenyRule) l3DependentL4Support() map[string]bool {
	return e.EgressCommonRule.l3DependentL4Support()
}

func (e *EgressCommonRule) l3Members() map[string]int {
	return map[string]int{
		"ToCIDR":      len(e.ToCIDR),
		"ToCIDRSet":   countNonGeneratedCIDRRules(e.ToCIDRSet),
		"ToEndpoints": countNonGeneratedEndpoints(e.ToEndpoints),
		"ToEntities":  len(e.ToEntities),
		"ToServices":  len(e.ToServices),
		"ToGroups":    len(e.ToGroups),
		"ToNodes":     len(e.ToNodes),
	}
}

func (e *EgressCommonRule) l3DependentL4Support() map[string]bool {
	return map[string]bool{
		"ToCIDR":      true,
		"ToCIDRSet":   true,
		"ToEndpoints": true,
		"ToEntities":  true,
		"ToServices":  true,
		"ToGroups":    true,
		"ToNodes":     true,
	}
}

// It is not allowed to configure an ingress listener, but we still
// have some unit tests relying on this. So, allow overriding this check in the unit tests.
var TestAllowIngressListener = false
