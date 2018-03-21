// Copyright 2016-2017 Authors of Cilium
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

package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api/v3"
	"github.com/cilium/cilium/pkg/u8proto"
)

var (
	// WildcardIdentitySelector is a selector that matches on all endpoints
	WildcardIdentitySelector = v3.NewWildcardIdentitySelector()
)

// L7DataMap contains a map of L7 rules per endpoint where key is a hash of IdentitySelector
type L7DataMap map[v3.IdentitySelector]v3.L7Rules

func (l7 L7DataMap) MarshalJSON() ([]byte, error) {
	if len(l7) == 0 {
		return []byte("[]"), nil
	}

	/* First, create a sorted slice of the selectors so we can get
	 * consistent JSON output */
	selectors := make(v3.IdentitySelectorSlice, 0, len(l7))
	for es := range l7 {
		selectors = append(selectors, es)
	}
	sort.Sort(selectors)

	/* Now we can iterate the slice and generate JSON entries. */
	var err error
	buffer := bytes.NewBufferString("[")
	for _, es := range selectors {
		buffer.WriteString("{\"")
		buffer.WriteString(es.LabelSelectorString())
		buffer.WriteString("\":")
		b, err := json.Marshal(l7[es])
		if err == nil {
			buffer.Write(b)
		} else {
			buffer.WriteString("\"L7DataMap error: ")
			buffer.WriteString(err.Error())
			buffer.WriteString("\"")
		}
		buffer.WriteString("},")
	}
	buffer.Truncate(buffer.Len() - 1) // Drop the final ","
	buffer.WriteString("]")

	return buffer.Bytes(), err
}

// L7ParserType is the type used to indicate what L7 parser to use and
// defines all supported types of L7 parsers
type L7ParserType string

const (
	// ParserTypeHTTP specifies a HTTP parser type
	ParserTypeHTTP L7ParserType = "http"
	// ParserTypeKafka specifies a Kafka parser type
	ParserTypeKafka L7ParserType = "kafka"
)

type L4Filter struct {
	// Port is the destination port to allow
	Port int `json:"port"`
	// Protocol is the L4 protocol to allow or NONE
	Protocol v3.L4Proto `json:"protocol"`
	// U8Proto is the Protocol in numeric format, or 0 for NONE
	U8Proto u8proto.U8proto `json:"-"`
	// FromEndpoints limit the source labels for allowing traffic. If
	// FromEndpoints is empty, then it selects all endpoints.
	FromEndpoints []v3.IdentitySelector `json:"-"`
	// L7Parser specifies the L7 protocol parser (optional)
	L7Parser L7ParserType `json:"-"`
	// L7RulesPerEp is a list of L7 rules per endpoint passed to the L7 proxy (optional)
	L7RulesPerEp L7DataMap `json:"l7-rules,omitempty"`
	// Ingress is true if filter applies at ingress
	Ingress bool `json:"-"`
	// The rule labels of this Filter
	DerivedFromRules labels.LabelArrayList `json:"-"`
}

// GetRelevantRules returns the relevant rules based on the source and
// destination addressing/identity information.
func (dm L7DataMap) GetRelevantRules(identity *identity.Identity) v3.L7Rules {
	rules := v3.L7Rules{}
	matched := 0

	if identity != nil {
		for selector, endpointRules := range dm {
			if selector.Matches(identity.Labels.LabelArray()) {
				matched++
				rules.HTTP = append(rules.HTTP, endpointRules.HTTP...)
				rules.Kafka = append(rules.Kafka, endpointRules.Kafka...)
			}
		}
	}

	if matched == 0 {
		// Fall back to wildcard selector
		if rules, ok := dm[WildcardIdentitySelector]; ok {
			return rules
		}
	}

	return rules
}

func (dm L7DataMap) addRulesForEndpoints(rules v3.L7Rules, fromEndpoints *v3.IdentitySelector) {
	if rules.Len() == 0 {
		return
	}

	if fromEndpoints != nil {
		dm[*fromEndpoints] = rules
	} else {
		// If there are no explicit fromEps, have a 'special' wildcard endpoint.
		dm[WildcardIdentitySelector] = rules
	}
}

// CreateL4Filter creates an L4Filter for the specified v3.PortProtocol in
// the direction ("ingress"/"egress") for a particular protocol.
// This L4Filter will only apply to endpoints covered by `fromEndpoints`.
// `rule` allows a series of L7 rules to be associated with this L4Filter.
func CreateL4Filter(fromEndpoint *v3.IdentitySelector, rule *v3.PortRule, port v3.PortProtocol,
	direction string, protocol v3.L4Proto, ruleLabels labels.LabelArray) L4Filter {

	// already validated via PortRule.Validate()
	p, _ := strconv.ParseUint(port.Port, 0, 16)
	// already validated via L4Proto.Validate()
	u8p, _ := u8proto.ParseProtocol(string(protocol))

	var fromEndpoints []v3.IdentitySelector
	if fromEndpoint == nil {
		fromEndpoints = []v3.IdentitySelector{}
	} else {
		fromEndpoints = []v3.IdentitySelector{*fromEndpoint}
	}

	l4 := L4Filter{
		Port:             int(p),
		Protocol:         protocol,
		U8Proto:          u8p,
		L7RulesPerEp:     make(L7DataMap),
		FromEndpoints:    fromEndpoints,
		DerivedFromRules: labels.LabelArrayList{ruleLabels},
	}

	if strings.ToLower(direction) == "ingress" {
		l4.Ingress = true
	}

	if rule != nil && rule.Rules != nil && protocol == v3.ProtoTCP {
		switch {
		case len(rule.Rules.HTTP) > 0:
			l4.L7Parser = ParserTypeHTTP
		case len(rule.Rules.Kafka) > 0:
			l4.L7Parser = ParserTypeKafka
		}

		l4.L7RulesPerEp.addRulesForEndpoints(*rule.Rules, fromEndpoint)
	}

	return l4
}

// IsRedirect returns true if the L4 filter contains a port redirection
func (l4 *L4Filter) IsRedirect() bool {
	return l4.L7Parser != ""
}

// MarshalIndent returns the `L4Filter` in indented JSON string.
func (l4 *L4Filter) MarshalIndent() string {
	b, err := json.MarshalIndent(l4, "", "  ")
	if err != nil {
		b = []byte("\"L4Filter error: " + err.Error() + "\"")
	}
	return string(b)
}

// String returns the `L4Filter` in a human-readable string.
func (l4 L4Filter) String() string {
	b, err := json.Marshal(l4)
	if err != nil {
		return err.Error()
	}
	return string(b)
}

func (l4 L4Filter) matchesLabels(labels labels.LabelArray) bool {
	if len(l4.FromEndpoints) == 0 {
		return true
	} else if len(labels) == 0 {
		return false
	}

	for _, sel := range l4.FromEndpoints {
		if sel.Matches(labels) {
			return true
		}
	}

	return false
}

// L4PolicyMap is a list of L4 filters indexable by protocol/port
// key format: "port/proto"
type L4PolicyMap map[string]L4Filter

// HasRedirect returns true if at least one L4 filter contains a port
// redirection
func (l4 L4PolicyMap) HasRedirect() bool {
	for _, f := range l4 {
		if f.IsRedirect() {
			return true
		}
	}

	return false
}

// containsAllL3L4 checks if the L4PolicyMap contains all L4 ports in `ports`.
// For L4Filters that specify FromEndpoints, uses `labels` to determine whether
// the policy allows L4 communication between the corresponding endpoints.
// Returns v3.Denied in the following conditions:
// * If the `L4PolicyMap` has at least one rule and `ports` is empty.
// * If a single port is not present in the `L4PolicyMap`.
// * If a port is present in the `L4PolicyMap`, but it applies FromEndpoints
//   constraints that require labels not present in `labels`.
// Otherwise, returns v3.Allowed.
func (l4 L4PolicyMap) containsAllL3L4(labels labels.LabelArray, ports []*models.Port) v3.Decision {
	if len(l4) == 0 {
		return v3.Allowed
	}

	if len(ports) == 0 {
		return v3.Denied
	}

	for _, l4CtxIng := range ports {
		lwrProtocol := l4CtxIng.Protocol
		switch lwrProtocol {
		case "", models.PortProtocolANY:
			tcpPort := fmt.Sprintf("%d/TCP", l4CtxIng.Port)
			tcpFilter, tcpmatch := l4[tcpPort]
			if tcpmatch {
				tcpmatch = tcpFilter.matchesLabels(labels)
			}
			udpPort := fmt.Sprintf("%d/UDP", l4CtxIng.Port)
			udpFilter, udpmatch := l4[udpPort]
			if udpmatch {
				udpmatch = udpFilter.matchesLabels(labels)
			}
			if !tcpmatch && !udpmatch {
				return v3.Denied
			}
		default:
			port := fmt.Sprintf("%d/%s", l4CtxIng.Port, lwrProtocol)
			filter, match := l4[port]
			if !match || !filter.matchesLabels(labels) {
				return v3.Denied
			}
		}
	}
	return v3.Allowed
}

type L4Policy struct {
	Ingress L4PolicyMap
	Egress  L4PolicyMap

	// Revision is the repository revision used to generate this policy.
	Revision uint64
}

func NewL4Policy() *L4Policy {
	return &L4Policy{
		Ingress:  L4PolicyMap{},
		Egress:   L4PolicyMap{},
		Revision: 0,
	}
}

// IngressCoversDPorts checks if the receiver's ingress `L4Policy` contains all
// `dPorts`.
func (l4 *L4Policy) IngressCoversDPorts(dPorts []*models.Port) v3.Decision {
	return l4.Ingress.containsAllL3L4(labels.LabelArray{}, dPorts)
}

// IngressCoversContext checks if the receiver's ingress `L4Policy` contains
// all `dPorts` and `labels`.
func (l4 *L4Policy) IngressCoversContext(ctx *SearchContext) v3.Decision {
	return l4.Ingress.containsAllL3L4(ctx.From, ctx.DPorts)
}

// EgressCoversDPorts checks if the receiver's egress `L4Policy` contains all
// `dPorts`.
func (l4 *L4Policy) EgressCoversDPorts(dPorts []*models.Port) v3.Decision {
	return l4.Egress.containsAllL3L4(labels.LabelArray{}, dPorts)
}

// HasRedirect returns true if the L4 policy contains at least one port redirection
func (l4 *L4Policy) HasRedirect() bool {
	return l4 != nil && (l4.Ingress.HasRedirect() || l4.Egress.HasRedirect())
}

// RequiresConntrack returns true if if the L4 configuration requires
// connection tracking to be enabled.
func (l4 *L4Policy) RequiresConntrack() bool {
	return l4 != nil && (len(l4.Ingress) > 0 || len(l4.Egress) > 0)
}

func (l4 *L4Policy) GetModel() *models.L4Policy {
	if l4 == nil {
		return nil
	}

	ingress := []*models.PolicyRule{}
	for _, v := range l4.Ingress {
		ingress = append(ingress, &models.PolicyRule{
			Rule:             v.MarshalIndent(),
			DerivedFromRules: v.DerivedFromRules.GetModel(),
		})
	}

	egress := []*models.PolicyRule{}
	for _, v := range l4.Egress {
		egress = append(egress, &models.PolicyRule{
			Rule:             v.MarshalIndent(),
			DerivedFromRules: v.DerivedFromRules.GetModel(),
		})
	}

	return &models.L4Policy{
		Ingress: ingress,
		Egress:  egress,
	}
}
