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

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/u8proto"
)

var (
	// WildcardEndpointSelector is a selector that matches on all endpoints
	WildcardEndpointSelector = api.NewWildcardEndpointSelector()
)

// L7DataMap contains a map of L7 rules per endpoint where key is a hash of EndpointSelector
type L7DataMap map[api.EndpointSelector]api.L7Rules

func (l7 L7DataMap) MarshalJSON() ([]byte, error) {
	if len(l7) == 0 {
		return []byte("[]"), nil
	}

	/* First, create a sorted slice of the selectors so we can get
	 * consistent JSON output */
	selectors := make(api.EndpointSelectorSlice, 0, len(l7))
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
	Protocol api.L4Proto `json:"protocol"`
	// U8Proto is the Protocol in numeric format, or 0 for NONE
	U8Proto u8proto.U8proto `json:"-"`
	// Endpoints limits the labels for allowing traffic (to / from). If
	// Endpoints is empty, then it selects all endpoints.
	Endpoints []api.EndpointSelector `json:"-"`
	// L7Parser specifies the L7 protocol parser (optional)
	L7Parser L7ParserType `json:"-"`
	// L7RulesPerEp is a list of L7 rules per endpoint passed to the L7 proxy (optional)
	L7RulesPerEp L7DataMap `json:"l7-rules,omitempty"`
	// Ingress is true if filter applies at ingress; false if it applies at egress.
	Ingress bool `json:"-"`
	// The rule labels of this Filter
	DerivedFromRules labels.LabelArrayList `json:"-"`
}

// GetRelevantRules returns the relevant rules based on the source and
// destination addressing/identity information.
func (l7 L7DataMap) GetRelevantRules(identity *identity.Identity) api.L7Rules {
	rules := api.L7Rules{}
	matched := 0

	if identity != nil {
		for selector, endpointRules := range l7 {
			if selector.Matches(identity.Labels.LabelArray()) {
				matched++
				rules.HTTP = append(rules.HTTP, endpointRules.HTTP...)
				rules.Kafka = append(rules.Kafka, endpointRules.Kafka...)
			}
		}
	}

	if matched == 0 {
		// Fall back to wildcard selector
		if rules, ok := l7[WildcardEndpointSelector]; ok {
			return rules
		}
	}

	return rules
}

func (l7 L7DataMap) addRulesForEndpoints(rules api.L7Rules, endpoints []api.EndpointSelector) {
	if rules.Len() == 0 {
		return
	}

	if len(endpoints) > 0 {
		for _, epsel := range endpoints {
			l7[epsel] = rules
		}
	} else {
		// If there are no explicit fromEps, have a 'special' wildcard endpoint.
		l7[WildcardEndpointSelector] = rules
	}
}

// CreateL4IngressFilter creates an L4Filter for the specified api.PortProtocol in
// the ingress direction for a particular protocol.
// This L4Filter will only apply to endpoints covered by `fromEndpoints`.
// `rule` allows a series of L7 rules to be associated with this L4Filter.
func CreateL4IngressFilter(fromEndpoints []api.EndpointSelector, rule api.PortRule, port api.PortProtocol,
	protocol api.L4Proto, ruleLabels labels.LabelArray) L4Filter {

	// already validated via PortRule.Validate()
	p, _ := strconv.ParseUint(port.Port, 0, 16)
	// already validated via L4Proto.Validate()
	u8p, _ := u8proto.ParseProtocol(string(protocol))

	l4 := L4Filter{
		Port:             int(p),
		Protocol:         protocol,
		U8Proto:          u8p,
		L7RulesPerEp:     make(L7DataMap),
		Endpoints:        fromEndpoints,
		DerivedFromRules: labels.LabelArrayList{ruleLabels},
	}

	l4.Ingress = true

	if protocol == api.ProtoTCP && rule.Rules != nil {
		switch {
		case len(rule.Rules.HTTP) > 0:
			l4.L7Parser = ParserTypeHTTP
		case len(rule.Rules.Kafka) > 0:
			l4.L7Parser = ParserTypeKafka
		}

		l4.L7RulesPerEp.addRulesForEndpoints(*rule.Rules, fromEndpoints)
	}

	return l4
}

// CreateL4EgressFilter creates an L4Filter for the specified api.PortProtocol in
// the egress direction for a particular protocol.
// This L4Filter will only apply to endpoints covered by `fromEndpoints`.
// `rule` allows a series of L7 rules to be associated with this L4Filter.
func CreateL4EgressFilter(toEndpoints []api.EndpointSelector, rule api.PortRule, port api.PortProtocol,
	protocol api.L4Proto, ruleLabels labels.LabelArray) L4Filter {

	// already validated via PortRule.Validate()
	p, _ := strconv.ParseUint(port.Port, 0, 16)
	// already validated via L4Proto.Validate()
	u8p, _ := u8proto.ParseProtocol(string(protocol))

	l4 := L4Filter{
		Port:             int(p),
		Protocol:         protocol,
		U8Proto:          u8p,
		L7RulesPerEp:     make(L7DataMap),
		Endpoints:        toEndpoints,
		DerivedFromRules: labels.LabelArrayList{ruleLabels},
	}

	l4.Ingress = false

	if protocol == api.ProtoTCP && rule.Rules != nil {
		switch {
		case len(rule.Rules.HTTP) > 0:
			l4.L7Parser = ParserTypeHTTP
		case len(rule.Rules.Kafka) > 0:
			l4.L7Parser = ParserTypeKafka
		}

		l4.L7RulesPerEp.addRulesForEndpoints(*rule.Rules, toEndpoints)
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
	if len(l4.Endpoints) == 0 {
		return true
	} else if len(labels) == 0 {
		return false
	}

	for _, sel := range l4.Endpoints {
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
// For L4Filters that specify ToEndpoints or FromEndpoints, uses `labels` to
// determine whether the policy allows L4 communication between the corresponding
// endpoints.
// Returns api.Denied in the following conditions:
// * If the `L4PolicyMap` has at least one rule and `ports` is empty.
// * If a single port is not present in the `L4PolicyMap`.
// * If a port is present in the `L4PolicyMap`, but it applies ToEndpoints or
// FromEndpoints constraints that require labels not present in `labels`.
// Otherwise, returns api.Allowed.
func (l4 L4PolicyMap) containsAllL3L4(labels labels.LabelArray, ports []*models.Port) api.Decision {
	if len(l4) == 0 {
		return api.Allowed
	}

	if len(ports) == 0 {
		return api.Denied
	}

	for _, l4Ctx := range ports {
		lwrProtocol := l4Ctx.Protocol
		switch lwrProtocol {
		case "", models.PortProtocolANY:
			tcpPort := fmt.Sprintf("%d/TCP", l4Ctx.Port)
			tcpFilter, tcpmatch := l4[tcpPort]
			if tcpmatch {
				tcpmatch = tcpFilter.matchesLabels(labels)
			}
			udpPort := fmt.Sprintf("%d/UDP", l4Ctx.Port)
			udpFilter, udpmatch := l4[udpPort]
			if udpmatch {
				udpmatch = udpFilter.matchesLabels(labels)
			}
			if !tcpmatch && !udpmatch {
				return api.Denied
			}
		default:
			port := fmt.Sprintf("%d/%s", l4Ctx.Port, lwrProtocol)
			filter, match := l4[port]
			if !match || !filter.matchesLabels(labels) {
				return api.Denied
			}
		}
	}
	return api.Allowed
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

// IngressCoversContext checks if the receiver's ingress `L4Policy` contains
// all `dPorts` and `labels`.
func (l4 *L4PolicyMap) IngressCoversContext(ctx *SearchContext) api.Decision {
	return l4.containsAllL3L4(ctx.From, ctx.DPorts)
}

// EgressCoversContext checks if the receiver's egress `L4Policy` contains
// all `dPorts` and `labels`.
func (l4 *L4PolicyMap) EgressCoversContext(ctx *SearchContext) api.Decision {
	return l4.containsAllL3L4(ctx.To, ctx.DPorts)
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
