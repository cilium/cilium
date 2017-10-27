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
	"strconv"
	"strings"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
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

	var err error
	buffer := bytes.NewBufferString("[")
	for k, v := range l7 {
		buffer.WriteString("\n  {    \n    \"")
		buffer.WriteString(k.LabelSelectorString())
		buffer.WriteString("\": ")
		b, err := json.MarshalIndent(v, "    ", "  ")
		if err == nil {
			buffer.Write(b)
		} else {
			buffer.WriteString("\"L7DataMap error: ")
			buffer.WriteString(err.Error())
			buffer.WriteString("\"")
		}
		buffer.WriteString("\n  },")
	}
	buffer.Truncate(buffer.Len() - 1) // Drop the final ","
	buffer.WriteString("\n]")

	return buffer.Bytes(), err
}

type L4Filter struct {
	// Port is the destination port to allow
	Port int `json:"port"`
	// Protocol is the L4 protocol to allow or NONE
	Protocol api.L4Proto `json:"protocol"`
	// FromEndpoints limit the source labels for allowing traffic. If
	// FromEndpoints is empty, then it selects all endpoints.
	FromEndpoints []api.EndpointSelector `json:"-"`
	// L7Parser specifies the L7 protocol parser (optional)
	L7Parser api.L7ParserType `json:"-"`
	// L7RedirectPort is the L7 proxy port to redirect to (optional)
	L7RedirectPort int `json:"l7RedirectPort,omitempty"`
	// L7RulesPerEp is a list of L7 rules per endpoint passed to the L7 proxy (optional)
	L7RulesPerEp L7DataMap `json:"l7Rules,omitempty"`
	// Ingress is true if filter applies at ingress
	Ingress bool `json:"-"`
}

// GetRelevantRules returns the relevant rules based on the source and
// destination addressing/identity information.
func (dm L7DataMap) GetRelevantRules(identity *Identity) api.L7Rules {
	rules := api.L7Rules{}
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
		if rules, ok := dm[WildcardEndpointSelector]; ok {
			return rules
		}
	}

	return rules
}

func (dm L7DataMap) addRulesForEndpoints(rules api.L7Rules, fromEndpoints []api.EndpointSelector) {
	if rules.Len() == 0 {
		return
	}

	if len(fromEndpoints) > 0 {
		for _, ep := range fromEndpoints {
			dm[ep] = api.L7Rules{
				HTTP:  append(dm[ep].HTTP, rules.HTTP...),
				Kafka: append(dm[ep].Kafka, rules.Kafka...),
			}
		}
	} else {
		// If there are no explicit fromEps, have a 'special' wildcard endpoint.
		dm[WildcardEndpointSelector] = api.L7Rules{
			HTTP:  append(dm[WildcardEndpointSelector].HTTP, rules.HTTP...),
			Kafka: append(dm[WildcardEndpointSelector].Kafka, rules.Kafka...),
		}
	}
}

// CreateL4Filter creates an L4Filter for the specified api.PortProtocol in
// the direction ("ingress"/"egress") for a particular protocol.
// This L4Filter will only apply to endpoints covered by `fromEndpoints`.
// `rule` allows a series of L7 rules to be associated with this L4Filter.
func CreateL4Filter(fromEndpoints []api.EndpointSelector, rule api.PortRule, port api.PortProtocol,
	direction string) L4Filter {

	// Already validated via PortRule.sanitize().
	p, _ := strconv.ParseUint(port.Port, 0, 16)

	l4 := L4Filter{
		Port:           int(p),
		Protocol:       port.Protocol,
		L7RedirectPort: rule.RedirectPort,
		L7RulesPerEp:   make(L7DataMap),
		FromEndpoints:  fromEndpoints,
	}

	if strings.ToLower(direction) == "ingress" {
		l4.Ingress = true
	}

	if rule.Rules != nil {
		switch {
		case len(rule.Rules.HTTP) > 0:
			l4.L7Parser = api.ParserTypeHTTP
		case len(rule.Rules.Kafka) > 0:
			l4.L7Parser = api.ParserTypeKafka
		}

		l4.L7RulesPerEp.addRulesForEndpoints(*rule.Rules, fromEndpoints)
	}

	return l4
}

// MatchesAnyPort returns true if the L4 filter matches any port.
func (l4 *L4Filter) MatchesAnyPort() bool {
	return l4.Protocol == api.ProtoAny && l4.Port == 0
}

// IsRedirect returns true if the L4 filter contains a port redirection.
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

// L4PolicyMap is a list of L4 filters indexed by L4 port/protocol.
// Key format: "port/proto".
type L4PolicyMap map[string]L4Filter

// L7VisibilityRule is an active ingress visibility rule.
type L7VisibilityRule struct {
	// Port is the destination L4 port to redirect to L7 for access logging.
	Port uint16 `json:"port"`
	// Protocol is the port's L4 protocol.
	Protocol api.L4Proto `json:"protocol"`
	// L7Protocol specifies the L7 protocol parser.
	L7Protocol api.L7ParserType `json:"l7Protocol"`
}

// MarshalIndent returns the `L7VisibilityRule` in indented JSON string.
func (v *L7VisibilityRule) MarshalIndent() string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err.Error()
	}
	return string(b)
}

// L7VisibilityMap is a list of L7 ingress visibility rules indexed by L4 port/protocol.
// Key format: "port/proto".
type L7VisibilityMap map[string]L7VisibilityRule

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
// Returns api.Denied in the following conditions:
// * If the `L4PolicyMap` has at least one rule and `ports` is empty.
// * If a single port is not present in the `L4PolicyMap`.
// * If a port is present in the `L4PolicyMap`, but it applies FromEndpoints
//   constraints that require labels not present in `labels`, and there is no
//   rule maching on "any port".
// Otherwise, returns api.Allowed.
func (l4 L4PolicyMap) containsAllL3L4(labels labels.LabelArray, ports []*models.Port) api.Decision {
	if len(l4) == 0 {
		return api.Allowed
	}

	if len(ports) == 0 {
		return api.Denied
	}

	// Check any rule that accepts any port.
	anyPortFilter, match := l4[fmt.Sprintf("%d/%s", 0, api.ProtoAny)]
	if match && anyPortFilter.matchesLabels(labels) {
		return api.Allowed
	}

	for _, l4CtxIng := range ports {
		lwrProtocol := l4CtxIng.Protocol
		switch lwrProtocol {
		case "", models.PortProtocolANY:
			tcpPort := fmt.Sprintf("%d/%s", l4CtxIng.Port, api.ProtoTCP)
			tcpFilter, tcpmatch := l4[tcpPort]
			if tcpmatch {
				tcpmatch = tcpFilter.matchesLabels(labels)
			}
			udpPort := fmt.Sprintf("%d/%s", l4CtxIng.Port, api.ProtoUDP)
			udpFilter, udpmatch := l4[udpPort]
			if udpmatch {
				udpmatch = udpFilter.matchesLabels(labels)
			}
			if !tcpmatch && !udpmatch {
				return api.Denied
			}
		default:
			port := fmt.Sprintf("%d/%s", l4CtxIng.Port, lwrProtocol)
			filter, match := l4[port]
			if !match || !filter.matchesLabels(labels) {
				return api.Denied
			}
		}
	}
	return api.Allowed
}

type L4Policy struct {
	Ingress           L4PolicyMap
	Egress            L4PolicyMap
	IngressVisibility L7VisibilityMap
}

func NewL4Policy() *L4Policy {
	return &L4Policy{
		Ingress:           make(L4PolicyMap),
		Egress:            make(L4PolicyMap),
		IngressVisibility: make(L7VisibilityMap),
	}
}

// IngressCoversDPorts checks if the receiver's ingress `L4Policy` contains all
// `dPorts`.
func (l4 *L4Policy) IngressCoversDPorts(dPorts []*models.Port) api.Decision {
	return l4.Ingress.containsAllL3L4(labels.LabelArray{}, dPorts)
}

// IngressCoversContext checks if the receiver's ingress `L4Policy` contains
// all `dPorts` and `labels`.
func (l4 *L4Policy) IngressCoversContext(ctx *SearchContext) api.Decision {
	return l4.Ingress.containsAllL3L4(ctx.From, ctx.DPorts)
}

// EgressCoversDPorts checks if the receiver's egress `L4Policy` contains all
// `dPorts`.
func (l4 *L4Policy) EgressCoversDPorts(dPorts []*models.Port) api.Decision {
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

	ingress := make([]string, 0, len(l4.Ingress))
	for _, v := range l4.Ingress {
		ingress = append(ingress, v.MarshalIndent())
	}

	egress := make([]string, 0, len(l4.Egress))
	for _, v := range l4.Egress {
		egress = append(egress, v.MarshalIndent())
	}

	ingressVisibility := make([]string, 0, len(l4.IngressVisibility))
	for _, v := range l4.IngressVisibility {
		ingressVisibility = append(ingressVisibility, v.MarshalIndent())
	}

	return &models.L4Policy{
		Ingress:           ingress,
		Egress:            egress,
		IngressVisibility: ingressVisibility,
	}
}

func (l4 *L4Policy) DeepCopy() *L4Policy {
	cpy := &L4Policy{
		Ingress:           make(L4PolicyMap, len(l4.Ingress)),
		Egress:            make(L4PolicyMap, len(l4.Egress)),
		IngressVisibility: make(L7VisibilityMap, len(l4.IngressVisibility)),
	}

	for k, v := range l4.Ingress {
		cpy.Ingress[k] = v
	}

	for k, v := range l4.Egress {
		cpy.Egress[k] = v
	}

	for k, v := range l4.IngressVisibility {
		cpy.IngressVisibility[k] = v
	}

	return cpy
}
