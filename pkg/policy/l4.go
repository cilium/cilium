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
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
	log "github.com/sirupsen/logrus"
)

const (
	// WildcardEndpointSelector is a special hash value for the wildcard endpoint, i.e., applies to all
	WildcardEndpointSelector = iota
)

// L7DataMap contains a map of L7 rules per endpoint where key is a hash of EndpointSelector
type L7DataMap map[uint64]api.L7Rules

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
	Port int
	// Protocol is the L4 protocol to allow or NONE
	Protocol string
	// FromEndpoints limit the source labels for allowing traffic. If
	// FromEndpoints is empty, then it selects all endpoints.
	FromEndpoints []api.EndpointSelector `json:"-"`
	// L7Parser specifies the L7 protocol parser (optional)
	L7Parser L7ParserType
	// L7RedirectPort is the L7 proxy port to redirect to (optional)
	L7RedirectPort int
	// L7RulesPerEp is a list of L7 rules per endpoint passed to the L7 proxy (optional)
	L7RulesPerEp L7DataMap
	// Ingress is true if filter applies at ingress
	Ingress bool
}

func (dm L7DataMap) addRulesForEndpoints(rules api.L7Rules,
	fromEndpoints []api.EndpointSelector) error {

	if rules.Len() == 0 {
		return nil
	}
	if len(fromEndpoints) > 0 {
		for _, ep := range fromEndpoints {
			hash, err := ep.Hash()
			if err != nil || hash == 0 {
				return fmt.Errorf("Could not hash (%d) endpoint %e", hash, err)
			}
			dm[hash] = api.L7Rules{
				HTTP:  append(dm[hash].HTTP, rules.HTTP...),
				Kafka: append(dm[hash].Kafka, rules.Kafka...),
			}
		}
	} else {
		// If there are no explicit fromEps, have a 'special' wildcard endpoint.
		dm[WildcardEndpointSelector] = api.L7Rules{
			HTTP:  append(dm[WildcardEndpointSelector].HTTP, rules.HTTP...),
			Kafka: append(dm[WildcardEndpointSelector].Kafka, rules.Kafka...),
		}
	}

	return nil
}

// CreateL4Filter creates an L4Filter for the specified api.PortProtocol in
// the direction ("ingress"/"egress") for a particular protocol.
// This L4Filter will only apply to endpoints covered by `fromEndpoints`.
// `rule` allows a series of L7 rules to be associated with this L4Filter.
func CreateL4Filter(fromEndpoints []api.EndpointSelector, rule api.PortRule, port api.PortProtocol,
	direction string, protocol string) L4Filter {

	// already validated via PortRule.Validate()
	p, _ := strconv.ParseUint(port.Port, 0, 16)

	l4 := L4Filter{
		Port:           int(p),
		Protocol:       protocol,
		L7RedirectPort: rule.RedirectPort,
		L7RulesPerEp:   make(map[uint64]api.L7Rules),
		FromEndpoints:  fromEndpoints,
	}

	if strings.ToLower(direction) == "ingress" {
		l4.Ingress = true
	}

	if rule.Rules != nil {
		switch {
		case len(rule.Rules.HTTP) > 0:
			l4.L7Parser = ParserTypeHTTP
		case len(rule.Rules.Kafka) > 0:
			l4.L7Parser = ParserTypeKafka
		}
		if err := l4.L7RulesPerEp.addRulesForEndpoints(*rule.Rules,
			fromEndpoints); err != nil {

			log.Errorf("%s", err)
			return L4Filter{}
		}
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
		return err.Error()
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
// Returns api.Denied in the following conditions:
// * If the `L4PolicyMap` has at least one rule and `ports` is empty.
// * If a single port is not present in the `L4PolicyMap`.
// * If a port is present in the `L4PolicyMap`, but it applies FromEndpoints
//   constraints that require labels not present in `labels`.
// Otherwise, returns api.Allowed.
func (l4 L4PolicyMap) containsAllL3L4(labels labels.LabelArray, ports []*models.Port) api.Decision {
	if len(l4) == 0 {
		return api.Allowed
	}

	if len(ports) == 0 {
		return api.Denied
	}

	for _, l4CtxIng := range ports {
		lwrProtocol := strings.ToLower(l4CtxIng.Protocol)
		switch lwrProtocol {
		case "", models.PortProtocolAny:
			tcpPort := fmt.Sprintf("%d/tcp", l4CtxIng.Port)
			tcpFilter, tcpmatch := l4[tcpPort]
			if tcpmatch {
				tcpmatch = tcpFilter.matchesLabels(labels)
			}
			udpPort := fmt.Sprintf("%d/udp", l4CtxIng.Port)
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
	Ingress L4PolicyMap
	Egress  L4PolicyMap
}

func NewL4Policy() *L4Policy {
	return &L4Policy{
		Ingress: make(L4PolicyMap),
		Egress:  make(L4PolicyMap),
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

	ingress := []string{}
	for _, v := range l4.Ingress {
		ingress = append(ingress, v.MarshalIndent())
	}

	egress := []string{}
	for _, v := range l4.Egress {
		egress = append(egress, v.MarshalIndent())
	}

	return &models.L4Policy{
		Ingress: ingress,
		Egress:  egress,
	}
}

func (l4 *L4Policy) DeepCopy() *L4Policy {
	cpy := &L4Policy{
		Ingress: make(L4PolicyMap, len(l4.Ingress)),
		Egress:  make(L4PolicyMap, len(l4.Egress)),
	}

	for k, v := range l4.Ingress {
		cpy.Ingress[k] = v
	}

	for k, v := range l4.Egress {
		cpy.Egress[k] = v
	}

	return cpy
}
