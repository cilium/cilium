// Copyright 2016-2019 Authors of Cilium
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
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/u8proto"
)

// L7DataMap contains a map of L7 rules per endpoint where key is a CachedSelector
type L7DataMap map[CachedSelector]api.L7Rules

func (l7 L7DataMap) MarshalJSON() ([]byte, error) {
	if len(l7) == 0 {
		return []byte("[]"), nil
	}

	/* First, create a sorted slice of the selectors so we can get
	 * consistent JSON output */
	selectors := make(CachedSelectorSlice, 0, len(l7))
	for cs := range l7 {
		selectors = append(selectors, cs)
	}
	sort.Sort(selectors)

	/* Now we can iterate the slice and generate JSON entries. */
	var err error
	buffer := bytes.NewBufferString("[")
	for _, cs := range selectors {
		buffer.WriteString("{\"")
		buffer.WriteString(cs.String())
		buffer.WriteString("\":")
		b, err := json.Marshal(l7[cs])
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

// L7ParserType is the type used to indicate what L7 parser to use.
// Consts are defined for all well known L7 parsers.
// Unknown string values are created for key-value pair policies, which
// are then transparently used in redirect configuration.
type L7ParserType string

func (l7 L7ParserType) String() string {
	return (string)(l7)
}

const (
	// ParserTypeNone represents the case where no parser type is provided.
	ParserTypeNone L7ParserType = ""
	// ParserTypeHTTP specifies a HTTP parser type
	ParserTypeHTTP L7ParserType = "http"
	// ParserTypeKafka specifies a Kafka parser type
	ParserTypeKafka L7ParserType = "kafka"
	// ParserTypeDNS specifies a DNS parser type
	ParserTypeDNS L7ParserType = "dns"
)

type L4Filter struct {
	// Port is the destination port to allow
	Port int `json:"port"`
	// Protocol is the L4 protocol to allow or NONE
	Protocol api.L4Proto `json:"protocol"`
	// U8Proto is the Protocol in numeric format, or 0 for NONE
	U8Proto u8proto.U8proto `json:"-"`
	// allowsAllAtL3 indicates whether this filter allows all traffic at L3.
	// This can be determined by checking whether 'Endpoints' contains
	// 'wildcardCachedSelector', but caching this information instead is
	// much more performant.
	allowsAllAtL3 bool
	// CachedSelectors limits the labels for allowing traffic (to / from).
	// This includes selectors for destinations affected by entity-based
	// and CIDR-based policy.
	// Holds references to the CachedSelectors, which must be released!
	CachedSelectors CachedSelectorSlice `json:"-"`
	// L7Parser specifies the L7 protocol parser (optional). If specified as
	// an empty string, then means that no L7 proxy redirect is performed.
	L7Parser L7ParserType `json:"-"`
	// L7RulesPerEp is a list of L7 rules per endpoint passed to the L7 proxy (optional)
	L7RulesPerEp L7DataMap `json:"l7-rules,omitempty"`
	// Ingress is true if filter applies at ingress; false if it applies at egress.
	Ingress bool `json:"-"`
	// The rule labels of this Filter
	DerivedFromRules labels.LabelArrayList `json:"-"`
}

// AllowsAllAtL3 returns whether this L4Filter applies to all endpoints at L3.
func (l4 *L4Filter) AllowsAllAtL3() bool {
	return l4.allowsAllAtL3
}

// HasL3DependentL7Rules returns true if this L4Filter is created from rules
// that require an L3 match as well as specific L7 rules.
func (l4 *L4Filter) HasL3DependentL7Rules() bool {
	switch len(l4.L7RulesPerEp) {
	case 0:
		// No L7 rules.
		return false
	case 1:
		// loop to get access to the first and only key in the map
		for cs := range l4.L7RulesPerEp {
			// If L3 is wildcarded, this filter corresponds to L4-only rule(s).
			return !cs.IsWildcard()
		}
	}
	return true
}

// ToKeys converts filter into a list of Keys.
func (l4 *L4Filter) ToKeys(direction trafficdirection.TrafficDirection) []Key {
	keysToAdd := []Key{}
	port := uint16(l4.Port)
	proto := uint8(l4.U8Proto)

	// The BPF datapath only supports a value of '0' for identity (wildcarding
	// at L3) if there is a corresponding port (i.e., a non-zero port).
	// Wildcarding at L3 and L4 at the same time is not understood by the
	// datapath at this time. So, if we have L3-only policy (e.g., port == 0),
	// we need to explicitly allow each identity at port 0.
	if l4.AllowsAllAtL3() && l4.Port != 0 {
		keyToAdd := Key{
			Identity: 0,
			// NOTE: Port is in host byte-order!
			DestPort:         port,
			Nexthdr:          proto,
			TrafficDirection: direction.Uint8(),
		}
		keysToAdd = append(keysToAdd, keyToAdd)
		if !l4.HasL3DependentL7Rules() {
			return keysToAdd
		} // else we need to calculate all L3-dependent L4 peers below.
	}

	for _, cs := range l4.CachedSelectors {
		identities := cs.GetSelections()
		log.Debugf("ToKeys: Allowed remote IDs for selector %v: %v", cs, identities)
		for _, id := range identities {
			srcID := id.Uint32()
			keyToAdd := Key{
				Identity: srcID,
				// NOTE: Port is in host byte-order!
				DestPort:         port,
				Nexthdr:          proto,
				TrafficDirection: direction.Uint8(),
			}
			keysToAdd = append(keysToAdd, keyToAdd)
		}
	}

	return keysToAdd
}

// IdentitySelectionUpdated implements CachedSelectionUser interface
func (l4 *L4Filter) IdentitySelectionUpdated(selector CachedSelector, selections, added, deleted []identity.NumericIdentity) {
	log.Infof("L4Filter::IdentitySelectionUpdated(selector: %v, selections: %v, added: %v, deleted: %v) call received",
		selector, selections, added, deleted)
}

func (l4 *L4Filter) cacheIdentitySelector(sel api.EndpointSelector, selectorCache *SelectorCache) CachedSelector {
	cs, added := selectorCache.AddIdentitySelector(l4, sel)
	if added {
		l4.CachedSelectors = append(l4.CachedSelectors, cs)
	}
	return cs
}

func (l4 *L4Filter) cacheIdentitySelectors(selectors api.EndpointSelectorSlice, selectorCache *SelectorCache) {
	for _, sel := range selectors {
		l4.cacheIdentitySelector(sel, selectorCache)
	}
}

// GetRelevantRulesForKafka returns the relevant rules based on the remote numeric identity.
func (l7 L7DataMap) GetRelevantRulesForKafka(nid identity.NumericIdentity) []api.PortRuleKafka {
	var rules []api.PortRuleKafka

	for cs, r := range l7 {
		if cs.IsWildcard() || cs.Selects(nid) {
			rules = append(rules, r.Kafka...)
		}
	}
	return rules
}

func (l7 L7DataMap) addRulesForEndpoints(rules api.L7Rules, endpoints []CachedSelector) {
	if rules.Len() == 0 {
		return
	}

	for _, epsel := range endpoints {
		l7[epsel] = rules
	}
}

// createL4Filter creates a filter for L4 policy that applies to the specified
// endpoints and port/protocol, with reference to the original rules that the
// filter is derived from. This filter may be associated with a series of L7
// rules via the `rule` parameter.
// Not called with an empty peerEndpoints.
func createL4Filter(peerEndpoints api.EndpointSelectorSlice, rule api.PortRule, port api.PortProtocol,
	protocol api.L4Proto, ruleLabels labels.LabelArray, ingress bool, selectorCache *SelectorCache) *L4Filter {

	// already validated via PortRule.Validate()
	p, _ := strconv.ParseUint(port.Port, 0, 16)
	// already validated via L4Proto.Validate()
	u8p, _ := u8proto.ParseProtocol(string(protocol))

	l4 := &L4Filter{
		Port:             int(p),
		Protocol:         protocol,
		U8Proto:          u8p,
		L7RulesPerEp:     make(L7DataMap),
		DerivedFromRules: labels.LabelArrayList{ruleLabels},
		Ingress:          ingress,
	}

	if peerEndpoints.SelectsAllEndpoints() {
		l4.cacheIdentitySelector(api.WildcardEndpointSelector, selectorCache)
		l4.allowsAllAtL3 = true
	} else {
		l4.CachedSelectors = make(CachedSelectorSlice, 0, len(peerEndpoints))
		l4.cacheIdentitySelectors(peerEndpoints, selectorCache)
	}

	if protocol == api.ProtoTCP && rule.Rules != nil {
		switch {
		case len(rule.Rules.HTTP) > 0:
			l4.L7Parser = ParserTypeHTTP
		case len(rule.Rules.Kafka) > 0:
			l4.L7Parser = ParserTypeKafka
		case rule.Rules.L7Proto != "":
			l4.L7Parser = (L7ParserType)(rule.Rules.L7Proto)
		}
		if !rule.Rules.IsEmpty() {
			l4.L7RulesPerEp.addRulesForEndpoints(*rule.Rules, l4.CachedSelectors)
		}
	}

	// we need this to redirect DNS UDP (or ANY, which is more useful)
	if !rule.Rules.IsEmpty() && len(rule.Rules.DNS) > 0 {
		l4.L7Parser = ParserTypeDNS
		l4.L7RulesPerEp.addRulesForEndpoints(*rule.Rules, l4.CachedSelectors)
	}

	return l4
}

// detach releases the references held in the L4Filter and must be called before
// the filter is left to be garbage collected.
func (l4 *L4Filter) detach(selectorCache *SelectorCache) {
	selectorCache.RemoveSelectors(l4.CachedSelectors, l4)
}

// createL4IngressFilter creates a filter for L4 policy that applies to the
// specified endpoints and port/protocol for ingress traffic, with reference
// to the original rules that the filter is derived from. This filter may be
// associated with a series of L7 rules via the `rule` parameter.
//
// hostWildcardL7 determines if L7 traffic from Host should be
// wildcarded (in the relevant daemon mode).
func createL4IngressFilter(fromEndpoints api.EndpointSelectorSlice, hostWildcardL7 bool, rule api.PortRule, port api.PortProtocol,
	protocol api.L4Proto, ruleLabels labels.LabelArray, selectorCache *SelectorCache) *L4Filter {

	filter := createL4Filter(fromEndpoints, rule, port, protocol, ruleLabels, true, selectorCache)

	// If the filter would apply L7 rules for the Host, when we should accept everything from host,
	// then wildcard Host at L7.
	if !rule.Rules.IsEmpty() && hostWildcardL7 {
		for _, cs := range filter.CachedSelectors {
			if cs.Selects(identity.ReservedIdentityHost) {
				hostSelector := api.ReservedEndpointSelectors[labels.IDNameHost]
				hcs := filter.cacheIdentitySelector(hostSelector, selectorCache)
				filter.L7RulesPerEp[hcs] = api.L7Rules{}
			}
		}
	}

	return filter
}

// createL4EgressFilter creates a filter for L4 policy that applies to the
// specified endpoints and port/protocol for egress traffic, with reference
// to the original rules that the filter is derived from. This filter may be
// associated with a series of L7 rules via the `rule` parameter.
func createL4EgressFilter(toEndpoints api.EndpointSelectorSlice, rule api.PortRule, port api.PortProtocol,
	protocol api.L4Proto, ruleLabels labels.LabelArray, selectorCache *SelectorCache) *L4Filter {

	return createL4Filter(toEndpoints, rule, port, protocol, ruleLabels, false, selectorCache)
}

// IsRedirect returns true if the L4 filter contains a port redirection
func (l4 *L4Filter) IsRedirect() bool {
	return l4.L7Parser != ParserTypeNone
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
func (l4 *L4Filter) String() string {
	b, err := json.Marshal(l4)
	if err != nil {
		return err.Error()
	}
	return string(b)
}

// Note: Only used for policy tracing
func (l4 *L4Filter) matchesLabels(labels labels.LabelArray) bool {
	if l4.AllowsAllAtL3() {
		return true
	} else if len(labels) == 0 {
		return false
	}

	for _, sel := range l4.CachedSelectors {
		// slow, but OK for tracing
		if idSel, ok := sel.(*labelIdentitySelector); ok && idSel.xxxMatches(labels) {
			return true
		}
	}

	return false
}

// L4PolicyMap is a list of L4 filters indexable by protocol/port
// key format: "port/proto"
type L4PolicyMap map[string]*L4Filter

// Detach removes the cached selectors held by L4PolicyMap from the
// selectorCache, allowing the map to be garbage collected when there
// are no more references to it.
func (l4 L4PolicyMap) Detach(selectorCache *SelectorCache) {
	for _, f := range l4 {
		f.detach(selectorCache)
	}
}

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
// * If a single port is not present in the `L4PolicyMap` and is not allowed
//   by the distilled L3 policy
// * If a port is present in the `L4PolicyMap`, but it applies ToEndpoints or
//   FromEndpoints constraints that require labels not present in `labels`.
// Otherwise, returns api.Allowed.
//
// Note: Only used for policy tracing
func (l4 L4PolicyMap) containsAllL3L4(labels labels.LabelArray, ports []*models.Port) api.Decision {
	if len(l4) == 0 {
		return api.Allowed
	}

	// Check L3-only filters first.
	filter, match := l4[api.PortProtocolAny]
	if match && filter.matchesLabels(labels) {
		return api.Allowed
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

// Detach makes the L4Policy ready for garbage collection, removing
// circular pointer references.
// Note that the L4Policy itself is not modified in any way, so that it may still
// be used concurrently.
func (l4 *L4Policy) Detach(selectorCache *SelectorCache) {
	l4.Ingress.Detach(selectorCache)
	l4.Egress.Detach(selectorCache)
}

// IngressCoversContext checks if the receiver's ingress L4Policy contains
// all `dPorts` and `labels`.
//
// Note: Only used for policy tracing
func (l4 *L4PolicyMap) IngressCoversContext(ctx *SearchContext) api.Decision {
	return l4.containsAllL3L4(ctx.From, ctx.DPorts)
}

// EgressCoversContext checks if the receiver's egress L4Policy contains
// all `dPorts` and `labels`.
//
// Note: Only used for policy tracing
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
