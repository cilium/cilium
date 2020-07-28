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
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"unsafe"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/iana"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/cilium/proxy/go/cilium/api"

	"github.com/sirupsen/logrus"
)

// TLS context holds the secret values resolved from an 'api.TLSContext'
type TLSContext struct {
	TrustedCA        string `json:"trustedCA,omitempty"`
	CertificateChain string `json:"certificateChain,omitempty"`
	PrivateKey       string `json:"privateKey,omitempty"`
}

// Equal returns true if 'a' and 'b' have the same contents.
func (a *TLSContext) Equal(b *TLSContext) bool {
	return a == nil && b == nil || a != nil && b != nil && *a == *b
}

// MarshalJSON marsahls a redacted version of the TLSContext. We want
// to see which fields are present, but not reveal their values in any
// logs, etc.
func (t *TLSContext) MarshalJSON() ([]byte, error) {
	type tlsContext TLSContext
	var redacted tlsContext
	if t.TrustedCA != "" {
		redacted.TrustedCA = "[redacted]"
	}
	if t.CertificateChain != "" {
		redacted.CertificateChain = "[redacted]"
	}
	if t.PrivateKey != "" {
		redacted.PrivateKey = "[redacted]"
	}
	return json.Marshal(&redacted)
}

type PerSelectorPolicy struct {
	// TerminatingTLS is the TLS context for the connection terminated by
	// the L7 proxy.  For egress policy this specifies the server-side TLS
	// parameters to be applied on the connections originated from the local
	// POD and terminated by the L7 proxy. For ingress policy this specifies
	// the server-side TLS parameters to be applied on the connections
	// originated from a remote source and terminated by the L7 proxy.
	TerminatingTLS *TLSContext `json:"terminatingTLS,omitempty"`

	// OriginatingTLS is the TLS context for the connections originated by
	// the L7 proxy.  For egress policy this specifies the client-side TLS
	// parameters for the upstream connection originating from the L7 proxy
	// to the remote destination. For ingress policy this specifies the
	// client-side TLS parameters for the connection from the L7 proxy to
	// the local POD.
	OriginatingTLS *TLSContext `json:"originatingTLS,omitempty"`

	// Pre-computed HTTP rules with resolved k8s secrets
	// Computed after rule merging is complete!
	EnvoyHTTPRules *cilium.HttpNetworkPolicyRules `json:"-"`

	// CanShortCircuit is true if all 'EnvoyHTTPRules' may be
	// short-circuited by other matches.
	CanShortCircuit bool `json:"-"`

	api.L7Rules
}

// Equal returns true if 'a' and 'b' represent the same L7 Rules
func (a *PerSelectorPolicy) Equal(b *PerSelectorPolicy) bool {
	return a == nil && b == nil || a != nil && b != nil &&
		a.TerminatingTLS.Equal(b.TerminatingTLS) &&
		a.OriginatingTLS.Equal(b.OriginatingTLS) &&
		reflect.DeepEqual(a.L7Rules, b.L7Rules)
}

// L7DataMap contains a map of L7 rules per endpoint where key is a CachedSelector
type L7DataMap map[CachedSelector]*PerSelectorPolicy

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

// ShallowCopy returns a shallow copy of the L7DataMap.
func (l7 L7DataMap) ShallowCopy() L7DataMap {
	m := make(L7DataMap, len(l7))
	for k, v := range l7 {
		m[k] = v
	}
	return m
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

// L4Filter represents the policy (allowed remote sources / destinations of
// traffic) that applies at a specific L4 port/protocol combination (including
// all ports and protocols), at either ingress or egress. The policy here is
// specified in terms of selectors that are mapped to security identities via
// the selector cache.
type L4Filter struct {
	// Port is the destination port to allow. Port 0 indicates that all traffic
	// is allowed at L4.
	Port     int    `json:"port"`
	PortName string `json:"port-name,omitempty"`
	// Protocol is the L4 protocol to allow or NONE
	Protocol api.L4Proto `json:"protocol"`
	// U8Proto is the Protocol in numeric format, or 0 for NONE
	U8Proto u8proto.U8proto `json:"-"`
	// wildcard is the cached selector representing a wildcard in this filter, if any.
	// This is nil the wildcard selector in not in 'L7RulesPerSelector'.
	// When the wildcard selector is in 'L7RulesPerSelector' this is set to that
	// same selector, which can then be used as a map key to find the corresponding
	// L4-only L7 policy (which can be nil).
	wildcard CachedSelector
	// L7RulesPerSelector is a list of L7 rules per endpoint passed to the L7 proxy.
	// nil values represent cached selectors that have no L7 restriction.
	// Holds references to the cached selectors, which must be released!
	L7RulesPerSelector L7DataMap `json:"l7-rules,omitempty"`
	// L7Parser specifies the L7 protocol parser (optional). If specified as
	// an empty string, then means that no L7 proxy redirect is performed.
	L7Parser L7ParserType `json:"-"`
	// Ingress is true if filter applies at ingress; false if it applies at egress.
	Ingress bool `json:"-"`
	// The rule labels of this Filter
	DerivedFromRules labels.LabelArrayList `json:"-"`

	// This reference is circular, but it is cleaned up at Detach()
	policy unsafe.Pointer // *L4Policy
}

// SelectsAllEndpoints returns whether the L4Filter selects all
// endpoints, which is true if the wildcard endpoint selector is present in the
// map.
func (l4 *L4Filter) SelectsAllEndpoints() bool {
	for cs := range l4.L7RulesPerSelector {
		if cs.IsWildcard() {
			return true
		}
	}
	return false
}

// CopyL7RulesPerEndpoint returns a shallow copy of the L7RulesPerSelector of the
// L4Filter.
func (l4 *L4Filter) CopyL7RulesPerEndpoint() L7DataMap {
	return l4.L7RulesPerSelector.ShallowCopy()
}

// GetL7Parser returns the L7ParserType of the L4Filter.
func (l4 *L4Filter) GetL7Parser() L7ParserType {
	return l4.L7Parser
}

// GetIngress returns whether the L4Filter applies at ingress or egress.
func (l4 *L4Filter) GetIngress() bool {
	return l4.Ingress
}

// GetPort returns the port at which the L4Filter applies as a uint16.
func (l4 *L4Filter) GetPort() uint16 {
	return uint16(l4.Port)
}

// NamedPort represents a mapping from a port name to the port number and protocol
type NamedPort struct {
	Port  uint16 // non-0
	Proto uint8  // 0 for any
}

type NamedPortsMap map[string]NamedPort

func ValidatePortName(name string) (string, error) {
	if !iana.IsSvcName(name) { // Port names are formatted as IANA Service Names
		return "", fmt.Errorf("Invalid port name \"%s\", not using as a named port", name)
	}
	return strings.ToLower(name), nil // Normalize for case-insensitive comparison
}

func ParsePortProtocol(port int, protocol string) (np NamedPort, err error) {
	var u8p u8proto.U8proto
	if protocol == "" {
		u8p = u8proto.TCP // K8s ContainerPort protocol defaults to TCP
	} else {
		var err error
		u8p, err = u8proto.ParseProtocol(protocol)
		if err != nil {
			return np, fmt.Errorf("Invalid protocol \"%s\": %s", protocol, err)
		}
	}
	if port < 1 || port > 65535 {
		return np, fmt.Errorf("Port number %d out of 16-bit range", port)
	}
	return NamedPort{
		Proto: uint8(u8p),
		Port:  uint16(port),
	}, nil
}

func (npm NamedPortsMap) AddPort(name string, port int, protocol string) error {
	name, err := ValidatePortName(name)
	if err != nil {
		return err
	}
	np, err := ParsePortProtocol(port, protocol)
	if err != nil {
		return err
	}
	npm[name] = np
	return nil
}

func (npm NamedPortsMap) GetNamedPort(name string, proto uint8) (port uint16, err error) {
	if npm == nil {
		return 0, fmt.Errorf("nil map")
	}
	np, ok := npm[name]
	if !ok {
		return 0, fmt.Errorf("named port %s not found in %v", name, npm)
	}
	if np.Proto != 0 && proto != np.Proto {
		return 0, fmt.Errorf("incompatible proto")
	}
	if np.Port == 0 {
		return 0, fmt.Errorf("named port has zero value")
	}
	return np.Port, nil
}

// ToMapState converts filter into a MapState with two possible values:
// - Entry with ProxyPort = 0: No proxy redirection is needed for this key
// - Entry with any other port #: Proxy redirection is required for this key,
//                                caller must replace the ProxyPort with the actual
//                                listening port number.
// Note: It is possible for two selectors to select the same security ID.
// To give priority for L7 redirection (e.g., for visibility purposes), we use
// RedirectPreferredInsert() instead of directly inserting the value to the map.
func (l4 *L4Filter) ToMapState(npMap NamedPortsMap, direction trafficdirection.TrafficDirection) MapState {
	port := uint16(l4.Port)
	proto := uint8(l4.U8Proto)

	logger := log
	if option.Config.Debug {
		logger = log.WithFields(logrus.Fields{
			logfields.Port:             port,
			logfields.PortName:         l4.PortName,
			logfields.Protocol:         proto,
			logfields.TrafficDirection: direction,
		})
	}

	keysToAdd := MapState{}

	// resolve named port
	if port == 0 && l4.PortName != "" {
		var err error
		port, err = npMap.GetNamedPort(l4.PortName, proto)
		if err != nil {
			logger.Debugf("ToMapState: Skipping named port: %s", err)
			return keysToAdd
		}
	}

	keyToAdd := Key{
		Identity:         0,    // Set in the loop below (if not wildcard)
		DestPort:         port, // NOTE: Port is in host byte-order!
		Nexthdr:          proto,
		TrafficDirection: direction.Uint8(),
	}

	// find the L7 rules for the wildcard entry, if any
	var wildcardL7Policy *PerSelectorPolicy
	if l4.wildcard != nil {
		wildcardL7Policy = l4.L7RulesPerSelector[l4.wildcard]
	}

	for cs, l7 := range l4.L7RulesPerSelector {
		// Skip generating L3/L4 keys if L4-only key (for the same L4 port and
		// protocol) has the same effect w.r.t. redirecting to the proxy or not,
		// considering that L3/L4 key should redirect if L4-only key does. In
		// summary, if have both L3/L4 and L4-only keys:
		//
		// L3/L4        L4-only      Skip generating L3/L4 key
		// redirect     none         no
		// no redirect  none         no
		// redirect     no redirect  no   (this case tested below)
		// no redirect  no redirect  yes  (same effect)
		// redirect     redirect     yes  (same effect)
		// no redirect  redirect     yes  (must redirect if L4-only redirects)
		//
		// have wildcard?        this is a L3L4 key?  not the "no" case?
		if l4.wildcard != nil && cs != l4.wildcard && !(l7 != nil && wildcardL7Policy == nil) {
			logger.WithField(logfields.EndpointSelector, cs).Debug("ToMapState: Skipping L3/L4 key due to existing L4-only key")
			continue
		}

		entry := NewMapStateEntry(l4.DerivedFromRules, l7 != nil)
		if cs.IsWildcard() {
			keyToAdd.Identity = 0
			keysToAdd.RedirectPreferredInsert(keyToAdd, entry)

			if port == 0 {
				// Allow-all
				logger.WithField(logfields.EndpointSelector, cs).Debug("ToMapState: allow all")
			} else {
				// L4 allow
				logger.WithField(logfields.EndpointSelector, cs).Debug("ToMapState: L4 allow all")
			}
			continue
		}

		identities := cs.GetSelections()
		if option.Config.Debug {
			logger.WithFields(logrus.Fields{
				logfields.EndpointSelector: cs,
				logfields.PolicyID:         identities,
			}).Debug("ToMapState: Allowed remote IDs")
		}
		for _, id := range identities {
			keyToAdd.Identity = id.Uint32()
			keysToAdd.RedirectPreferredInsert(keyToAdd, entry)
		}
	}

	return keysToAdd
}

// IdentitySelectionUpdated implements CachedSelectionUser interface
// This call is made while holding name manager and selector cache
// locks, must beware of deadlocking!
//
// The caller is responsible for making sure the same identity is not
// present in both 'added' and 'deleted'.
func (l4 *L4Filter) IdentitySelectionUpdated(selector CachedSelector, selections, added, deleted []identity.NumericIdentity) {
	log.WithFields(logrus.Fields{
		logfields.EndpointSelector: selector,
		logfields.PolicyID:         selections,
		logfields.AddedPolicyID:    added,
		logfields.DeletedPolicyID:  deleted,
	}).Debug("identities selected by L4Filter updated")

	// Skip updates on wildcard selectors, as datapath and L7
	// proxies do not need enumeration of all ids for L3 wildcard.
	// This mirrors the per-selector logic in ToMapState().
	if selector.IsWildcard() {
		return
	}

	// Push endpoint policy changes.
	//
	// `l4.policy` is set to nil when the filter is detached so
	// that we could not push updates on a stale policy.
	l4Policy := (*L4Policy)(atomic.LoadPointer(&l4.policy))
	if l4Policy != nil {
		direction := trafficdirection.Egress
		if l4.Ingress {
			direction = trafficdirection.Ingress
		}
		l4Policy.AccumulateMapChanges(added, deleted, l4, direction, l4.L7RulesPerSelector[selector] != nil)
	}
}

func (l4 *L4Filter) cacheIdentitySelector(sel api.EndpointSelector, selectorCache *SelectorCache) CachedSelector {
	cs, added := selectorCache.AddIdentitySelector(l4, sel)
	if added {
		l4.L7RulesPerSelector[cs] = nil // no l7 rules (yet)
	}
	return cs
}

func (l4 *L4Filter) cacheIdentitySelectors(selectors api.EndpointSelectorSlice, selectorCache *SelectorCache) {
	for _, sel := range selectors {
		l4.cacheIdentitySelector(sel, selectorCache)
	}
}

func (l4 *L4Filter) cacheFQDNSelectors(selectors api.FQDNSelectorSlice, selectorCache *SelectorCache) {
	for _, fqdnSel := range selectors {
		l4.cacheFQDNSelector(fqdnSel, selectorCache)
	}
}

func (l4 *L4Filter) cacheFQDNSelector(sel api.FQDNSelector, selectorCache *SelectorCache) CachedSelector {
	cs, added := selectorCache.AddFQDNSelector(l4, sel)
	if added {
		l4.L7RulesPerSelector[cs] = nil // no l7 rules (yet)
	}
	return cs
}

// add L7 rules for all endpoints in the L7DataMap
func (l7 L7DataMap) addRulesForEndpoints(rules api.L7Rules, terminatingTLS, originatingTLS *TLSContext) {
	l7policy := &PerSelectorPolicy{
		L7Rules:        rules,
		TerminatingTLS: terminatingTLS,
		OriginatingTLS: originatingTLS,
	}
	for epsel := range l7 {
		l7[epsel] = l7policy
	}
}

type TLSDirection string

const (
	TerminatingTLS TLSDirection = "terminating"
	OriginatingTLS TLSDirection = "originating"
)

func (l4 *L4Filter) getCerts(policyCtx PolicyContext, tls *api.TLSContext, direction TLSDirection) (*TLSContext, error) {
	if tls == nil {
		return nil, nil
	}
	ca, public, private, err := policyCtx.GetTLSContext(tls)
	if err != nil {
		log.WithError(err).Warningf("policy: Error getting %s TLS Context.", direction)
		return nil, err
	}
	switch direction {
	case TerminatingTLS:
		if public == "" || private == "" {
			return nil, fmt.Errorf("Terminating TLS context is missing certs.")
		}
	case OriginatingTLS:
		if ca == "" {
			return nil, fmt.Errorf("Originating TLS context is missing CA certs.")
		}
	default:
		return nil, fmt.Errorf("invalid TLS direction: %s", direction)
	}

	return &TLSContext{
		TrustedCA:        ca,
		CertificateChain: public,
		PrivateKey:       private,
	}, nil
}

// createL4Filter creates a filter for L4 policy that applies to the specified
// endpoints and port/protocol, with reference to the original rules that the
// filter is derived from. This filter may be associated with a series of L7
// rules via the `rule` parameter.
// Not called with an empty peerEndpoints.
func createL4Filter(policyCtx PolicyContext, peerEndpoints api.EndpointSelectorSlice, rule api.PortRule, port api.PortProtocol,
	protocol api.L4Proto, ruleLabels labels.LabelArray, ingress bool, fqdns api.FQDNSelectorSlice) (*L4Filter, error) {
	selectorCache := policyCtx.GetSelectorCache()

	portName := ""
	p := uint64(0)
	if iana.IsSvcName(port.Port) {
		portName = port.Port
	} else {
		// already validated via PortRule.Validate()
		p, _ = strconv.ParseUint(port.Port, 0, 16)
	}

	// already validated via L4Proto.Validate(), never "ANY"
	u8p, _ := u8proto.ParseProtocol(string(protocol))

	l4 := &L4Filter{
		Port:               int(p),   // 0 for L3-only rules and named ports
		PortName:           portName, // non-"" for named ports
		Protocol:           protocol,
		U8Proto:            u8p,
		L7RulesPerSelector: make(L7DataMap),
		DerivedFromRules:   labels.LabelArrayList{ruleLabels},
		Ingress:            ingress,
	}

	if peerEndpoints.SelectsAllEndpoints() {
		l4.wildcard = l4.cacheIdentitySelector(api.WildcardEndpointSelector, selectorCache)
	} else {
		l4.cacheIdentitySelectors(peerEndpoints, selectorCache)
		l4.cacheFQDNSelectors(fqdns, selectorCache)
	}

	if rule.Rules != nil {
		var terminatingTLS *TLSContext
		var originatingTLS *TLSContext

		// Note: No rules -> no TLS
		if !rule.Rules.IsEmpty() {
			var err error
			terminatingTLS, err = l4.getCerts(policyCtx, rule.TerminatingTLS, TerminatingTLS)
			if err != nil {
				return nil, err
			}
			originatingTLS, err = l4.getCerts(policyCtx, rule.OriginatingTLS, OriginatingTLS)
			if err != nil {
				return nil, err
			}
		}

		if protocol == api.ProtoTCP {
			switch {
			case len(rule.Rules.HTTP) > 0:
				l4.L7Parser = ParserTypeHTTP
			case len(rule.Rules.Kafka) > 0:
				l4.L7Parser = ParserTypeKafka
			case rule.Rules.L7Proto != "":
				l4.L7Parser = (L7ParserType)(rule.Rules.L7Proto)
			}
			if !rule.Rules.IsEmpty() {
				l4.L7RulesPerSelector.addRulesForEndpoints(*rule.Rules, terminatingTLS, originatingTLS)
			}
		}

		// we need this to redirect DNS UDP (or ANY, which is more useful)
		if len(rule.Rules.DNS) > 0 {
			l4.L7Parser = ParserTypeDNS
			l4.L7RulesPerSelector.addRulesForEndpoints(*rule.Rules, terminatingTLS, originatingTLS)
		}
	}

	return l4, nil
}

func (l4 *L4Filter) removeSelectors(selectorCache *SelectorCache) {
	selectors := make(CachedSelectorSlice, 0, len(l4.L7RulesPerSelector))
	for cs := range l4.L7RulesPerSelector {
		selectors = append(selectors, cs)
	}
	selectorCache.RemoveSelectors(selectors, l4)
}

// detach releases the references held in the L4Filter and must be called before
// the filter is left to be garbage collected.
func (l4 *L4Filter) detach(selectorCache *SelectorCache) {
	l4.removeSelectors(selectorCache)
	l4.attach(nil, nil)
}

func (l4 *L4Filter) attach(ctx PolicyContext, l4Policy *L4Policy) {
	// All rules have been added to the L4Filter at this point.
	// Sort the rules label array list for more efficient equality comparison.
	l4.DerivedFromRules.Sort()

	// Compute Envoy policies when a policy is ready to be used
	if ctx != nil {
		for _, l7policy := range l4.L7RulesPerSelector {
			if l7policy != nil {
				l7policy.EnvoyHTTPRules, l7policy.CanShortCircuit = ctx.GetEnvoyHTTPRules(&l7policy.L7Rules)
			}
		}
	}

	atomic.StorePointer(&l4.policy, unsafe.Pointer(l4Policy))
}

// createL4IngressFilter creates a filter for L4 policy that applies to the
// specified endpoints and port/protocol for ingress traffic, with reference
// to the original rules that the filter is derived from. This filter may be
// associated with a series of L7 rules via the `rule` parameter.
//
// hostWildcardL7 determines if L7 traffic from Host should be
// wildcarded (in the relevant daemon mode).
func createL4IngressFilter(policyCtx PolicyContext, fromEndpoints api.EndpointSelectorSlice, hostWildcardL7 []string, rule api.PortRule, port api.PortProtocol,
	protocol api.L4Proto, ruleLabels labels.LabelArray) (*L4Filter, error) {

	filter, err := createL4Filter(policyCtx, fromEndpoints, rule, port, protocol, ruleLabels, true, nil)
	if err != nil {
		return nil, err
	}

	// If the filter would apply L7 rules for the Host, when we should accept everything from host,
	// then wildcard Host at L7.
	if !rule.Rules.IsEmpty() && len(hostWildcardL7) > 0 {
		for cs := range filter.L7RulesPerSelector {
			if cs.Selects(identity.ReservedIdentityHost) {
				for _, name := range hostWildcardL7 {
					selector := api.ReservedEndpointSelectors[name]
					filter.cacheIdentitySelector(selector, policyCtx.GetSelectorCache())
				}
			}
		}
	}

	return filter, nil
}

// createL4EgressFilter creates a filter for L4 policy that applies to the
// specified endpoints and port/protocol for egress traffic, with reference
// to the original rules that the filter is derived from. This filter may be
// associated with a series of L7 rules via the `rule` parameter.
func createL4EgressFilter(policyCtx PolicyContext, toEndpoints api.EndpointSelectorSlice, rule api.PortRule, port api.PortProtocol,
	protocol api.L4Proto, ruleLabels labels.LabelArray, fqdns api.FQDNSelectorSlice) (*L4Filter, error) {

	return createL4Filter(policyCtx, toEndpoints, rule, port, protocol, ruleLabels, false, fqdns)
}

// IsRedirect returns true if the L4 filter contains a port redirection
func (l4 *L4Filter) IsRedirect() bool {
	return l4.L7Parser != ParserTypeNone
}

// IsEnvoyRedirect returns true if the L4 filter contains a port redirected to Envoy
func (l4 *L4Filter) IsEnvoyRedirect() bool {
	return l4.IsRedirect() && l4.L7Parser != ParserTypeDNS
}

// IsProxylibRedirect returns true if the L4 filter contains a port redirected to Proxylib (via Envoy)
func (l4 *L4Filter) IsProxylibRedirect() bool {
	return l4.IsEnvoyRedirect() && l4.L7Parser != ParserTypeHTTP
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
	if l4.wildcard != nil {
		return true
	} else if len(labels) == 0 {
		return false
	}

	for sel := range l4.L7RulesPerSelector {
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

// Attach makes all the L4Filters to point back to the L4Policy that contains them.
func (l4 L4PolicyMap) Attach(ctx PolicyContext, l4Policy *L4Policy) {
	for _, f := range l4 {
		f.attach(ctx, l4Policy)
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

// HasEnvoyRedirect returns true if at least one L4 filter contains a port
// redirection that is forwarded to Envoy
func (l4 L4PolicyMap) HasEnvoyRedirect() bool {
	for _, f := range l4 {
		if f.IsEnvoyRedirect() {
			return true
		}
	}
	return false
}

// HasProxylibRedirect returns true if at least one L4 filter contains a port
// redirection that is forwarded to Proxylib (via Envoy)
func (l4 L4PolicyMap) HasProxylibRedirect() bool {
	for _, f := range l4 {
		if f.IsProxylibRedirect() {
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
		portStr := l4Ctx.Name
		if !iana.IsSvcName(portStr) {
			portStr = fmt.Sprintf("%d", l4Ctx.Port)
		}
		lwrProtocol := l4Ctx.Protocol
		switch lwrProtocol {
		case "", models.PortProtocolANY:
			tcpPort := fmt.Sprintf("%s/TCP", portStr)
			tcpFilter, tcpmatch := l4[tcpPort]
			if tcpmatch {
				tcpmatch = tcpFilter.matchesLabels(labels)
			}
			udpPort := fmt.Sprintf("%s/UDP", portStr)
			udpFilter, udpmatch := l4[udpPort]
			if udpmatch {
				udpmatch = udpFilter.matchesLabels(labels)
			}
			if !tcpmatch && !udpmatch {
				return api.Denied
			}
		default:
			port := fmt.Sprintf("%s/%s", portStr, lwrProtocol)
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

	// Endpoint policies using this L4Policy
	// These are circular references, cleaned up in Detach()
	mutex lock.RWMutex
	users map[*EndpointPolicy]struct{}
}

// NewL4Policy creates a new L4Policy
func NewL4Policy(revision uint64) *L4Policy {
	return &L4Policy{
		Ingress:  L4PolicyMap{},
		Egress:   L4PolicyMap{},
		Revision: revision,
		users:    make(map[*EndpointPolicy]struct{}),
	}
}

// insertUser adds a user to the L4Policy so that incremental
// updates of the L4Policy may be forwarded to the users of it.
func (l4 *L4Policy) insertUser(user *EndpointPolicy) {
	l4.mutex.Lock()

	// 'users' is set to nil when the policy is detached. This
	// happens to the old policy when it is being replaced with a
	// new one, or when the last endpoint using this policy is
	// removed.
	// In the case of an policy update it is possible that an
	// endpoint has started regeneration before the policy was
	// updated, and that the policy was updated before the said
	// endpoint reached this point. In this case the endpoint's
	// policy is going to be recomputed soon after and we do
	// nothing here.
	if l4.users != nil {
		l4.users[user] = struct{}{}
	}

	l4.mutex.Unlock()
}

// AccumulateMapChanges distributes the given changes to the registered users.
//
// The caller is responsible for making sure the same identity is not
// present in both 'adds' and 'deletes'.
func (l4 *L4Policy) AccumulateMapChanges(adds, deletes []identity.NumericIdentity, l4Filter *L4Filter,
	direction trafficdirection.TrafficDirection, redirect bool) {
	port := uint16(l4Filter.Port)
	proto := uint8(l4Filter.U8Proto)
	derivedFrom := l4Filter.DerivedFromRules

	l4.mutex.RLock()
	for epPolicy := range l4.users {
		// resolve named port
		if port == 0 && l4Filter.PortName != "" {
			var err error
			port, err = epPolicy.NamedPortsMap.GetNamedPort(l4Filter.PortName, proto)
			if err != nil {
				if option.Config.Debug {
					logger := log.WithFields(logrus.Fields{
						logfields.Port:             port,
						logfields.PortName:         l4Filter.PortName,
						logfields.Protocol:         proto,
						logfields.TrafficDirection: direction,
						logfields.EndpointID:       epPolicy.PolicyOwner.GetID(),
					})
					logger.WithError(err).Debug("AccumulateMapChanges: Skipping named port")
				}
				continue
			}
		}

		epPolicy.policyMapChanges.AccumulateMapChanges(adds, deletes, port, proto, direction, redirect, derivedFrom)
	}
	l4.mutex.RUnlock()
}

// Detach makes the L4Policy ready for garbage collection, removing
// circular pointer references.
// Note that the L4Policy itself is not modified in any way, so that it may still
// be used concurrently.
func (l4 *L4Policy) Detach(selectorCache *SelectorCache) {
	l4.Ingress.Detach(selectorCache)
	l4.Egress.Detach(selectorCache)

	l4.mutex.Lock()
	l4.users = nil
	l4.mutex.Unlock()
}

// Attach makes all the L4Filters to point back to the L4Policy that contains them.
// This is done before the L4Policy is exposed to concurrent access.
func (l4 *L4Policy) Attach(ctx PolicyContext) {
	l4.Ingress.Attach(ctx, l4)
	l4.Egress.Attach(ctx, l4)
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

// HasEnvoyRedirect returns true if the L4 policy contains at least one port redirection to Envoy
func (l4 *L4Policy) HasEnvoyRedirect() bool {
	return l4 != nil && (l4.Ingress.HasEnvoyRedirect() || l4.Egress.HasEnvoyRedirect())
}

// HasProxylibRedirect returns true if the L4 policy contains at least one port redirection to Proxylib
func (l4 *L4Policy) HasProxylibRedirect() bool {
	return l4 != nil && (l4.Ingress.HasProxylibRedirect() || l4.Egress.HasProxylibRedirect())
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

// ProxyPolicy is any type which encodes state needed to redirect to an L7
// proxy.
type ProxyPolicy interface {
	CopyL7RulesPerEndpoint() L7DataMap
	GetL7Parser() L7ParserType
	GetIngress() bool
	GetPort() uint16
}
