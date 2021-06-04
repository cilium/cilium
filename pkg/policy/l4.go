// Copyright 2016-2021 Authors of Cilium
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
	cilium "github.com/cilium/proxy/go/cilium/api"

	"github.com/sirupsen/logrus"
)

// __canSkipArgs is a wrapper structure to store all boolean conditions for the
// __canSkipTruthTable.
type __canSkipArgs struct {
	currentL3L4Redirect bool
	currentL3L4Allow    bool
	l4OnlyRedirect      bool
	l4OnlyAllow         bool
}

// __canSkipTruthTable is a map used to store the conditions for which we should
// skip L3/L4 keys if L4-only key exists.
var __canSkipTruthTable map[__canSkipArgs]struct{}

func init() {
	// __canSkipTruthTable contains all the required conditions to skip
	// the generation of L3/L4 keys.
	__canSkipTruthTable = map[__canSkipArgs]struct{}{
		// Skip generating L3/L4 keys if L4-only key (for the same L4 port and
		// protocol) has the same effect w.r.t. redirecting to the proxy or not,
		// considering that L3/L4 key should redirect if L4-only key does.
		//
		// Also consider that a deny policy should take precedence so that
		// - l4-only deny overrides l3/l4 allows (and denies)
		// - l3/l4 deny overrides l4-only allows (for that specific l3)
		//
		// This entire logic is needed for the line with (must redirect if
		// L4-only redirects) apart from this line and the ones marked with
		// (deny takes precedence), this is logic is entirely an optimization.
		//
		// In summary, if have both L3/L4 and L4-only keys:
		//
		//    Current L3/L4            L4-only (if any)         Skip generating L3/L4 key
		//    redirect     allow       none         none        no
		//    no redirect  allow       none         none        no
		//    no redirect  deny        none         none        no
		//    redirect     allow       no redirect  allow       no   (this case tested below)
		//    redirect     allow       no redirect  deny        yes  (deny takes precedence)
		/* */ {true /* */, true /* */, false /* */, false}:/**/ {},
		//    no redirect  allow       no redirect  allow       yes  (same effect)
		/* */ {false /**/, true /* */, false /* */, true}:/* */ {},
		//    no redirect  allow       no redirect  deny        yes  (deny takes precedence)
		/* */ {false /**/, true /* */, false /* */, false}:/**/ {},
		//    no redirect  deny        no redirect  allow       no   (deny takes precedence)
		//    no redirect  deny        no redirect  deny        yes  (same effect)
		/* */ {false /**/, false /**/, false /* */, false}:/**/ {},
		//    redirect     allow       redirect     allow       yes  (same effect)
		/* */ {true /* */, true /* */, true /*  */, true}:/* */ {},
		//    no redirect  allow       redirect     allow       yes  (must redirect if L4-only redirects)
		/* */ {false /**/, true /* */, true /*  */, true}:/* */ {},
		//    no redirect  deny        redirect     allow       no   (deny takes precedence)
	}
}

// __canSkip returns true or false depending on the condition created for the
// ;__canSkipTruthTable' truth table.
func __canSkip(currentRule *PerSelectorPolicy, wildcardRule *PerSelectorPolicy) bool {
	_, ok := __canSkipTruthTable[__canSkipArgs{
		currentL3L4Redirect: currentRule.IsRedirect(),
		currentL3L4Allow:    currentRule == nil || !currentRule.IsDeny,
		l4OnlyRedirect:      wildcardRule.IsRedirect(),
		l4OnlyAllow:         wildcardRule == nil || !wildcardRule.IsDeny,
	}]
	return ok
}

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

	// IsDeny is set if this L4Filter contains should be denied
	IsDeny bool `json:",omitempty"`
}

// Equal returns true if 'a' and 'b' represent the same L7 Rules
func (a *PerSelectorPolicy) Equal(b *PerSelectorPolicy) bool {
	return a == nil && b == nil || a != nil && b != nil &&
		a.TerminatingTLS.Equal(b.TerminatingTLS) &&
		a.OriginatingTLS.Equal(b.OriginatingTLS) &&
		a.IsDeny == b.IsDeny &&
		reflect.DeepEqual(a.L7Rules, b.L7Rules)
}

// IsRedirect returns true if the L7Rules are a redirect.
func (a *PerSelectorPolicy) IsRedirect() bool {
	// Deny policies do not support L7 rules
	return !a.IsEmpty() && !a.IsDeny
}

// IsEmpty returns whether the `L7Rules` is nil or contains nil rules.
func (a *PerSelectorPolicy) IsEmpty() bool {
	return a == nil || a.L7Rules.IsEmpty()
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

// ToMapState converts filter into a MapState with two possible values:
// - Entry with ProxyPort = 0: No proxy redirection is needed for this key
// - Entry with any other port #: Proxy redirection is required for this key,
//                                caller must replace the ProxyPort with the actual
//                                listening port number.
// Note: It is possible for two selectors to select the same security ID.
// To give priority for L7 redirection (e.g., for visibility purposes), we use
// RedirectPreferredInsert() instead of directly inserting the value to the map.
// PolicyOwner (aka Endpoint) is locked during this call.
func (l4Filter *L4Filter) ToMapState(policyOwner PolicyOwner, direction trafficdirection.TrafficDirection) MapState {
	port := uint16(l4Filter.Port)
	proto := uint8(l4Filter.U8Proto)

	logger := log
	if option.Config.Debug {
		logger = log.WithFields(logrus.Fields{
			logfields.Port:             port,
			logfields.PortName:         l4Filter.PortName,
			logfields.Protocol:         proto,
			logfields.TrafficDirection: direction,
		})
	}

	keysToAdd := MapState{}

	// resolve named port
	if port == 0 && l4Filter.PortName != "" {
		port = policyOwner.GetNamedPortLocked(l4Filter.Ingress, l4Filter.PortName, proto)
		if port == 0 {
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
	var wildcardRule *PerSelectorPolicy
	if l4Filter.wildcard != nil {
		wildcardRule = l4Filter.L7RulesPerSelector[l4Filter.wildcard]
	}

	for cs, currentRule := range l4Filter.L7RulesPerSelector {
		// have wildcard?        this is a L3L4 key?
		isDenyRule := currentRule != nil && currentRule.IsDeny

		if (l4Filter.Port != 0 || l4Filter.PortName != "") && l4Filter.wildcard != nil {
			// Now that we have a port number and a wildcard the filter has a
			// L4-only rule.

			currentRuleIsL3L4 := l4Filter.wildcard != cs

			// To understand the logic for the "skip" cases, see the
			// documentation for the __canSkip function.
			if currentRuleIsL3L4 && __canSkip(currentRule, wildcardRule) {
				logger.WithField(logfields.EndpointSelector, cs).Debug("ToMapState: Skipping L3/L4 key due to existing L4-only key")
				continue
			}
		}

		entry := NewMapStateEntry(cs, l4Filter.DerivedFromRules, currentRule.IsRedirect(), isDenyRule)
		if cs.IsWildcard() {
			keyToAdd.Identity = 0
			keysToAdd.DenyPreferredInsert(keyToAdd, entry)

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
			if isDenyRule {
				logger.WithFields(logrus.Fields{
					logfields.EndpointSelector: cs,
					logfields.PolicyID:         identities,
				}).Debug("ToMapState: Denied remote IDs")
			} else {
				logger.WithFields(logrus.Fields{
					logfields.EndpointSelector: cs,
					logfields.PolicyID:         identities,
				}).Debug("ToMapState: Allowed remote IDs")
			}
		}
		for _, id := range identities {
			keyToAdd.Identity = id.Uint32()
			keysToAdd.DenyPreferredInsert(keyToAdd, entry)
		}
	}

	return keysToAdd
}

// IdentitySelectionUpdated implements CachedSelectionUser interface
// This call is made from a single goroutine in FIFO order to keep add
// and delete events ordered properly. No locks are held.
//
// The caller is responsible for making sure the same identity is not
// present in both 'added' and 'deleted'.
func (l4 *L4Filter) IdentitySelectionUpdated(selector CachedSelector, added, deleted []identity.NumericIdentity) {
	log.WithFields(logrus.Fields{
		logfields.EndpointSelector: selector,
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
	// `l4.policy` is nil when the filter is detached so
	// that we could not push updates on an unstable policy.
	l4Policy := (*L4Policy)(atomic.LoadPointer(&l4.policy))
	if l4Policy != nil {
		direction := trafficdirection.Egress
		if l4.Ingress {
			direction = trafficdirection.Ingress
		}
		l7Rules := l4.L7RulesPerSelector[selector]
		isRedirect := l7Rules.IsRedirect()
		isDeny := l7Rules != nil && l7Rules.IsDeny
		l4Policy.AccumulateMapChanges(selector, added, deleted, l4, direction, isRedirect, isDeny)
	}
}

func (l4 *L4Filter) cacheIdentitySelector(sel api.EndpointSelector, selectorCache *SelectorCache, isDeny bool) CachedSelector {
	cs, added := selectorCache.AddIdentitySelector(l4, sel)
	if added {
		if isDeny {
			l4.L7RulesPerSelector[cs] = &PerSelectorPolicy{IsDeny: isDeny} // no l7 rules (yet)
		} else {
			l4.L7RulesPerSelector[cs] = nil // no l7 rules (yet)
		}
	}
	return cs
}

func (l4 *L4Filter) cacheIdentitySelectors(selectors api.EndpointSelectorSlice, selectorCache *SelectorCache, isDeny bool) {
	for _, sel := range selectors {
		l4.cacheIdentitySelector(sel, selectorCache, isDeny)
	}
}

func (l4 *L4Filter) cacheFQDNSelectors(selectors api.FQDNSelectorSlice, selectorCache *SelectorCache, isDeny bool) {
	for _, fqdnSel := range selectors {
		l4.cacheFQDNSelector(fqdnSel, selectorCache, isDeny)
	}
}

func (l4 *L4Filter) cacheFQDNSelector(sel api.FQDNSelector, selectorCache *SelectorCache, isDeny bool) CachedSelector {
	cs, added := selectorCache.AddFQDNSelector(l4, sel)
	if added {
		if isDeny {
			l4.L7RulesPerSelector[cs] = &PerSelectorPolicy{IsDeny: isDeny} // no l7 rules (yet)
		} else {
			l4.L7RulesPerSelector[cs] = nil // no l7 rules (yet)
		}
	}
	return cs
}

// add L7 rules for all endpoints in the L7DataMap
func (l7 L7DataMap) addRulesForEndpoints(rules api.L7Rules, terminatingTLS, originatingTLS *TLSContext, deny bool) {
	l7policy := &PerSelectorPolicy{
		L7Rules:        rules,
		TerminatingTLS: terminatingTLS,
		OriginatingTLS: originatingTLS,
		IsDeny:         deny,
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
func createL4Filter(policyCtx PolicyContext, peerEndpoints api.EndpointSelectorSlice, rule api.Ports, port api.PortProtocol,
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
		l4.wildcard = l4.cacheIdentitySelector(api.WildcardEndpointSelector, selectorCache, policyCtx.IsDeny())
	} else {
		l4.cacheIdentitySelectors(peerEndpoints, selectorCache, policyCtx.IsDeny())
		l4.cacheFQDNSelectors(fqdns, selectorCache, policyCtx.IsDeny())
	}

	pr := rule.GetPortRule()
	if pr != nil && pr.Rules != nil {
		var terminatingTLS *TLSContext
		var originatingTLS *TLSContext

		// Note: No rules -> no TLS
		if !pr.Rules.IsEmpty() {
			var err error
			terminatingTLS, err = l4.getCerts(policyCtx, pr.TerminatingTLS, TerminatingTLS)
			if err != nil {
				return nil, err
			}
			originatingTLS, err = l4.getCerts(policyCtx, pr.OriginatingTLS, OriginatingTLS)
			if err != nil {
				return nil, err
			}
		}

		if protocol == api.ProtoTCP {
			switch {
			case len(pr.Rules.HTTP) > 0:
				l4.L7Parser = ParserTypeHTTP
			case len(pr.Rules.Kafka) > 0:
				l4.L7Parser = ParserTypeKafka
			case pr.Rules.L7Proto != "":
				l4.L7Parser = (L7ParserType)(pr.Rules.L7Proto)
			}
			if !pr.Rules.IsEmpty() {
				l4.L7RulesPerSelector.addRulesForEndpoints(*pr.Rules, terminatingTLS, originatingTLS, policyCtx.IsDeny())
			}
		}

		// we need this to redirect DNS UDP (or ANY, which is more useful)
		if len(pr.Rules.DNS) > 0 {
			l4.L7Parser = ParserTypeDNS
			l4.L7RulesPerSelector.addRulesForEndpoints(*pr.Rules, terminatingTLS, originatingTLS, policyCtx.IsDeny())
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
// L4Filter may still be accessed concurrently after it has been detached.
func (l4 *L4Filter) detach(selectorCache *SelectorCache) {
	l4.removeSelectors(selectorCache)
	l4.attach(nil, nil)
}

// attach signifies that the L4Filter is ready and reacheable for updates
// from SelectorCache. L4Filter is read-only after this is called,
// multiple goroutines will be reading the fields from that point on.
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
func createL4IngressFilter(policyCtx PolicyContext, fromEndpoints api.EndpointSelectorSlice, hostWildcardL7 []string, rule api.Ports, port api.PortProtocol,
	protocol api.L4Proto, ruleLabels labels.LabelArray) (*L4Filter, error) {

	filter, err := createL4Filter(policyCtx, fromEndpoints, rule, port, protocol, ruleLabels, true, nil)
	if err != nil {
		return nil, err
	}

	pr := rule.GetPortRule()
	if pr == nil {
		return filter, nil
	}
	// If the filter would apply L7 rules for the Host, when we should accept everything from host,
	// then wildcard Host at L7.
	if !pr.Rules.IsEmpty() && len(hostWildcardL7) > 0 {
		for cs := range filter.L7RulesPerSelector {
			if cs.Selects(identity.ReservedIdentityHost) {
				for _, name := range hostWildcardL7 {
					selector := api.ReservedEndpointSelectors[name]
					filter.cacheIdentitySelector(selector, policyCtx.GetSelectorCache(), policyCtx.IsDeny())
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
func createL4EgressFilter(policyCtx PolicyContext, toEndpoints api.EndpointSelectorSlice, rule api.Ports, port api.PortProtocol,
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
func (l4 *L4Filter) matchesLabels(labels labels.LabelArray) (bool, bool) {
	if l4.wildcard != nil {
		l7Rules := l4.L7RulesPerSelector[l4.wildcard]
		isDeny := l7Rules != nil && l7Rules.IsDeny
		return true, isDeny
	} else if len(labels) == 0 {
		return false, false
	}

	var selected bool
	for sel, rule := range l4.L7RulesPerSelector {
		// slow, but OK for tracing
		if idSel, ok := sel.(*labelIdentitySelector); ok && idSel.xxxMatches(labels) {
			isDeny := rule != nil && rule.IsDeny
			selected = true
			if isDeny {
				return true, isDeny
			}
		}
	}
	return selected, false
}

// addL4Filter adds 'filterToMerge' into the 'resMap'. Returns an error if it
// the 'filterToMerge' can't be merged with an existing filter for the same
// port and proto.
func addL4Filter(policyCtx PolicyContext,
	ctx *SearchContext, resMap L4PolicyMap,
	p api.PortProtocol, proto api.L4Proto,
	filterToMerge *L4Filter,
	ruleLabels labels.LabelArray) error {

	key := p.Port + "/" + string(proto)
	existingFilter, ok := resMap[key]
	if !ok {
		resMap[key] = filterToMerge
		return nil
	}

	selectorCache := policyCtx.GetSelectorCache()
	if err := mergePortProto(ctx, existingFilter, filterToMerge, selectorCache); err != nil {
		filterToMerge.detach(selectorCache)
		return err
	}
	var exists bool
	for _, existingRuleLabels := range existingFilter.DerivedFromRules {
		if existingRuleLabels.DeepEqual(&ruleLabels) {
			exists = true
			break
		}
	}
	if !exists {
		existingFilter.DerivedFromRules = append(existingFilter.DerivedFromRules, ruleLabels)
	}
	resMap[key] = existingFilter
	return nil
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
// This is done before the L4PolicyMap is exposed to concurrent access.
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
	if match {

		matches, isDeny := filter.matchesLabels(labels)
		switch {
		case matches && isDeny:
			return api.Denied
		case matches:
			return api.Allowed
		}
	}

	for _, l4Ctx := range ports {
		portStr := l4Ctx.Name
		if !iana.IsSvcName(portStr) {
			portStr = fmt.Sprintf("%d", l4Ctx.Port)
		}
		lwrProtocol := l4Ctx.Protocol
		var isUDPDeny, isTCPDeny bool
		switch lwrProtocol {
		case "", models.PortProtocolANY:
			tcpPort := fmt.Sprintf("%s/TCP", portStr)
			tcpFilter, tcpmatch := l4[tcpPort]
			if tcpmatch {
				tcpmatch, isTCPDeny = tcpFilter.matchesLabels(labels)
			}
			udpPort := fmt.Sprintf("%s/UDP", portStr)
			udpFilter, udpmatch := l4[udpPort]
			if udpmatch {
				udpmatch, isUDPDeny = udpFilter.matchesLabels(labels)
			}
			if (!tcpmatch && !udpmatch) || (isTCPDeny && isUDPDeny) {
				return api.Denied
			}
		default:
			port := fmt.Sprintf("%s/%s", portStr, lwrProtocol)
			filter, match := l4[port]
			if !match {
				return api.Denied
			}
			matches, isDeny := filter.matchesLabels(labels)
			if !matches || isDeny {
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
	// This mutex is taken while Endpoint mutex is held, so Endpoint lock
	// MUST always be taken before this mutex.
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

// removeUser removes a user that no longer needs incremental updates
// from the L4Policy.
func (l4 *L4Policy) removeUser(user *EndpointPolicy) {
	// 'users' is set to nil when the policy is detached. This
	// happens to the old policy when it is being replaced with a
	// new one, or when the last endpoint using this policy is
	// removed.
	l4.mutex.Lock()
	if l4.users != nil {
		delete(l4.users, user)
	}
	l4.mutex.Unlock()
}

// AccumulateMapChanges distributes the given changes to the registered users.
//
// The caller is responsible for making sure the same identity is not
// present in both 'adds' and 'deletes'.
func (l4 *L4Policy) AccumulateMapChanges(cs CachedSelector, adds, deletes []identity.NumericIdentity, l4Filter *L4Filter,
	direction trafficdirection.TrafficDirection, redirect, isDeny bool) {
	port := uint16(l4Filter.Port)
	proto := uint8(l4Filter.U8Proto)
	derivedFrom := l4Filter.DerivedFromRules

	// Must take a copy of 'users' as GetNamedPort() will lock the Endpoint below and
	// the Endpoint lock may not be taken while 'l4.mutex' is held.
	l4.mutex.RLock()
	users := make(map[*EndpointPolicy]struct{}, len(l4.users))
	for user := range l4.users {
		users[user] = struct{}{}
	}
	l4.mutex.RUnlock()

	for epPolicy := range users {
		// resolve named port
		if port == 0 && l4Filter.PortName != "" {
			port = epPolicy.PolicyOwner.GetNamedPort(direction == trafficdirection.Ingress, l4Filter.PortName, proto)
			if port == 0 {
				continue
			}
		}
		epPolicy.policyMapChanges.AccumulateMapChanges(cs, adds, deletes, port, proto, direction, redirect, isDeny, derivedFrom)
	}
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
