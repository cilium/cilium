// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"sync/atomic"

	cilium "github.com/cilium/proxy/go/cilium/api"
	"github.com/sirupsen/logrus"

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
)

// covers returns true if 'l4rule' has the effect needed for the 'l3l4rule', when 'l4rule' is added
// to the datapath, due to the l4-only rule matching if l3l4-rule is not present. This determination
// can be done here only when both rules have the same port number (or both have a wildcarded port).
func (l4rule *PerSelectorPolicy) covers(l3l4rule *PerSelectorPolicy) bool {
	// Deny takes highest precedence so it is dealt with first
	if l4rule != nil && l4rule.IsDeny {
		// l4-only deny takes precedence
		return true
	} else if l3l4rule != nil && l3l4rule.IsDeny {
		// Must not skip if l3l4 rule is deny while l4-only rule is not
		return false
	}

	// Can not skip if currentRule has an explicit auth type and wildcardRule does not or if
	// both have different auth types.  In all other cases the auth type from the wildcardRule
	// can be used also for the current rule.
	// Note that the caller must deal with inheriting redirect from wildcardRule to currentRule,
	// if any.
	cHasAuth, cAuthType := l3l4rule.GetAuthType()
	wHasAuth, wAuthType := l4rule.GetAuthType()
	if cHasAuth && !wHasAuth || cHasAuth && wHasAuth && cAuthType != wAuthType {
		return false
	}

	l3l4IsRedirect := l3l4rule.IsRedirect()
	l4OnlyIsRedirect := l4rule.IsRedirect()
	if l3l4IsRedirect && !l4OnlyIsRedirect {
		// Can not skip if l3l4-rule is redirect while l4-only is not
		return false
	}

	// else can skip
	return true
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

type StringSet map[string]struct{}

func (a StringSet) Equal(b StringSet) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, exists := b[k]; !exists {
			return false
		}
	}
	return true
}

// NewStringSet returns a StringSet initialized from slice of strings.
// Returns nil for an empty slice
func NewStringSet(from []string) StringSet {
	if len(from) == 0 {
		return nil
	}
	set := make(StringSet, len(from))
	for _, s := range from {
		set[s] = struct{}{}
	}
	return set
}

// Merge returns StringSet with strings from both a and b.
// Returns a or b, possibly with modifications.
func (a StringSet) Merge(b StringSet) StringSet {
	if len(a) == 0 {
		return b
	}
	for s := range b {
		a[s] = struct{}{}
	}
	return a
}

// PerSelectorPolicy contains policy rules for a CachedSelector, i.e. for a
// selection of numerical identities.
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

	// ServerNames is a list of allowed TLS SNI values. If not empty, then
	// TLS must be present and one of the provided SNIs must be indicated in the
	// TLS handshake.
	ServerNames StringSet `json:"serverNames,omitempty"`

	// isRedirect is 'true' when traffic must be redirected
	isRedirect bool `json:"-"`

	// Pre-computed HTTP rules, computed after rule merging is complete
	EnvoyHTTPRules *cilium.HttpNetworkPolicyRules `json:"-"`

	// CanShortCircuit is true if all 'EnvoyHTTPRules' may be
	// short-circuited by other matches.
	CanShortCircuit bool `json:"-"`

	api.L7Rules

	// Authentication is the kind of cryptographic authentication required for the traffic to be allowed
	// at L3, if any.
	Authentication *api.Authentication `json:"auth,omitempty"`

	// IsDeny is set if this L4Filter contains should be denied
	IsDeny bool `json:",omitempty"`
}

// Equal returns true if 'a' and 'b' represent the same L7 Rules
func (a *PerSelectorPolicy) Equal(b *PerSelectorPolicy) bool {
	return a == nil && b == nil || a != nil && b != nil &&
		a.TerminatingTLS.Equal(b.TerminatingTLS) &&
		a.OriginatingTLS.Equal(b.OriginatingTLS) &&
		a.ServerNames.Equal(b.ServerNames) &&
		a.isRedirect == b.isRedirect &&
		(a.Authentication == nil && b.Authentication == nil || a.Authentication != nil && a.Authentication.DeepEqual(b.Authentication)) &&
		a.IsDeny == b.IsDeny &&
		a.L7Rules.DeepEqual(&b.L7Rules)
}

// AuthType enumerates the supported authentication types in api.
// Numerically higher type takes precedence in case of conflicting auth types.
type AuthType uint8

// AuthTypes is a set of AuthTypes, usually nil if empty
type AuthTypes map[AuthType]struct{}

// Authmap maps remote selectors to their needed AuthTypes, if any
type AuthMap map[CachedSelector]AuthTypes

const (
	// AuthTypeDisabled means no authentication required
	AuthTypeDisabled AuthType = iota
	// AuthTypeSpire is a mutual auth type that uses SPIFFE identities with a SPIRE server
	AuthTypeSpire
	// AuthTypeAlwaysFail is a simple auth type that always denies the request
	AuthTypeAlwaysFail
)

type HasAuthType bool

const (
	DefaultAuthType  HasAuthType = false
	ExplicitAuthType HasAuthType = true
)

// GetAuthType returns the AuthType of the L4Filter.
func (a *PerSelectorPolicy) GetAuthType() (HasAuthType, AuthType) {
	if a == nil {
		return DefaultAuthType, AuthTypeDisabled
	}
	return GetAuthType(a.Authentication)
}

// GetAuthType returns boolean HasAuthType and AuthType for the api.Authentication
// If there is no explicit auth type, (DefaultAuthType, AuthTypeDisabled) is returned
func GetAuthType(auth *api.Authentication) (HasAuthType, AuthType) {
	if auth == nil {
		return DefaultAuthType, AuthTypeDisabled
	}
	switch auth.Mode {
	case api.AuthenticationModeDisabled:
		return ExplicitAuthType, AuthTypeDisabled
	case api.AuthenticationModeRequired:
		return ExplicitAuthType, AuthTypeSpire
	case api.AuthenticationModeAlwaysFail:
		return ExplicitAuthType, AuthTypeAlwaysFail
	default:
		return DefaultAuthType, AuthTypeDisabled
	}
}

// Uint8 returns AuthType as a uint8
func (a AuthType) Uint8() uint8 {
	return uint8(a)
}

// String returns AuthType as a string
// This must return the strings accepted for api.AuthType
func (a AuthType) String() string {
	switch a {
	case AuthTypeDisabled:
		return "disabled"
	case AuthTypeSpire:
		return "spire"
	case AuthTypeAlwaysFail:
		return "test-always-fail"
	}
	return "Unknown-auth-type-" + strconv.FormatUint(uint64(a.Uint8()), 10)
}

// IsRedirect returns true if the L7Rules are a redirect.
func (a *PerSelectorPolicy) IsRedirect() bool {
	return a != nil && a.isRedirect
}

// HasL7Rules returns whether the `L7Rules` contains any L7 rules.
func (a *PerSelectorPolicy) HasL7Rules() bool {
	return !a.L7Rules.IsEmpty()
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
	// ParserTypeTLS is used for TLS origination, termination, or SNI filtering without any L7
	// parsing. If TLS policies are used with HTTP rules, ParserTypeHTTP is used instead.
	ParserTypeTLS L7ParserType = "tls"
	// ParserTypeCRD is used with a custom CiliumEnvoyConfig redirection. Incompatible with any
	// parser type with L7 enforcement (HTTP, Kafka, proxylib), as the custom Listener generally
	// does not support them.
	ParserTypeCRD L7ParserType = "crd"
	// ParserTypeHTTP specifies a HTTP parser type
	ParserTypeHTTP L7ParserType = "http"
	// ParserTypeKafka specifies a Kafka parser type
	ParserTypeKafka L7ParserType = "kafka"
	// ParserTypeDNS specifies a DNS parser type
	ParserTypeDNS L7ParserType = "dns"
)

// redirectTypes is a bitmask of redirection types of multiple filters
type redirectTypes uint16

const (
	// redirectTypeDNS bit is set when policy contains a redirection to DNS proxy
	redirectTypeDNS redirectTypes = 1 << iota
	// redirectTypeEnvoy bit is set when policy contains a redirection to Envoy
	redirectTypeEnvoy
	// redirectTypeProxylib bits are set when policy contains a redirection to Proxylib (via
	// Envoy)
	redirectTypeProxylib redirectTypes = 1<<iota | redirectTypeEnvoy

	// redirectTypeNone represents the case where there is no proxy redirect
	redirectTypeNone redirectTypes = redirectTypes(0)
)

func (from L7ParserType) canPromoteTo(to L7ParserType) bool {
	switch from {
	case ParserTypeNone:
		// ParserTypeNone can be promoted to any other type
		return true
	case ParserTypeTLS:
		// ParserTypeTLS can be promoted to any other type, except for DNS or CRD,
		// but ParserTypeTLS can not be demoted to ParserTypeNone
		if to != ParserTypeNone && to != ParserTypeDNS && to != ParserTypeCRD {
			return true
		}
	}
	return false
}

// Merge ParserTypes 'a' to 'b' if possible
func (a L7ParserType) Merge(b L7ParserType) (L7ParserType, error) {
	if a == b {
		return a, nil
	}
	if a.canPromoteTo(b) {
		return b, nil
	}
	if b.canPromoteTo(a) {
		return a, nil
	}
	return ParserTypeNone, fmt.Errorf("cannot merge conflicting L7 parsers (%s/%s)", a, b)
}

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
	// This is nil the wildcard selector in not in 'PerSelectorPolicies'.
	// When the wildcard selector is in 'PerSelectorPolicies' this is set to that
	// same selector, which can then be used as a map key to find the corresponding
	// L4-only L7 policy (which can be nil).
	wildcard CachedSelector
	// PerSelectorPolicies is a map of policies for selectors, including any L7 rules passed to
	// the L7 proxy. nil values represent cached selectors that have selector-specific policy
	// restriction (such as no L7 rules). Holds references to the cached selectors, which must
	// be released!
	PerSelectorPolicies L7DataMap `json:"l7-rules,omitempty"`
	// L7Parser specifies the L7 protocol parser (optional). If specified as
	// an empty string, then means that no L7 proxy redirect is performed.
	L7Parser L7ParserType `json:"-"`
	// Listener is an optional fully qualified name of a Envoy Listner defined in a CiliumEnvoyConfig CRD that should be
	// used for this traffic instead of the default listener
	Listener string `json:"listener,omitempty"`
	// Ingress is true if filter applies at ingress; false if it applies at egress.
	Ingress bool `json:"-"`
	// RuleOrigin tracks which policy rules (identified by labels) are the origin for this L3/L4
	// (i.e. selector and port) filter. This information is used when distilling a policy to an
	// EndpointPolicy, to track which policy rules were involved for a specific verdict.
	// Each LabelArrayList is in sorted order.
	RuleOrigin map[CachedSelector]labels.LabelArrayList `json:"-"`

	// This reference is circular, but it is cleaned up at Detach()
	policy atomic.Pointer[L4Policy]
}

// SelectsAllEndpoints returns whether the L4Filter selects all
// endpoints, which is true if the wildcard endpoint selector is present in the
// map.
func (l4 *L4Filter) SelectsAllEndpoints() bool {
	for cs := range l4.PerSelectorPolicies {
		if cs.IsWildcard() {
			return true
		}
	}
	return false
}

// CopyL7RulesPerEndpoint returns a shallow copy of the PerSelectorPolicies of the
// L4Filter.
func (l4 *L4Filter) CopyL7RulesPerEndpoint() L7DataMap {
	return l4.PerSelectorPolicies.ShallowCopy()
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

// GetListener returns the optional listener name.
func (l4 *L4Filter) GetListener() string {
	return l4.Listener
}

// 'entryCallback' is a function called for each entry before adding to a MapState. If the
// function returns 'true', the entry is added, otherwise not. The function gets a reference to the
// entry so that it may update it's value (e.g., the proxy port).
type entryCallback func(key Key, value *MapStateEntry) bool

// ChangeState allows caller to revert changes made by (multiple) toMapState call(s)
type ChangeState struct {
	Adds    Keys     // Added or modified keys, if not nil
	Deletes Keys     // deleted keys, if not nil
	Old     MapState // Old values of all modified or deleted keys, if not nil
}

// toMapState converts a single filter into a MapState entries added to 'p.PolicyMapState'.
//
// Note: It is possible for two selectors to select the same security ID.  To give priority to deny,
// AuthType, and L7 redirection (e.g., for visibility purposes), the mapstate entries are added to
// 'p.PolicyMapState' using denyPreferredInsertWithChanges().
// Keys and old values of any added or deleted entries are added to 'changes'.
// The implementation of 'identities' is also in a locked state.
func (l4Filter *L4Filter) toMapState(p *EndpointPolicy, features policyFeatures, entryCb entryCallback, changes ChangeState) {
	port := uint16(l4Filter.Port)
	proto := uint8(l4Filter.U8Proto)

	direction := trafficdirection.Egress
	if l4Filter.Ingress {
		direction = trafficdirection.Ingress
	}

	logger := log
	if option.Config.Debug {
		logger = log.WithFields(logrus.Fields{
			logfields.Port:             port,
			logfields.PortName:         l4Filter.PortName,
			logfields.Protocol:         proto,
			logfields.TrafficDirection: direction,
		})
	}

	// resolve named port
	if port == 0 && l4Filter.PortName != "" {
		port = p.PolicyOwner.GetNamedPort(l4Filter.Ingress, l4Filter.PortName, proto)
		if port == 0 {
			return // nothing to be done for undefined named port
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
		wildcardRule = l4Filter.PerSelectorPolicies[l4Filter.wildcard]
	}

	for cs, currentRule := range l4Filter.PerSelectorPolicies {
		// have wildcard and this is an L3L4 key?
		isL3L4withWildcardPresent := (l4Filter.Port != 0 || l4Filter.PortName != "") && l4Filter.wildcard != nil && cs != l4Filter.wildcard

		if isL3L4withWildcardPresent && wildcardRule.covers(currentRule) {
			logger.WithField(logfields.EndpointSelector, cs).Debug("ToMapState: Skipping L3/L4 key due to existing L4-only key")
			continue
		}

		isDenyRule := currentRule != nil && currentRule.IsDeny
		isRedirect := currentRule.IsRedirect()
		if !isDenyRule && isL3L4withWildcardPresent && !isRedirect {
			// Inherit the redirect status from the wildcard rule.
			// This is now needed as 'covers()' can pass non-redirect L3L4 rules
			// that must inherit the redirect status from the L4-only (== L3-wildcard)
			// rule due to auth type on the L3L4 rule being different than in the
			// L4-only rule.
			isRedirect = wildcardRule.IsRedirect()
		}
		hasAuth, authType := currentRule.GetAuthType()
		entry := NewMapStateEntry(cs, l4Filter.RuleOrigin[cs], isRedirect, isDenyRule, hasAuth, authType)
		if cs.IsWildcard() {
			keyToAdd.Identity = 0
			if entryCb(keyToAdd, &entry) {
				p.policyMapState.denyPreferredInsertWithChanges(keyToAdd, entry, p.SelectorCache, features, changes)

				if port == 0 {
					// Allow-all
					logger.WithField(logfields.EndpointSelector, cs).Debug("ToMapState: allow all")
				} else {
					// L4 allow
					logger.WithField(logfields.EndpointSelector, cs).Debug("ToMapState: L4 allow all")
				}
			}
			continue
		}

		idents := cs.GetSelections()
		if option.Config.Debug {
			if isDenyRule {
				logger.WithFields(logrus.Fields{
					logfields.EndpointSelector: cs,
					logfields.PolicyID:         idents,
				}).Debug("ToMapState: Denied remote IDs")
			} else {
				logger.WithFields(logrus.Fields{
					logfields.EndpointSelector: cs,
					logfields.PolicyID:         idents,
				}).Debug("ToMapState: Allowed remote IDs")
			}
		}
		for _, id := range idents {
			keyToAdd.Identity = id.Uint32()
			if entryCb(keyToAdd, &entry) {
				p.policyMapState.denyPreferredInsertWithChanges(keyToAdd, entry, p.SelectorCache, features, changes)
				// If Cilium is in dual-stack mode then the "World" identity
				// needs to be split into two identities to represent World
				// IPv6 and IPv4 traffic distinctly from one another.
				if id == identity.ReservedIdentityWorld && option.Config.IsDualStack() {
					keyToAdd.Identity = identity.ReservedIdentityWorldIPv4.Uint32()
					if entryCb(keyToAdd, &entry) {
						p.policyMapState.denyPreferredInsertWithChanges(keyToAdd, entry, p.SelectorCache, features, changes)
					}
					keyToAdd.Identity = identity.ReservedIdentityWorldIPv6.Uint32()
					if entryCb(keyToAdd, &entry) {
						p.policyMapState.denyPreferredInsertWithChanges(keyToAdd, entry, p.SelectorCache, features, changes)
					}
				}
			}
		}
	}
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
	l4Policy := l4.policy.Load()
	if l4Policy != nil {
		direction := trafficdirection.Egress
		if l4.Ingress {
			direction = trafficdirection.Ingress
		}
		perSelectorPolicy := l4.PerSelectorPolicies[selector]
		isRedirect := perSelectorPolicy.IsRedirect()
		hasAuth, authType := perSelectorPolicy.GetAuthType()
		isDeny := perSelectorPolicy != nil && perSelectorPolicy.IsDeny
		l4Policy.AccumulateMapChanges(selector, added, deleted, l4, direction, isRedirect, isDeny, hasAuth, authType)
	}
}

func (l4 *L4Filter) cacheIdentitySelector(sel api.EndpointSelector, lbls labels.LabelArray, selectorCache *SelectorCache) CachedSelector {
	cs, added := selectorCache.AddIdentitySelector(l4, lbls, sel)
	if added {
		l4.PerSelectorPolicies[cs] = nil // no per-selector policy (yet)
	}
	return cs
}

func (l4 *L4Filter) cacheIdentitySelectors(selectors api.EndpointSelectorSlice, lbls labels.LabelArray, selectorCache *SelectorCache) {
	for _, sel := range selectors {
		l4.cacheIdentitySelector(sel, lbls, selectorCache)
	}
}

func (l4 *L4Filter) cacheFQDNSelectors(selectors api.FQDNSelectorSlice, lbls labels.LabelArray, selectorCache *SelectorCache) {
	for _, fqdnSel := range selectors {
		l4.cacheFQDNSelector(fqdnSel, lbls, selectorCache)
	}
}

func (l4 *L4Filter) cacheFQDNSelector(sel api.FQDNSelector, lbls labels.LabelArray, selectorCache *SelectorCache) CachedSelector {
	cs, added := selectorCache.AddFQDNSelector(l4, lbls, sel)
	if added {
		l4.PerSelectorPolicies[cs] = nil // no per-selector policy (yet)
	}
	return cs
}

// add L7 rules for all endpoints in the L7DataMap
func (l7 L7DataMap) addPolicyForSelector(rules *api.L7Rules, terminatingTLS, originatingTLS *TLSContext, auth *api.Authentication, deny bool, sni []string, forceRedirect bool) {
	isRedirect := !deny && (forceRedirect || terminatingTLS != nil || originatingTLS != nil || len(sni) > 0 || !rules.IsEmpty())
	for epsel := range l7 {
		l7policy := &PerSelectorPolicy{
			TerminatingTLS: terminatingTLS,
			OriginatingTLS: originatingTLS,
			Authentication: auth,
			IsDeny:         deny,
			ServerNames:    NewStringSet(sni),
			isRedirect:     isRedirect,
		}
		if rules != nil {
			l7policy.L7Rules = *rules
		}
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
func createL4Filter(policyCtx PolicyContext, peerEndpoints api.EndpointSelectorSlice, auth *api.Authentication, rule api.Ports, port api.PortProtocol,
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
		Port:                int(p),   // 0 for L3-only rules and named ports
		PortName:            portName, // non-"" for named ports
		Protocol:            protocol,
		U8Proto:             u8p,
		PerSelectorPolicies: make(L7DataMap),
		RuleOrigin:          make(map[CachedSelector]labels.LabelArrayList), // Filled in below.
		Ingress:             ingress,
	}

	if peerEndpoints.SelectsAllEndpoints() {
		l4.wildcard = l4.cacheIdentitySelector(api.WildcardEndpointSelector, ruleLabels, selectorCache)
	} else {
		l4.cacheIdentitySelectors(peerEndpoints, ruleLabels, selectorCache)
		l4.cacheFQDNSelectors(fqdns, ruleLabels, selectorCache)
	}

	var terminatingTLS *TLSContext
	var originatingTLS *TLSContext
	var rules *api.L7Rules
	var sni []string
	forceRedirect := false
	pr := rule.GetPortRule()
	if pr != nil {
		rules = pr.Rules
		sni = pr.ServerNames

		// Get TLS contexts, if any
		var err error
		terminatingTLS, err = l4.getCerts(policyCtx, pr.TerminatingTLS, TerminatingTLS)
		if err != nil {
			return nil, err
		}
		originatingTLS, err = l4.getCerts(policyCtx, pr.OriginatingTLS, OriginatingTLS)
		if err != nil {
			return nil, err
		}

		// Set parser type to TLS, if TLS. This will be overridden by L7 below, if rules
		// exists.
		if terminatingTLS != nil || originatingTLS != nil || len(pr.ServerNames) > 0 {
			l4.L7Parser = ParserTypeTLS
		}

		// Determine L7ParserType from rules present. Earlier validation ensures rules
		// for multiple protocols are not present here.
		if rules != nil {
			// we need this to redirect DNS UDP (or ANY, which is more useful)
			if len(rules.DNS) > 0 {
				l4.L7Parser = ParserTypeDNS
			} else if protocol == api.ProtoTCP { // Other than DNS only support TCP
				switch {
				case len(rules.HTTP) > 0:
					l4.L7Parser = ParserTypeHTTP
				case len(rules.Kafka) > 0:
					l4.L7Parser = ParserTypeKafka
				case rules.L7Proto != "":
					l4.L7Parser = (L7ParserType)(rules.L7Proto)
				}
			}
		}

		// Override the parser type to CRD is applicable.
		if pr.Listener != nil {
			l4.L7Parser = ParserTypeCRD
			ns := policyCtx.GetNamespace()
			resource := pr.Listener.EnvoyConfig
			switch resource.Kind {
			case "CiliumEnvoyConfig":
				if ns == "" {
					// Cluster-scoped CCNP tries to use namespaced
					// CiliumEnvoyConfig
					//
					// TODO: Catch this in rule validation once we have a
					// validation context in there so that we can differentiate
					// between CNP and CCNP at validation time.
					return nil, fmt.Errorf("Listener %q in CCNP can not use Kind CiliumEnvoyConfig", pr.Listener.Name)
				}
			case "CiliumClusterwideEnvoyConfig":
				// CNP refers to a cluster-scoped listener
				ns = ""
			default:
			}
			l4.Listener = api.ResourceQualifiedName(ns, resource.Name, pr.Listener.Name, api.ForceNamespace)
			forceRedirect = true
		}
	}

	if l4.L7Parser != ParserTypeNone || auth != nil || policyCtx.IsDeny() {
		l4.PerSelectorPolicies.addPolicyForSelector(rules, terminatingTLS, originatingTLS, auth, policyCtx.IsDeny(), sni, forceRedirect)
	}

	for cs := range l4.PerSelectorPolicies {
		l4.RuleOrigin[cs] = labels.LabelArrayList{ruleLabels}
	}

	return l4, nil
}

func (l4 *L4Filter) removeSelectors(selectorCache *SelectorCache) {
	selectors := make(CachedSelectorSlice, 0, len(l4.PerSelectorPolicies))
	for cs := range l4.PerSelectorPolicies {
		selectors = append(selectors, cs)
	}
	selectorCache.RemoveSelectors(selectors, l4)
}

// detach releases the references held in the L4Filter and must be called before
// the filter is left to be garbage collected.
// L4Filter may still be accessed concurrently after it has been detached.
func (l4 *L4Filter) detach(selectorCache *SelectorCache) {
	l4.removeSelectors(selectorCache)
	l4.policy.Store(nil)
}

// attach signifies that the L4Filter is ready and reacheable for updates
// from SelectorCache. L4Filter (and L4Policy) is read-only after this is called,
// multiple goroutines will be reading the fields from that point on.
func (l4 *L4Filter) attach(ctx PolicyContext, l4Policy *L4Policy) policyFeatures {
	// All rules have been added to the L4Filter at this point.
	// Sort the rules label array list for more efficient equality comparison.
	for _, labels := range l4.RuleOrigin {
		labels.Sort()
	}

	var features policyFeatures
	for cs, cp := range l4.PerSelectorPolicies {
		if cp != nil {
			if cp.IsDeny {
				features.setFeature(denyRules)
			}

			hasAuth, authType := GetAuthType(cp.Authentication)
			if hasAuth {
				features.setFeature(authRules)

				if authType != AuthTypeDisabled {
					if l4Policy.AuthMap == nil {
						l4Policy.AuthMap = make(AuthMap, 1)
					}
					authTypes := l4Policy.AuthMap[cs]
					if authTypes == nil {
						authTypes = make(AuthTypes, 1)
					}
					authTypes[authType] = struct{}{}
					l4Policy.AuthMap[cs] = authTypes
				}
			}

			// Compute Envoy policies when a policy is ready to be used
			if len(cp.L7Rules.HTTP) > 0 {
				cp.EnvoyHTTPRules, cp.CanShortCircuit = ctx.GetEnvoyHTTPRules(&cp.L7Rules)
			}
		}
	}

	l4.policy.Store(l4Policy)
	return features
}

// createL4IngressFilter creates a filter for L4 policy that applies to the
// specified endpoints and port/protocol for ingress traffic, with reference
// to the original rules that the filter is derived from. This filter may be
// associated with a series of L7 rules via the `rule` parameter.
//
// hostWildcardL7 determines if L7 traffic from Host should be
// wildcarded (in the relevant daemon mode).
func createL4IngressFilter(policyCtx PolicyContext, fromEndpoints api.EndpointSelectorSlice, auth *api.Authentication, hostWildcardL7 []string, rule api.Ports, port api.PortProtocol,
	protocol api.L4Proto, ruleLabels labels.LabelArray) (*L4Filter, error) {

	filter, err := createL4Filter(policyCtx, fromEndpoints, auth, rule, port, protocol, ruleLabels, true, nil)
	if err != nil {
		return nil, err
	}

	// If the filter would apply proxy redirection for the Host, when we should accept
	// everything from host, then wildcard Host at L7.
	if len(hostWildcardL7) > 0 {
		for cs, l7 := range filter.PerSelectorPolicies {
			if l7.IsRedirect() && cs.Selects(identity.ReservedIdentityHost) {
				for _, name := range hostWildcardL7 {
					selector := api.ReservedEndpointSelectors[name]
					filter.cacheIdentitySelector(selector, ruleLabels, policyCtx.GetSelectorCache())
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
func createL4EgressFilter(policyCtx PolicyContext, toEndpoints api.EndpointSelectorSlice, auth *api.Authentication, rule api.Ports, port api.PortProtocol,
	protocol api.L4Proto, ruleLabels labels.LabelArray, fqdns api.FQDNSelectorSlice) (*L4Filter, error) {

	return createL4Filter(policyCtx, toEndpoints, auth, rule, port, protocol, ruleLabels, false, fqdns)
}

// redirectType returns the redirectType for this filter
func (l4 *L4Filter) redirectType() redirectTypes {
	switch l4.L7Parser {
	case ParserTypeNone:
		return redirectTypeNone
	case ParserTypeDNS:
		return redirectTypeDNS
	case ParserTypeHTTP, ParserTypeTLS, ParserTypeCRD:
		return redirectTypeEnvoy
	default:
		// all other (non-empty) values are used for proxylib redirects
		return redirectTypeProxylib
	}
}

// IsRedirect returns true if the L4 filter contains a port redirection
func (l4 *L4Filter) IsRedirect() bool {
	return l4.L7Parser != ParserTypeNone
}

// Marshal returns the `L4Filter` in a JSON string.
func (l4 *L4Filter) Marshal() string {
	b, err := json.Marshal(l4)
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
		perSelectorPolicy := l4.PerSelectorPolicies[l4.wildcard]
		isDeny := perSelectorPolicy != nil && perSelectorPolicy.IsDeny
		return true, isDeny
	} else if len(labels) == 0 {
		return false, false
	}

	var selected bool
	for sel, rule := range l4.PerSelectorPolicies {
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

	// To keep the rule origin tracking correct, merge the rule label arrays for each CachedSelector
	// we know about. New CachedSelectors are added.
	for cs, newLabels := range filterToMerge.RuleOrigin {
		if existingLabels, ok := existingFilter.RuleOrigin[cs]; ok {
			existingFilter.RuleOrigin[cs] = existingLabels.MergeSorted(newLabels)
		} else {
			existingFilter.RuleOrigin[cs] = newLabels
		}
	}

	resMap[key] = existingFilter
	return nil
}

// L4PolicyMap is a list of L4 filters indexable by protocol/port
// key format: "port/proto"
type L4PolicyMap map[string]*L4Filter

type policyFeatures uint8

const (
	denyRules policyFeatures = 1 << iota
	authRules

	allFeatures policyFeatures = ^policyFeatures(0)
)

func (pf *policyFeatures) setFeature(feature policyFeatures) {
	*pf |= feature
}

func (pf policyFeatures) contains(feature policyFeatures) bool {
	return pf&feature != 0
}

type L4DirectionPolicy struct {
	PortRules L4PolicyMap

	// features tracks properties of PortRules to skip code when features are not used
	features policyFeatures
}

func newL4DirectionPolicy() L4DirectionPolicy {
	return L4DirectionPolicy{
		PortRules: L4PolicyMap{},
	}
}

// Detach removes the cached selectors held by L4PolicyMap from the
// selectorCache, allowing the map to be garbage collected when there
// are no more references to it.
func (l4 L4DirectionPolicy) Detach(selectorCache *SelectorCache) {
	l4.PortRules.Detach(selectorCache)
}

// detach is used directly from tracing and testing functions
func (l4 L4PolicyMap) Detach(selectorCache *SelectorCache) {
	for _, f := range l4 {
		f.detach(selectorCache)
	}
}

// Attach makes all the L4Filters to point back to the L4Policy that contains them.
// This is done before the L4PolicyMap is exposed to concurrent access.
// Returns the bitmask of all redirect types for this policymap.
func (l4 *L4DirectionPolicy) attach(ctx PolicyContext, l4Policy *L4Policy) redirectTypes {
	var redirectTypes redirectTypes
	var features policyFeatures
	for _, f := range l4.PortRules {
		features |= f.attach(ctx, l4Policy)
		redirectTypes |= f.redirectType()
	}
	l4.features = features
	return redirectTypes
}

// containsAllL3L4 checks if the L4PolicyMap contains all L4 ports in `ports`.
// For L4Filters that specify ToEndpoints or FromEndpoints, uses `labels` to
// determine whether the policy allows L4 communication between the corresponding
// endpoints.
// Returns api.Denied in the following conditions:
//   - If a single port is not present in the `L4PolicyMap` and is not allowed
//     by the distilled L3 policy
//   - If a port is present in the `L4PolicyMap`, but it applies ToEndpoints or
//     FromEndpoints constraints that require labels not present in `labels`.
//
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
			portStr = strconv.FormatUint(uint64(l4Ctx.Port), 10)
		}
		lwrProtocol := l4Ctx.Protocol
		var isUDPDeny, isTCPDeny, isSCTPDeny bool
		switch lwrProtocol {
		case "", models.PortProtocolANY:
			tcpPort := portStr + "/TCP"
			tcpFilter, tcpmatch := l4[tcpPort]
			if tcpmatch {
				tcpmatch, isTCPDeny = tcpFilter.matchesLabels(labels)
			}

			udpPort := portStr + "/UDP"
			udpFilter, udpmatch := l4[udpPort]
			if udpmatch {
				udpmatch, isUDPDeny = udpFilter.matchesLabels(labels)
			}

			sctpPort := portStr + "/SCTP"
			sctpFilter, sctpmatch := l4[sctpPort]
			if sctpmatch {
				sctpmatch, isSCTPDeny = sctpFilter.matchesLabels(labels)
			}

			if (!tcpmatch && !udpmatch && !sctpmatch) || (isTCPDeny && isUDPDeny && isSCTPDeny) {
				return api.Denied
			}
		default:
			port := portStr + "/" + lwrProtocol
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
	Ingress L4DirectionPolicy
	Egress  L4DirectionPolicy

	AuthMap AuthMap

	// Revision is the repository revision used to generate this policy.
	Revision uint64

	// redirectTypes is a bitmap containing the types of redirect contained by this policy.  It
	// is computed after the policy maps to avoid scanning them repeatedly when using the
	// L4Policy
	redirectTypes redirectTypes

	// Endpoint policies using this L4Policy
	// These are circular references, cleaned up in Detach()
	// This mutex is taken while Endpoint mutex is held, so Endpoint lock
	// MUST always be taken before this mutex.
	mutex lock.RWMutex
	users map[*EndpointPolicy]struct{}
}

// NewL4Policy creates a new L4Policy
func NewL4Policy(revision uint64) L4Policy {
	return L4Policy{
		Ingress:  newL4DirectionPolicy(),
		Egress:   newL4DirectionPolicy(),
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
	direction trafficdirection.TrafficDirection, redirect, isDeny bool, hasAuth HasAuthType, authType AuthType) {
	port := uint16(l4Filter.Port)
	proto := uint8(l4Filter.U8Proto)
	derivedFrom := l4Filter.RuleOrigin[cs]

	// Must take a copy of 'users' as GetNamedPort() will lock the Endpoint below and
	// the Endpoint lock may not be taken while 'l4.mutex' is held.
	l4.mutex.RLock()
	users := make(map[*EndpointPolicy]struct{}, len(l4.users))
	for user := range l4.users {
		users[user] = struct{}{}
	}
	l4.mutex.RUnlock()

	for epPolicy := range users {
		// Skip if endpoint has no policy maps
		if !epPolicy.PolicyOwner.HasBPFPolicyMap() {
			continue
		}
		// resolve named port
		if port == 0 && l4Filter.PortName != "" {
			port = epPolicy.PolicyOwner.GetNamedPort(direction == trafficdirection.Ingress, l4Filter.PortName, proto)
			if port == 0 {
				continue
			}
		}
		epPolicy.policyMapChanges.AccumulateMapChanges(cs, adds, deletes, port, proto, direction, redirect, isDeny, hasAuth, authType, derivedFrom)
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
	ingressRedirects := l4.Ingress.attach(ctx, l4)
	egressRedirects := l4.Egress.attach(ctx, l4)
	l4.redirectTypes = ingressRedirects | egressRedirects
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
	return l4 != nil && l4.redirectTypes != redirectTypeNone
}

// HasEnvoyRedirect returns true if the L4 policy contains at least one port redirection to Envoy
func (l4 *L4Policy) HasEnvoyRedirect() bool {
	return l4 != nil && l4.redirectTypes&redirectTypeEnvoy == redirectTypeEnvoy
}

// HasProxylibRedirect returns true if the L4 policy contains at least one port redirection to Proxylib
func (l4 *L4Policy) HasProxylibRedirect() bool {
	return l4 != nil && l4.redirectTypes&redirectTypeProxylib == redirectTypeProxylib
}

func (l4 *L4Policy) GetModel() *models.L4Policy {
	if l4 == nil {
		return nil
	}

	ingress := []*models.PolicyRule{}
	for _, v := range l4.Ingress.PortRules {
		rulesBySelector := map[string][][]string{}
		derivedFrom := labels.LabelArrayList{}
		for sel, rules := range v.RuleOrigin {
			derivedFrom.MergeSorted(rules)
			rulesBySelector[sel.String()] = rules.GetModel()
		}
		ingress = append(ingress, &models.PolicyRule{
			Rule:             v.Marshal(),
			DerivedFromRules: derivedFrom.GetModel(),
			RulesBySelector:  rulesBySelector,
		})
	}

	egress := []*models.PolicyRule{}
	for _, v := range l4.Egress.PortRules {
		derivedFrom := labels.LabelArrayList{}
		for _, rules := range v.RuleOrigin {
			derivedFrom.MergeSorted(rules)
		}
		egress = append(egress, &models.PolicyRule{
			Rule:             v.Marshal(),
			DerivedFromRules: derivedFrom.GetModel(),
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
	GetListener() string
}
