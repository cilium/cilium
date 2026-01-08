// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"iter"
	"log/slog"
	"math/bits"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	cilium "github.com/cilium/proxy/go/cilium/api"
	"github.com/cilium/proxy/pkg/policy/api/kafka"
	k8sTypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/container/bitlpm"
	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/iana"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

type AuthType = types.AuthType
type AuthTypes = types.AuthTypes
type AuthRequirement = types.AuthRequirement

// authmap maps remote selectors to their needed AuthTypes, if any
type authMap map[CachedSelector]types.AuthTypes

// TLS context holds the secret values resolved from an 'api.TLSContext'
type TLSContext struct {
	TrustedCA        string `json:"trustedCA,omitempty"`
	CertificateChain string `json:"certificateChain,omitempty"`
	PrivateKey       string `json:"privateKey,omitempty"`
	// Secret holds the name of the Secret that was referenced in the Policy
	Secret k8sTypes.NamespacedName
	// FromFile is true if the values in the keys above were read from the filesystem
	// and not a Kubernetes Secret
	FromFile bool
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

func (t *TLSContext) String() string {
	data, _ := t.MarshalJSON()
	return string(data)
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
	// L7Parser specifies the L7 protocol parser (optional). If specified as
	// an empty string, then means that no L7 proxy redirect is performed.
	L7Parser L7ParserType `json:"-"`

	// Priority is the priority level for this rule. Defaults to 0. Rules with lower priority
	// values take precedence over rules with later priority values.
	Priority types.Priority `json:"priority,omitempty"`

	// PolicyVerdict specifies if traffic matching this policy should be allowed, denied, or if
	// the verdict should be determined by lower priority rules (pass).
	Verdict types.Verdict `json:"verdict,omitempty"`

	// ListenerPriority of the listener used when multiple listeners would apply to the same
	// MapStateEntry.
	// Lower numbers indicate higher priority. Except for the default 0, which indicates the
	// lowest priority.  If higher priority desired, a low unique number like 1, 2, or 3 should
	// be explicitly specified here.
	ListenerPriority ListenerPriority `json:"listenerPriority,omitempty"`

	// Listener is an optional fully qualified name of a Envoy Listner defined in a
	// CiliumEnvoyConfig CRD that should be used for this traffic instead of the default
	// listener
	Listener string `json:"listener,omitempty"`

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

	// Pre-computed HTTP rules, computed after rule merging is complete
	envoyHTTPRules *cilium.HttpNetworkPolicyRules `json:"-"`

	// canShortCircuit is true if all 'EnvoyHTTPRules' may be
	// short-circuited by other matches.
	canShortCircuit bool `json:"-"`

	api.L7Rules

	// Authentication is the kind of cryptographic authentication required for the traffic to be
	// allowed at L3, if any.
	Authentication *api.Authentication `json:"auth,omitempty"`
}

// CanShortCircuit returns true if EnvoyHTTPRules enforcement can take the first match as the final
// verdict.
func (a *PerSelectorPolicy) CanShortCircuit() bool {
	return a.canShortCircuit
}

// EnvoyHTTPRules returns pre-computed Envoy HTTP rules.
func (a *PerSelectorPolicy) EnvoyHTTPRules() *cilium.HttpNetworkPolicyRules {
	return a.envoyHTTPRules
}

// Equal returns true if 'a' and 'b' represent the same L7 Rules
func (a *PerSelectorPolicy) Equal(b *PerSelectorPolicy) bool {
	return a == nil && b == nil || a != nil && b != nil &&
		a.L7Parser == b.L7Parser &&
		a.TerminatingTLS.Equal(b.TerminatingTLS) &&
		a.OriginatingTLS.Equal(b.OriginatingTLS) &&
		a.ServerNames.Equal(b.ServerNames) &&
		a.Listener == b.Listener &&
		a.ListenerPriority == b.ListenerPriority &&
		(a.Authentication == nil && b.Authentication == nil || a.Authentication != nil && a.Authentication.DeepEqual(b.Authentication)) &&
		a.Verdict == b.Verdict &&
		a.L7Rules.DeepEqual(&b.L7Rules)
}

// GetListener returns the listener of the PerSelectorPolicy.
func (a *PerSelectorPolicy) GetListener() string {
	if a == nil {
		return ""
	}
	return a.Listener
}

// GetListenerPriority returns the pritority of the listener of the PerSelectorPolicy.
func (a *PerSelectorPolicy) GetListenerPriority() ListenerPriority {
	if a == nil {
		return 0
	}
	return a.ListenerPriority
}

// GetPriority returns the priority of the PerSelectorPolicy.
func (a *PerSelectorPolicy) GetPriority() types.Priority {
	if a == nil {
		return 0
	}
	return a.Priority
}

// getAuthType returns AuthType for the api.Authentication
func getAuthType(auth *api.Authentication) (bool, AuthType) {
	if auth == nil {
		return false, types.AuthTypeDisabled
	}
	switch auth.Mode {
	case api.AuthenticationModeDisabled:
		return true, types.AuthTypeDisabled
	case api.AuthenticationModeRequired:
		return true, types.AuthTypeSpire
	case api.AuthenticationModeAlwaysFail:
		return true, types.AuthTypeAlwaysFail
	default:
		return false, types.AuthTypeDisabled
	}
}

// GetAuthRequirement returns the AuthRequirement of the L4Filter.
func (a *PerSelectorPolicy) getAuthRequirement() AuthRequirement {
	if a == nil {
		return AuthRequirement(types.AuthTypeDisabled)
	}
	explicit, authType := getAuthType(a.Authentication)
	req := AuthRequirement(authType)
	if explicit {
		req |= types.AuthTypeIsExplicit
	}
	return req
}

// IsRedirect returns true if the L7Rules are a redirect.
func (sp *PerSelectorPolicy) IsRedirect() bool {
	return sp != nil && sp.L7Parser != ""
}

// HasL7Rules returns whether the `L7Rules` contains any L7 rules.
func (sp *PerSelectorPolicy) HasL7Rules() bool {
	return sp != nil && !sp.L7Rules.IsEmpty()
}

func (a *PerSelectorPolicy) GetVerdict() types.Verdict {
	if a == nil {
		return types.Allow
	}
	return a.Verdict
}

func (a *PerSelectorPolicy) IsDeny() bool {
	return a.GetVerdict() == types.Deny
}

// L7DataMap contains a map of L7 rules per endpoint where key is a CachedSelector
type L7DataMap map[CachedSelector]*PerSelectorPolicy

func (l7 L7DataMap) MarshalJSON() ([]byte, error) {
	if len(l7) == 0 {
		return []byte("[]"), nil
	}

	/* First, create a sorted slice of the selectors so we can get
	 * consistent JSON output */
	selectors := make(types.CachedSelectorSlice, 0, len(l7))
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

type ListenerPriority = types.ListenerPriority

// API listener priorities and corresponding defaults for L7 parser types
// 0 - default (low) priority for all proxy redirects
// 1 - highest listener priority
// ..
// 100 - lowest (non-default) listener priority
// 101 - priority for HTTP parser type
// 106 - priority for the Kafka parser type
// 111 - priority for the proxylib parsers
// 116 - priority for TLS interception parsers (can be promoted to HTTP/Kafka/proxylib)
// 121 - priority for DNS parser type
// 126 - default priority for CRD parser type
// 127 - reserved (listener priority passed as 0)
//
// MapStateEntry stores this reverted in 'ProxyPortPriority' where higher numbers have higher
// precedence
const (
	ListenerPriorityNone  ListenerPriority = 0
	ListenerPriorityHTTP  ListenerPriority = 101
	ListenerPriorityKafka ListenerPriority = 106
	ListenerPriorityTLS   ListenerPriority = 116
	ListenerPriorityDNS   ListenerPriority = 121
	ListenerPriorityCRD   ListenerPriority = 126
)

// defaultPriority maps the parser type to an "API listener priority"
func (l7 L7ParserType) defaultPriority() ListenerPriority {
	switch l7 {
	case ParserTypeNone:
		return ListenerPriorityNone // no priority
	case ParserTypeHTTP:
		return ListenerPriorityHTTP
	case ParserTypeKafka:
		return ListenerPriorityKafka
	case ParserTypeTLS:
		return ListenerPriorityTLS
	case ParserTypeDNS:
		return ListenerPriorityDNS
	case ParserTypeCRD:
		// CRD type can have an explicit higher priority in range 1-100
		return ListenerPriorityCRD
	default:
		return ListenerPriorityNone
	}
}

// redirectTypes is a bitmask of redirection types of multiple filters
type redirectTypes uint16

const (
	// redirectTypeDNS bit is set when policy contains a redirection to DNS proxy
	redirectTypeDNS redirectTypes = 1 << iota
	// redirectTypeEnvoy bit is set when policy contains a redirection to Envoy
	redirectTypeEnvoy

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

// hasWildcard checks if the L7Rules contains a wildcard rule for the given parser type.
func hasWildcard(rules *api.L7Rules, parserType L7ParserType) bool {
	if rules == nil {
		return false
	}

	switch {
	case parserType == ParserTypeDNS:
		for _, rule := range rules.DNS {
			if rule.MatchPattern == "*" {
				return true
			}
		}
	case parserType == ParserTypeHTTP:
		for _, rule := range rules.HTTP {
			if rule.Path == "" && rule.Method == "" && rule.Host == "" &&
				len(rule.Headers) == 0 && len(rule.HeaderMatches) == 0 {
				return true
			}
		}
	case parserType == ParserTypeKafka:
		for _, rule := range rules.Kafka {
			if rule.Topic == "" {
				return true
			}
		}
	case rules.L7Proto != "":
		// For custom L7 rules
		for _, rule := range rules.L7 {
			if len(rule) == 0 {
				return true
			}
		}
	default:
		// Unsupported parser type
	}

	return false
}

// addWildcard adds a wildcard rule to the L7Rules for the given parser type.
// It returns a copy of the rules with the wildcard rule added.
func addWildcard(rules *api.L7Rules, parserType L7ParserType) *api.L7Rules {
	rulesCopy := *rules
	result := &rulesCopy

	switch {
	case parserType == ParserTypeDNS:
		if len(rules.DNS) > 0 {
			result.DNS = append(result.DNS, api.PortRuleDNS{MatchPattern: "*"})
		}
	case parserType == ParserTypeHTTP:
		if len(rules.HTTP) > 0 {
			result.HTTP = append(result.HTTP, api.PortRuleHTTP{})
		}
	case parserType == ParserTypeKafka:
		if len(rules.Kafka) > 0 {
			result.Kafka = append(result.Kafka, kafka.PortRule{})
		}
	case rules.L7Proto != "":
		// For custom L7 rules with L7Proto
		if len(rules.L7) > 0 {
			result.L7 = append(result.L7, api.PortRuleL7{})
		}
	default:
		// Unsupported parser type
	}

	return result
}

// ensureWildcard ensures that the L7Rules contains a wildcard rule for the given parser type.
// It returns a copy of the rules with the wildcard rule added if it wasn't already present.
func ensureWildcard(rules *api.L7Rules, parserType L7ParserType) *api.L7Rules {
	if rules == nil {
		return nil
	}

	if hasWildcard(rules, parserType) {
		return rules
	}

	return addWildcard(rules, parserType)
}

// L4Filter represents the policy (allowed remote sources / destinations of
// traffic) that applies at a specific L4 port/protocol combination (including
// all ports and protocols), at either ingress or egress. The policy here is
// specified in terms of selectors that are mapped to security identities via
// the selector cache.
type L4Filter struct {
	Tier types.Tier `json:"tier,omitempty"`
	// U8Proto is the Protocol in numeric format, or 0 for NONE
	U8Proto u8proto.U8proto `json:"-"`
	// Port is the destination port to allow. Port 0 indicates that all traffic
	// is allowed at L4.
	Port uint16 `json:"port"`
	// EndPort is zero for a singular port
	EndPort uint16 `json:"endPort,omitempty"`
	// Protocol is the L4 protocol to allow or NONE
	Protocol api.L4Proto `json:"protocol"`
	PortName string      `json:"port-name,omitempty"`
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
	// Ingress is true if filter applies at ingress; false if it applies at egress.
	Ingress bool `json:"-"`
	// RuleOrigin is a set of rule labels tracking which policy rules are the origin for this
	// L3/L4 filter.
	RuleOrigin map[CachedSelector]ruleOrigin `json:"-"`

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
func (l4 *L4Filter) GetPerSelectorPolicies() L7DataMap {
	return l4.PerSelectorPolicies
}

// GetIngress returns whether the L4Filter applies at ingress or egress.
func (l4 *L4Filter) GetIngress() bool {
	return l4.Ingress
}

// GetPort returns the port at which the L4Filter applies as a uint16.
func (l4 *L4Filter) GetPort() uint16 {
	return l4.Port
}

// Equals returns true if two L4Filters are equal
func (l4 *L4Filter) Equals(bL4 *L4Filter) bool {
	if l4.Port == bL4.Port &&
		l4.EndPort == bL4.EndPort &&
		l4.PortName == bL4.PortName &&
		l4.Protocol == bL4.Protocol &&
		l4.Ingress == bL4.Ingress &&
		l4.wildcard == bL4.wildcard {

		if len(l4.PerSelectorPolicies) != len(bL4.PerSelectorPolicies) {
			return false
		}
		for k, v := range l4.PerSelectorPolicies {
			bV, ok := bL4.PerSelectorPolicies[k]
			if !ok || !bV.Equal(v) {
				return false
			}

		}
		return true
	}
	return false
}

// ChangeState allows caller to revert changes made by (multiple) toMapState call(s)
// All fields are maps so we can pass this by value.
type ChangeState struct {
	Adds    Keys        // Added or modified keys, if not nil
	Deletes Keys        // deleted keys, if not nil
	old     mapStateMap // Old values of all modified or deleted keys, if not nil
}

func (c *ChangeState) Empty() bool {
	return len(c.Adds)+len(c.Deletes)+len(c.old) == 0
}

// Size returns the total number of Adds minus
// the total number of true Deletes (Deletes
// that are not also in Adds). The return value
// can be negative.
func (c *ChangeState) Size() int {
	deleteLen := 0
	for k := range c.Deletes {
		if _, ok := c.Adds[k]; !ok {
			deleteLen++
		}
	}
	return len(c.Adds) - deleteLen
}

// generateWildcardMapStateEntry creates map state entry for wildcard selector in the filter.
func (l4 *L4Filter) generateWildcardMapStateEntry(logger *slog.Logger, p *EndpointPolicy, port uint16, nextTierPriority types.Priority) mapStateEntry {
	if l4.wildcard != nil {
		currentRule := l4.PerSelectorPolicies[l4.wildcard]
		cs := l4.wildcard

		return l4.makeMapStateEntry(logger, p, port, cs, currentRule, nextTierPriority)
	}

	return makeInvalidEntry()

}

// makeMapStateEntry creates a mapStateEntry for the given selector and policy for the Endpoint.
func (l4 *L4Filter) makeMapStateEntry(logger *slog.Logger, p *EndpointPolicy, port uint16, cs CachedSelector, currentRule *PerSelectorPolicy, nextTierPriority types.Priority) mapStateEntry {
	var proxyPort uint16
	if currentRule.IsRedirect() {
		var err error
		proxyPort, err = p.LookupRedirectPort(l4.Ingress, string(l4.Protocol), port, currentRule.GetListener())
		if err != nil {
			// Skip unrealized redirects; this happens routineously just
			// before new redirects are realized. Once created, we are called
			// again.
			logger.Debug(
				"Skipping unrealized redirect",
				logfields.Error, err,
				logfields.EndpointSelector, cs,
			)
			return makeInvalidEntry()
		}
	}

	return newMapStateEntry(
		currentRule.GetPriority(),
		nextTierPriority,
		l4.RuleOrigin[cs],
		proxyPort,
		currentRule.GetListenerPriority(),
		currentRule.GetVerdict(),
		currentRule.getAuthRequirement(),
	)
}

// toMapState converts a single filter into a MapState entries added to 'p.PolicyMapState'.
//
// Note: It is possible for two selectors to select the same security ID.  To give priority to deny,
// AuthType, and L7 redirection (e.g., for visibility purposes), the mapstate entries are added to
// 'p.PolicyMapState' using insertWithChanges().
// Keys and old values of any added or deleted entries are added to 'changes'.
// 'redirects' is the map of currently realized redirects, it is used to find the proxy port for any redirects.
func (l4 *L4Filter) toMapState(logger *slog.Logger, basePriority, nextTierPriority types.Priority, p *EndpointPolicy, features policyFeatures, changes ChangeState) {
	port := l4.Port
	proto := l4.U8Proto

	direction := trafficdirection.Egress
	if l4.Ingress {
		direction = trafficdirection.Ingress
	}

	scopedLog := logger
	if option.Config.Debug {
		scopedLog = logger.With(
			logfields.Port, port,
			logfields.EndPort, l4.EndPort,
			logfields.PortName, l4.PortName,
			logfields.Protocol, proto,
			logfields.TrafficDirection, direction,
		)
	}

	// resolve named port
	if port == 0 && l4.PortName != "" {
		port = p.PolicyOwner.GetNamedPort(l4.Ingress, l4.PortName, proto)
		if port == 0 {
			return // nothing to be done for undefined named port
		}
	}

	basePrecedence := basePriority.ToPassPrecedence()

	var keysToAdd []Key
	for _, mp := range PortRangeToMaskedPorts(port, l4.EndPort) {
		keysToAdd = append(keysToAdd,
			KeyForDirection(direction).WithPortProtoPrefix(proto, mp.port, uint8(bits.LeadingZeros16(^mp.mask))))
	}

	// Compute the wildcard entry, if present.
	wildcardEntry := l4.generateWildcardMapStateEntry(scopedLog, p, port, nextTierPriority)
	haveWildcard := wildcardEntry.IsValid() || wildcardEntry.IsPassEntry()

	var idents identity.NumericIdentitySlice
	var entry mapStateEntry
	for cs, currentRule := range l4.PerSelectorPolicies {
		// is this wildcard? If so, we already created it above
		if haveWildcard && cs == l4.wildcard {
			entry = wildcardEntry
			// wildcard identity
			idents = identity.NumericIdentitySlice{0}
		} else {
			entry = l4.makeMapStateEntry(logger, p, port, cs, currentRule, nextTierPriority)
			if !entry.IsValid() && !entry.IsPassEntry() {
				continue
			}

			// If this entry is identical to the wildcard's entry, we can elide it.
			// Do not elide for port wildcards. TODO: This is probably too
			// conservative, determine if it's safe to elide l3 entry when no l4 specifier is present.
			if wildcardEntry.IsValid() && port != 0 && entry.MapStateEntry == wildcardEntry.MapStateEntry {
				scopedLog.Debug("ToMapState: Skipping L3/L4 key due to existing identical L4-only key", logfields.EndpointSelector, cs)
				continue
			}
			idents = cs.GetSelectionsAt(p.selectors)
		}

		if option.Config.Debug {
			if entry.IsDeny() {
				scopedLog.Debug(
					"ToMapState: Denied remote IDs",
					logfields.Version, p.selectors,
					logfields.EndpointSelector, cs,
					logfields.PolicyID, idents,
				)
			} else {
				scopedLog.Debug(
					"ToMapState: Allowed remote IDs",
					logfields.Version, p.selectors,
					logfields.EndpointSelector, cs,
					logfields.PolicyID, idents,
				)
			}
		}
		for _, id := range idents {
			for _, keyToAdd := range keysToAdd {
				keyToAdd.Identity = id
				p.policyMapState.insertWithChanges(basePrecedence, keyToAdd, entry, features, changes)
			}
		}
	}
	if option.Config.Debug {
		scopedLog.Debug(
			"ToMapChange changes",
			logfields.PolicyKeysAdded, changes.Adds,
			logfields.PolicyKeysDeleted, changes.Deletes,
			logfields.PolicyEntriesOld, changes.old,
		)
	}
}

// IdentitySelectionUpdated implements CachedSelectionUser interface
// This call is made from a single goroutine in FIFO order to keep add
// and delete events ordered properly. No locks are held.
//
// The caller is responsible for making sure the same identity is not
// present in both 'added' and 'deleted'.
func (l4 *L4Filter) IdentitySelectionUpdated(logger *slog.Logger, cs types.CachedSelector, added, deleted []identity.NumericIdentity) {
	logger.Debug(
		"identities selected by L4Filter updated",
		logfields.EndpointSelector, cs,
		logfields.AddedPolicyID, added,
		logfields.DeletedPolicyID, deleted,
	)

	// Skip updates on wildcard selectors, as datapath and L7
	// proxies do not need enumeration of all ids for L3 wildcard.
	// This mirrors the per-selector logic in toMapState().
	if cs.IsWildcard() {
		return
	}

	// Push endpoint policy changes.
	//
	// `l4.policy` is nil when the filter is detached so
	// that we could not push updates on an unstable policy.
	l4Policy := l4.policy.Load()
	if l4Policy != nil {
		l4Policy.AccumulateMapChanges(logger, l4, cs, added, deleted)
	}
}

func (l4 *L4Filter) IdentitySelectionCommit(logger *slog.Logger, txn SelectorSnapshot) {
	logger.Debug(
		"identity selection updates done",
		logfields.NewVersion, txn,
	)

	// Push endpoint policy incremental sync.
	//
	// `l4.policy` is nil when the filter is detached so
	// that we could not push updates on an unstable policy.
	l4Policy := l4.policy.Load()
	if l4Policy != nil {
		l4Policy.SyncMapChanges(l4, txn)
	}
}

func (l4 *L4Filter) IsPeerSelector() bool {
	return true
}

func (l4 *L4Filter) cacheIdentitySelector(sel api.EndpointSelector, lbls stringLabels, selectorCache *SelectorCache) CachedSelector {
	cs, added := selectorCache.AddIdentitySelectorForTest(l4, lbls, sel)
	if added {
		l4.PerSelectorPolicies[cs] = nil // no per-selector policy (yet)
	}
	return cs
}

// add L7 rules for all endpoints in the L7DataMap
func (l7 L7DataMap) addPolicyForSelector(l7Parser L7ParserType, rules *api.L7Rules, terminatingTLS, originatingTLS *TLSContext, auth *api.Authentication, verdict types.Verdict, sni []string, listener string, listenerPriority ListenerPriority, priority types.Priority) {
	for epsel := range l7 {
		l7policy := &PerSelectorPolicy{
			Priority:         priority,
			L7Parser:         l7Parser,
			TerminatingTLS:   terminatingTLS,
			OriginatingTLS:   originatingTLS,
			Authentication:   auth,
			Verdict:          verdict,
			ServerNames:      NewStringSet(sni),
			Listener:         listener,
			ListenerPriority: listenerPriority,
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

// getCerts reads certificates out of the PolicyContext, reading from k8s or local files depending on config
// and puts the values into the relevant keys in the TLSContext. Note that if the returned TLSContext.FromFile is
// `false`, then this will be read from Kubernetes.
func (l4 *L4Filter) getCerts(policyCtx PolicyContext, tls *api.TLSContext, direction TLSDirection) (*TLSContext, error) {
	if tls == nil {
		return nil, nil
	}

	logger := policyCtx.GetLogger()

	ca, public, private, inlineSecrets, err := policyCtx.GetTLSContext(tls)
	if err != nil {
		logger.Warn(
			"policy: Error getting TLS Context",
			logfields.Error, err,
			logfields.TrafficDirection, direction,
		)
		return nil, err
	}

	// If the secret is not being included into NPDS inline, we're going to pass an SDS reference instead.
	if inlineSecrets {
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
	} else {
		logger.Debug("Secret being read from Kubernetes", logfields.Secret, k8sTypes.NamespacedName(*tls.Secret))
	}

	return &TLSContext{
		TrustedCA:        ca,
		CertificateChain: public,
		PrivateKey:       private,
		FromFile:         inlineSecrets,
		Secret:           k8sTypes.NamespacedName(*tls.Secret),
	}, nil
}

// createL4Filter creates a filter for L4 policy that applies to the specified
// endpoints and port/protocol, with reference to the original rules that the
// filter is derived from. This filter may be associated with a series of L7
// rules via the `rule` parameter.
// Not called with an empty peerEndpoints.
func createL4Filter(policyCtx PolicyContext, entry *types.PolicyEntry, portRule api.Ports, port api.PortProtocol) (*L4Filter, error) {
	selectorCache := policyCtx.GetSelectorCache()
	logger := policyCtx.GetLogger()
	origin := policyCtx.Origin()
	tier, priority := policyCtx.Priority()

	portName := ""
	p := uint64(0)
	if iana.IsSvcName(port.Port) {
		portName = port.Port
	} else {
		// already validated via PortRule.Validate()
		p, _ = strconv.ParseUint(port.Port, 0, 16)
	}

	// already validated via L4Proto.Validate(), never "ANY"
	// NOTE: "ANY" for wildcarded port/proto!
	u8p, _ := u8proto.ParseProtocol(string(port.Protocol))

	l4 := &L4Filter{
		Tier:                tier,
		Port:                uint16(p),            // 0 for L3-only rules and named ports
		EndPort:             uint16(port.EndPort), // 0 for a single port, >= 'Port' for a range
		PortName:            portName,             // non-"" for named ports
		Protocol:            port.Protocol,
		U8Proto:             u8p,
		PerSelectorPolicies: make(L7DataMap),
		RuleOrigin:          make(map[CachedSelector]ruleOrigin), // Filled in below.
		Ingress:             entry.Ingress,
	}

	peerEndpoints := entry.L3
	// For L4 Policy, an empty slice of EndpointSelector indicates that the
	// rule allows all at L3 - explicitly specify this by creating a slice
	// with the WildcardEndpointSelector.
	if len(entry.L3) == 0 {
		peerEndpoints = types.WildcardSelectors
	}

	css, _ := selectorCache.AddSelectorsTxn(l4, origin.stringLabels(), peerEndpoints...)
	for _, cs := range css {
		if cs.IsWildcard() {
			l4.wildcard = cs
		}
		l4.PerSelectorPolicies[cs] = nil // no per-selector policy (yet)
	}

	var l7Parser L7ParserType
	var terminatingTLS *TLSContext
	var originatingTLS *TLSContext
	var rules *api.L7Rules
	var sni []string
	listener := ""
	var listenerPriority ListenerPriority

	pr := portRule.GetPortRule()
	if pr != nil {
		rules = pr.Rules
		sni = pr.GetServerNames()

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
			l7Parser = ParserTypeTLS
		}

		// Determine L7ParserType from rules present. Earlier validation ensures rules
		// for multiple protocols are not present here.
		if rules != nil {
			// we need this to redirect DNS UDP (or ANY, which is more useful)
			if len(rules.DNS) > 0 {
				l7Parser = ParserTypeDNS
			} else if port.Protocol == api.ProtoTCP { // Other than DNS only support TCP
				switch {
				case len(rules.HTTP) > 0:
					l7Parser = ParserTypeHTTP
				case len(rules.Kafka) > 0:
					l7Parser = ParserTypeKafka
				case rules.L7Proto != "":
					l7Parser = (L7ParserType)(rules.L7Proto)
				}
			}
		}

		// Override the parser type and possibly priority for CRD is applicable.
		if pr.Listener != nil {
			l7Parser = ParserTypeCRD
		}

		// Map parser type to default priority for the given parser type
		listenerPriority = l7Parser.defaultPriority()

		// Override the parser type and possibly priority for CRD is applicable.
		if pr.Listener != nil {
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
			listener, _ = api.ResourceQualifiedName(ns, resource.Name, pr.Listener.Name, api.ForceNamespace)
			if pr.Listener.Priority != 0 {
				listenerPriority = ListenerPriority(pr.Listener.Priority)
			}
		}
	}

	if l7Parser != ParserTypeNone || entry.Authentication != nil || !entry.IsAllow() || priority != 0 {
		modifiedRules := rules

		// If we have L7 rules and default deny is disabled (EnableDefaultDeny=false), we should ensure those rules
		// don't cause other L7 traffic to be denied.
		// Special handling for L7 rules is applied when:
		// 1. We have L7 rules
		// 2. Default deny is disabled for this direction
		// 3. This is a positive policy (not a deny policy)
		hasL7Rules := !rules.IsEmpty()
		isDefaultDenyDisabled := (entry.Ingress && !policyCtx.DefaultDenyIngress()) || (!entry.Ingress && !policyCtx.DefaultDenyEgress())
		isAllowPolicy := entry.IsAllow() // note: L7 rules cannot be deny

		if hasL7Rules && isDefaultDenyDisabled && isAllowPolicy {
			logger.Debug("Adding wildcard L7 rules for default-allow policy",
				logfields.L7Parser, l7Parser,
				logfields.Ingress, entry.Ingress)

			modifiedRules = ensureWildcard(rules, l7Parser)
		}

		l4.PerSelectorPolicies.addPolicyForSelector(l7Parser, modifiedRules, terminatingTLS, originatingTLS, entry.Authentication, entry.Verdict, sni, listener, listenerPriority, priority)
	}

	for cs := range l4.PerSelectorPolicies {
		l4.RuleOrigin[cs] = origin
	}

	return l4, nil
}

func (l4 *L4Filter) removeSelectors(selectorCache *SelectorCache) {
	selectors := make(types.CachedSelectorSlice, 0, len(l4.PerSelectorPolicies))
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
func (l4 *L4Filter) attach(ctx PolicyContext, l4Policy *L4Policy) (policyFeatures, redirectTypes) {
	var redirectTypes redirectTypes
	var features policyFeatures

	// Daemon options may induce L3 ingress allows for host. If a filter would apply
	// proxy redirection for the Host, when we should accept everything from host, then
	// wildcard Host at L7 (which is taken care of at the mapstate level).

	for cs, sp := range l4.PerSelectorPolicies {
		if sp != nil {
			// Allow localhost if requested and this is a redirect that selects the host
			if ctx.AllowLocalhost() && l4.Ingress && sp.IsRedirect() && cs.Selects(identity.ReservedIdentityHost) {
				// Make sure host selector is in the selector cache.
				host := api.ReservedEndpointSelectors[labels.IDNameHost]
				// Add the cached host selector to the PerSelectorPolicies, if not
				// already there. Use empty string labels due to this selector being
				// added due to agent config rather than any specific rule.
				l4.cacheIdentitySelector(host, EmptyStringLabels, ctx.GetSelectorCache())
			}

			// collect redirect types (if any)
			redirectTypes |= sp.redirectType()

			if sp.L7Parser != "" {
				features.setFeature(redirectRules)
			}

			if sp.Priority > 0 {
				features.setFeature(orderedRules)
			}

			if sp.Verdict == types.Deny {
				features.setFeature(denyRules)
			}

			explicit, authType := getAuthType(sp.Authentication)
			if explicit {
				features.setFeature(authRules)

				if authType != types.AuthTypeDisabled {
					if l4Policy.authMap == nil {
						l4Policy.authMap = make(authMap, 1)
					}
					authTypes := l4Policy.authMap[cs]
					if authTypes == nil {
						authTypes = make(AuthTypes, 1)
					}
					authTypes[authType] = struct{}{}
					l4Policy.authMap[cs] = authTypes
				}
			}

			// Compute Envoy policies when a policy is ready to be used
			if len(sp.L7Rules.HTTP) > 0 {
				sp.envoyHTTPRules, sp.canShortCircuit = ctx.GetEnvoyHTTPRules(&sp.L7Rules)
			}
		}
	}

	l4.policy.Store(l4Policy)
	return features, redirectTypes
}

// redirectType returns the redirectType for this filter
func (sp *PerSelectorPolicy) redirectType() redirectTypes {
	if sp == nil {
		return redirectTypeNone
	}
	switch sp.L7Parser {
	case ParserTypeNone:
		return redirectTypeNone
	case ParserTypeDNS:
		return redirectTypeDNS
	case ParserTypeHTTP, ParserTypeTLS, ParserTypeCRD:
		return redirectTypeEnvoy
	default:
		return redirectTypeNone
	}
}

// Marshal returns the `L4Filter` in a JSON string.
func (l4 *L4Filter) Marshal() string {
	b, err := json.Marshal(l4)
	if err != nil {
		jsonErr, err2 := json.Marshal(err.Error())
		if err2 != nil {
			jsonErr = []byte("unable to marshall error")
		}
		return "L4Filter error: " + string(jsonErr)
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

// addL4Filter adds 'filterToMerge' into the 'resMap'. Returns an error if it
// the 'filterToMerge' can't be merged with an existing filter for the same
// port and proto.
func (resMap *L4PolicyMap) addL4Filter(policyCtx PolicyContext,
	p api.PortProtocol, filterToMerge *L4Filter,
) error {
	existingFilter := resMap.ExactLookup(p.Port, uint16(p.EndPort), string(p.Protocol))
	if existingFilter == nil {
		resMap.Upsert(p.Port, uint16(p.EndPort), string(p.Protocol), filterToMerge)
		return nil
	}

	if err := existingFilter.mergePortProto(policyCtx, filterToMerge); err != nil {
		filterToMerge.detach(policyCtx.GetSelectorCache())
		return err
	}

	// To keep the rule origin tracking correct, merge the rule label arrays for each
	// CachedSelector we know about. New CachedSelectors are added.
	for cs, newLabels := range filterToMerge.RuleOrigin {
		if existingLabels, ok := existingFilter.RuleOrigin[cs]; ok {
			existingFilter.RuleOrigin[cs] = existingLabels.Merge(newLabels)
		} else {
			existingFilter.RuleOrigin[cs] = newLabels
		}
	}

	resMap.Upsert(p.Port, uint16(p.EndPort), string(p.Protocol), existingFilter)
	return nil
}

// makeL4PolicyMap creates an new L4PolicMap.
func makeL4PolicyMap() L4PolicyMap {
	return L4PolicyMap{
		NamedPortMap:   make(map[string]*L4Filter),
		RangePortMap:   make(map[portProtoKey]*L4Filter),
		RangePortIndex: bitlpm.NewUintTrie[uint32, map[portProtoKey]struct{}](),
	}
}

// L4PolicyMaps is a slice of L4PolicyMap, one for each tier in the policy
type L4PolicyMaps []L4PolicyMap

func (ls L4PolicyMaps) Len() int {
	length := 0
	for i := range ls {
		length += ls[i].Len()
	}
	return length
}

func (ls L4PolicyMaps) Filters() iter.Seq[*L4Filter] {
	return func(yield func(*L4Filter) bool) {
		done := false
		for i := range ls {
			ls[i].ForEach(func(l4 *L4Filter) bool {
				ok := yield(l4)
				if !ok {
					done = true
				}
				return ok
			})
			if done {
				break
			}
		}
	}
}

// NewL4PolicyMapWithValues creates an new L4PolicMap, with an initial
// set of values. The initMap argument does not support port ranges.
func NewL4PolicyMapWithValues(initMap map[string]*L4Filter) L4PolicyMaps {
	l4M := L4PolicyMaps{makeL4PolicyMap()}
	for k, v := range initMap {
		l4M.ensureTier(v.Tier)
		portProtoSlice := strings.Split(k, "/")
		if len(portProtoSlice) < 2 {
			continue
		}
		l4M[v.Tier].Upsert(portProtoSlice[0], 0, portProtoSlice[1], v)
	}
	return l4M
}

type portProtoKey struct {
	Port, EndPort uint16
	Proto         uint8
}

// L4PolicyMap is the implementation of L4PolicyMap
type L4PolicyMap struct {
	// NamedPortMap represents the named ports (a Kubernetes feature)
	// that map to an L4Filter. They must be tracked at the selection
	// level, because they can only be resolved at the endpoint/identity
	// level. Named ports cannot have ranges.
	NamedPortMap map[string]*L4Filter
	// RangePortMap is a map of all L4Filters indexed by their port-
	// protocol.
	RangePortMap map[portProtoKey]*L4Filter
	// RangePortIndex is an index of all L4Filters so that
	// L4Filters that have overlapping port ranges can be looked up
	// by with a single port.
	RangePortIndex *bitlpm.UintTrie[uint32, map[portProtoKey]struct{}]
}

func parsePortProtocol(port, protocol string) (uint16, uint8) {
	// These string values have been validated many times
	// over at this point.
	prt, _ := strconv.ParseUint(port, 10, 16)
	proto, _ := u8proto.ParseProtocol(protocol)
	return uint16(prt), uint8(proto)
}

// makePolicyMapKey creates a protocol-port uint32 with the
// upper 16 bits containing the protocol and the lower 16
// bits containing the port.
func makePolicyMapKey(port, mask uint16, proto uint8) uint32 {
	return (uint32(proto) << 16) | uint32(port&mask)
}

// Upsert L4Filter adds an L4Filter indexed by protocol/port-endPort.
func (l4M *L4PolicyMap) Upsert(port string, endPort uint16, protocol string, l4 *L4Filter) {
	if iana.IsSvcName(port) {
		l4M.NamedPortMap[port+"/"+protocol] = l4
		return
	}

	portU, protoU := parsePortProtocol(port, protocol)
	ppK := portProtoKey{
		Port:    portU,
		EndPort: endPort,
		Proto:   protoU,
	}
	_, indexExists := l4M.RangePortMap[ppK]
	l4M.RangePortMap[ppK] = l4
	// We do not need to reindex a key that already exists,
	// even if the filter changed.
	if !indexExists {
		for _, mp := range PortRangeToMaskedPorts(portU, endPort) {
			k := makePolicyMapKey(mp.port, mp.mask, protoU)
			prefix := 32 - uint(bits.TrailingZeros16(mp.mask))
			portProtoSet, ok := l4M.RangePortIndex.ExactLookup(prefix, k)
			if !ok {
				portProtoSet = make(map[portProtoKey]struct{})
				l4M.RangePortIndex.Upsert(prefix, k, portProtoSet)
			}
			portProtoSet[ppK] = struct{}{}
		}
	}
}

// Delete an L4Filter from the index by protocol/port-endPort
func (l4M *L4PolicyMap) Delete(port string, endPort uint16, protocol string) {
	if iana.IsSvcName(port) {
		delete(l4M.NamedPortMap, port+"/"+protocol)
		return
	}

	portU, protoU := parsePortProtocol(port, protocol)
	ppK := portProtoKey{
		Port:    portU,
		EndPort: endPort,
		Proto:   protoU,
	}
	_, indexExists := l4M.RangePortMap[ppK]
	delete(l4M.RangePortMap, ppK)
	// Only delete the index if the key exists.
	if indexExists {
		for _, mp := range PortRangeToMaskedPorts(portU, endPort) {
			k := makePolicyMapKey(mp.port, mp.mask, protoU)
			prefix := 32 - uint(bits.TrailingZeros16(mp.mask))
			portProtoSet, ok := l4M.RangePortIndex.ExactLookup(prefix, k)
			if !ok {
				return
			}
			delete(portProtoSet, ppK)
			if len(portProtoSet) == 0 {
				l4M.RangePortIndex.Delete(prefix, k)
			}
		}
	}
}

// ExactLookup looks up an L4Filter by protocol/port-endPort and looks for an exact match.
func (l4M *L4PolicyMap) ExactLookup(port string, endPort uint16, protocol string) *L4Filter {
	if iana.IsSvcName(port) {
		return l4M.NamedPortMap[port+"/"+protocol]
	}

	portU, protoU := parsePortProtocol(port, protocol)
	ppK := portProtoKey{
		Port:    portU,
		EndPort: endPort,
		Proto:   protoU,
	}
	return l4M.RangePortMap[ppK]
}

// ForEach iterates over all L4Filters in the l4PolicyMap.
func (l4M *L4PolicyMap) ForEach(fn func(l4 *L4Filter) bool) {
	for _, f := range l4M.NamedPortMap {
		if !fn(f) {
			return
		}
	}
	for _, v := range l4M.RangePortMap {
		if !fn(v) {
			return
		}
	}
}

// Len returns the number of entries in the map.
func (l4M *L4PolicyMap) Len() int {
	if l4M == nil {
		return 0
	}
	return len(l4M.NamedPortMap) + len(l4M.RangePortMap)
}

type policyFeatures uint8

const (
	denyRules policyFeatures = 1 << iota
	redirectRules
	orderedRules
	authRules

	// if any of the precedenceFeatures is set, then we need to scan for policy overrides due to
	// precedence differences between rules.
	precedenceFeatures policyFeatures = denyRules | redirectRules | orderedRules

	allFeatures policyFeatures = ^policyFeatures(0)
)

func (pf *policyFeatures) setFeature(feature policyFeatures) {
	*pf |= feature
}

func (pf policyFeatures) contains(feature policyFeatures) bool {
	return pf&feature != 0
}

type L4DirectionPolicy struct {
	PortRules L4PolicyMaps

	// TierBasePriority stores the starting priority for each tier.
	// For tier 0 this is always 0, for later tiers this should be a priority lower (numerically
	// higher) than any rule's priority on the preceding tiers.
	tierBasePriority []types.Priority

	// features tracks properties of PortRules to skip code when features are not used
	features policyFeatures
}

// newL4DirectionPolicy creates a new L4DirectionPolicy with slices initialized for one tier for
// legacy compatibility as testing code assumes indexing by '0' works in all situations.
func newL4DirectionPolicy() L4DirectionPolicy {
	return L4DirectionPolicy{
		PortRules:        L4PolicyMaps{makeL4PolicyMap()},
		tierBasePriority: make([]types.Priority, 1),
	}
}

func (l4 L4DirectionPolicy) Filters() iter.Seq[*L4Filter] {
	return l4.PortRules.Filters()
}

// Detach removes the cached selectors held by L4PolicyMap from the
// selectorCache, allowing the map to be garbage collected when there
// are no more references to it.
func (l4 L4DirectionPolicy) Detach(selectorCache *SelectorCache) {
	for f := range l4.Filters() {
		f.detach(selectorCache)
	}
}

// Attach makes all the L4Filters to point back to the L4Policy that contains them.
// This is done before the L4PolicyMap is exposed to concurrent access.
// Returns the bitmask of all redirect types for this policymap.
func (l4 *L4DirectionPolicy) attach(ctx PolicyContext, l4Policy *L4Policy) redirectTypes {
	var redirectTypes redirectTypes
	var features policyFeatures

	for f := range l4.Filters() {
		feat, redir := f.attach(ctx, l4Policy)
		features |= feat
		redirectTypes |= redir
	}

	l4.features = features
	return redirectTypes
}

type L4Policy struct {
	Ingress L4DirectionPolicy
	Egress  L4DirectionPolicy

	authMap authMap

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
// May not call into SelectorCache, as SelectorCache is locked during this call.
func (l4 *L4Policy) insertUser(user *EndpointPolicy) {
	l4.mutex.Lock()

	// 'users' is set to nil when the policy is detached. This
	// happens to the old policy when it is being replaced with a
	// new one, or when the last endpoint using this policy is
	// removed.
	// In the case of an policy update it is possible that an
	// endpoint has started regeneration before the policy was
	// updated, and that the policy was updated before the said
	// endpoint reached this point. In this case, we need to
	// ensure that the endpoint will be regenerated at least once
	// afterward. This to ensure it doesn't get stuck with a
	// detached policy.
	if l4.users != nil {
		l4.users[user] = struct{}{}
	} else {
		go user.PolicyOwner.RegenerateIfAlive(&regeneration.ExternalRegenerationMetadata{
			Reason:            "selector policy has changed because of another endpoint with the same identity",
			RegenerationLevel: regeneration.RegenerateWithoutDatapath,
		})
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
func (l4Policy *L4Policy) AccumulateMapChanges(logger *slog.Logger, l4 *L4Filter, cs CachedSelector, adds, deletes []identity.NumericIdentity) {
	port := uint16(l4.Port)
	proto := l4.U8Proto
	derivedFrom := l4.RuleOrigin[cs]

	direction := trafficdirection.Egress
	directionPolicy := &l4Policy.Egress
	if l4.Ingress {
		direction = trafficdirection.Ingress
		directionPolicy = &l4Policy.Ingress
	}
	perSelectorPolicy := l4.PerSelectorPolicies[cs]
	redirect := perSelectorPolicy.IsRedirect()
	listener := perSelectorPolicy.GetListener()
	listenerPriority := perSelectorPolicy.GetListenerPriority()
	authReq := perSelectorPolicy.getAuthRequirement()
	verdict := perSelectorPolicy.GetVerdict()
	tier := l4.Tier
	priority := perSelectorPolicy.GetPriority()
	basePriority := directionPolicy.tierBasePriority[tier]
	nextTierPriority := types.MaxPriority
	if len(directionPolicy.tierBasePriority) > int(tier)+1 {
		nextTierPriority = directionPolicy.tierBasePriority[tier+1]
	}

	// Can hold rlock here as neither GetNamedPort() nor LookupRedirectPort() no longer
	// takes the Endpoint lock below.
	// SelectorCache may not be called into while holding this lock!
	l4Policy.mutex.RLock()
	defer l4Policy.mutex.RUnlock()

	for epPolicy := range l4Policy.users {
		// resolve named port
		if port == 0 && l4.PortName != "" {
			port = epPolicy.PolicyOwner.GetNamedPort(l4.Ingress, l4.PortName, proto)
			if port == 0 {
				continue
			}
		}
		var proxyPort uint16
		if redirect {
			var err error
			proxyPort, err = epPolicy.LookupRedirectPort(l4.Ingress, string(l4.Protocol), port, listener)
			if err != nil {
				logger.Warn(
					"AccumulateMapChanges: Missing redirect.",
					logfields.EndpointSelector, cs,
					logfields.Port, port,
					logfields.Protocol, proto,
					logfields.TrafficDirection, direction,
					logfields.Priority, priority,
					logfields.IsRedirect, redirect,
					logfields.Listener, listener,
					logfields.ListenerPriority, listenerPriority,
				)
				continue
			}
		}
		var keysToAdd []Key
		for _, mp := range PortRangeToMaskedPorts(port, l4.EndPort) {
			keysToAdd = append(keysToAdd,
				KeyForDirection(direction).WithPortProtoPrefix(proto, mp.port, uint8(bits.LeadingZeros16(^mp.mask))))
		}

		value := newMapStateEntry(priority, nextTierPriority, derivedFrom, proxyPort, listenerPriority, verdict, authReq)

		// If the entry is identical to wildcard map entry, we can elide it.
		// See comment in L4Filter.toMapState()
		wildcardMapEntry := l4.generateWildcardMapStateEntry(logger, epPolicy, port, nextTierPriority)

		if wildcardMapEntry.IsValid() && port != 0 && value.MapStateEntry == wildcardMapEntry.MapStateEntry {
			logger.Debug(
				"AccumulateMapChanges: Skipping L3/L4 key due to existing identical L4-only key",
				logfields.EndpointSelector, cs)
			continue
		}

		if option.Config.Debug {
			authString := "default"
			if authReq.IsExplicit() {
				authString = authReq.AuthType().String()
			}
			logger.Debug(
				"AccumulateMapChanges",
				logfields.EndpointSelector, cs,
				logfields.AddedPolicyID, adds,
				logfields.DeletedPolicyID, deletes,
				logfields.Port, port,
				logfields.Protocol, proto,
				logfields.TrafficDirection, direction,
				logfields.IsRedirect, redirect,
				logfields.AuthType, authString,
				logfields.Listener, listener,
				logfields.ListenerPriority, listenerPriority,
				logfields.Tier, tier,
				logfields.TierBasePriority, basePriority,
				logfields.Priority, priority,
			)
		}
		epPolicy.policyMapChanges.AccumulateMapChanges(tier, basePriority, adds, deletes, keysToAdd, value)
	}
}

// SyncMapChanges marks earlier updates as completed
func (l4Policy *L4Policy) SyncMapChanges(l4 *L4Filter, txn SelectorSnapshot) {
	// SelectorCache may not be called into while holding this lock!
	l4Policy.mutex.RLock()

	for epPolicy := range l4Policy.users {
		epPolicy.policyMapChanges.SyncMapChanges(txn)
	}
	l4Policy.mutex.RUnlock()
}

// detach makes the L4Policy ready for garbage collection, removing
// circular pointer references.
// The endpointID argument is only necessary if isDelete is false.
// It ensures that detach does not call a regeneration trigger on
// the same endpoint that initiated a selector policy update.
// Note that the L4Policy itself is not modified in any way, so that it may still
// be used concurrently.
func (l4 *L4Policy) detach(selectorCache *SelectorCache, isDelete bool, endpointID uint64) {
	l4.Ingress.Detach(selectorCache)
	l4.Egress.Detach(selectorCache)

	l4.mutex.Lock()
	defer l4.mutex.Unlock()
	// If this detach is a delete there is no reason to initiate
	// a regenerate.
	if !isDelete {
		for ePolicy := range l4.users {
			if endpointID != ePolicy.PolicyOwner.GetID() {
				go ePolicy.PolicyOwner.RegenerateIfAlive(&regeneration.ExternalRegenerationMetadata{
					Reason:            "selector policy has changed because of another endpoint with the same identity",
					RegenerationLevel: regeneration.RegenerateWithoutDatapath,
				})
			}
		}
	}
	l4.users = nil
}

// Attach makes all the L4Filters to point back to the L4Policy that contains them.
// This is done before the L4Policy is exposed to concurrent access.
func (l4 *L4Policy) Attach(ctx PolicyContext) {
	ingressRedirects := l4.Ingress.attach(ctx, l4)
	egressRedirects := l4.Egress.attach(ctx, l4)
	l4.redirectTypes = ingressRedirects | egressRedirects
}

// HasRedirect returns true if the L4 policy contains at least one port redirection
func (l4 *L4Policy) HasRedirect() bool {
	return l4 != nil && l4.redirectTypes != redirectTypeNone
}

// HasEnvoyRedirect returns true if the L4 policy contains at least one port redirection to Envoy
func (l4 *L4Policy) HasEnvoyRedirect() bool {
	return l4 != nil && l4.redirectTypes&redirectTypeEnvoy == redirectTypeEnvoy
}

// GetModel returns the API model of the L4 policy.
func (l4 *L4Policy) GetModel() *models.L4Policy {
	if l4 == nil {
		return nil
	}

	ingress := []*models.PolicyRule{}
	for v := range l4.Ingress.Filters() {
		rulesBySelector := map[string][][]string{}
		derivedFrom := labels.LabelArrayList{}
		for sel, rules := range v.RuleOrigin {
			lal := rules.GetLabelArrayList()
			derivedFrom.MergeSorted(lal)
			rulesBySelector[sel.String()] = lal.GetModel()
		}
		ingress = append(ingress, &models.PolicyRule{
			Rule:             v.Marshal(),
			DerivedFromRules: derivedFrom.GetModel(),
			RulesBySelector:  rulesBySelector,
		})
	}

	egress := []*models.PolicyRule{}
	for v := range l4.Egress.Filters() {
		// TODO: Add RulesBySelector field like for ingress above?
		derivedFrom := labels.LabelArrayList{}
		for _, rules := range v.RuleOrigin {
			lal := rules.GetLabelArrayList()
			derivedFrom.MergeSorted(lal)
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

// GetRuleOriginModel returns the API model of the L4 policy with the rule origins only.
func (l4 *L4Policy) GetRuleOriginModel() *models.L4Policy {
	if l4 == nil {
		return nil
	}

	ingress := []*models.PolicyRule{}
	for v := range l4.Ingress.Filters() {
		derivedFrom := labels.LabelArrayList{}
		for _, rules := range v.RuleOrigin {
			lal := rules.GetLabelArrayList()
			derivedFrom.MergeSorted(lal)
		}
		ingress = append(ingress, &models.PolicyRule{
			DerivedFromRules: derivedFrom.GetModel(),
		})
	}

	egress := []*models.PolicyRule{}
	for v := range l4.Egress.Filters() {
		derivedFrom := labels.LabelArrayList{}
		for _, rules := range v.RuleOrigin {
			lal := rules.GetLabelArrayList()
			derivedFrom.MergeSorted(lal)
		}
		egress = append(egress, &models.PolicyRule{
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
	GetPerSelectorPolicies() L7DataMap
	GetL7Parser() L7ParserType
	GetIngress() bool
	GetPort() uint16
	GetProtocol() u8proto.U8proto
	GetListener() string
}
