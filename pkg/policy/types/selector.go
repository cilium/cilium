// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package types

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/cilium/statedb/part"

	"github.com/cilium/cilium/pkg/identity"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
)

// PeerSelector is a marker for all API types that can be converted to Selectors and used as peer
// selectors in the policy.
type PeerSelector interface {
	IsPeerSelector()

	// KeyString is a unique string for the given selector that is used as a key in
	// selector maps. Must never be an empty string.
	KeyString() string
}

var (
	WildcardSelector  = NewLabelSelectorFromLabels()
	WildcardSelectors = Selectors{WildcardSelector}
)

// Selectors is a slice of Selectors.
type Selectors []Selector

func (ps Selectors) Matches(logger *slog.Logger, lbls labels.LabelArray) bool {
	for i := range ps {
		if ps[i].Matches(logger, lbls) {
			return true
		}
	}
	return false
}

// DeepEqual returns true if both Selectors slices are deeply equal.
// As the elements of the slice are interfaces, we have to implement
// a type switch and call DeepEqual on each possible concrete type.
func (s *Selectors) DeepEqual(other *Selectors) bool {
	if s == nil && other == nil {
		return true
	}
	if s == nil || other == nil {
		return false
	}
	if len(*s) != len(*other) {
		return false
	}

	for idx := range *s {
		p1, p2 := (*s)[idx], (*other)[idx]
		switch v1 := p1.(type) {
		case *LabelSelector:
			if v2, ok := p2.(*LabelSelector); !ok || !v1.DeepEqual(v2) {
				return false
			}
		case *FQDNSelector:
			if v2, ok := p2.(*FQDNSelector); !ok || !v1.DeepEqual(v2) {
				return false
			}
		case *CIDRSelector:
			if v2, ok := p2.(*CIDRSelector); !ok || !v1.DeepEqual(v2) {
				return false
			}
		default:
			return false
		}
	}

	return true
}

// WithRequirements returns a copy of the Selectors with the specified
// label requirements applied to all EndpointSelectors.
func (s Selectors) WithRequirements(requirements []slim_metav1.LabelSelectorRequirement) Selectors {
	if len(requirements) == 0 || len(s) == 0 {
		return s
	}

	haveLabelSelectors := false
	for _, sel := range s {
		if _, ok := sel.(*LabelSelector); ok {
			haveLabelSelectors = true
		}
	}
	if !haveLabelSelectors {
		return s
	}

	res := make(Selectors, 0, len(s))
	for _, sel := range s {
		if ls, ok := sel.(*LabelSelector); ok {
			// replace with LabelSelector with requirements added
			sel = NewLabelSelector(api.EndpointSelector{
				LabelSelector: &slim_metav1.LabelSelector{
					MatchLabels:      ls.ls.MatchLabels,
					MatchExpressions: append(slices.Clone(ls.ls.MatchExpressions), requirements...),
				},
			})
		}
		res = append(res, sel)
	}
	return res
}

// ToSelector converts any supported concrete type that implements PeerSelector
// into a Selector.
func ToSelector[T PeerSelector](peer T) Selector {
	var source Selector
	switch v := any(peer).(type) {
	case *slim_metav1.LabelSelector:
		if v == nil {
			return nil
		}
		source = NewLabelSelector(api.EndpointSelector{LabelSelector: v})
	case api.EndpointSelector:
		if v.LabelSelector == nil {
			return nil
		}
		source = NewLabelSelector(v)
	case api.CIDR:
		source = NewCIDRSelector(v.KeyString(), v, nil)
	case api.CIDRRule:
		source = newCIDRRuleSelector(v)
	case api.FQDNSelector:
		source = NewFqdnSelector(v)
	}

	return source
}

// ToSelectors converts a slice of any supported concrete type that implements PeerSelector
// into a Selectors slice.
func ToSelectors[T PeerSelector](peers []T) Selectors {
	if len(peers) == 0 {
		return nil
	}
	sources := make(Selectors, len(peers))
	for idx := range peers {
		source := ToSelector(peers[idx])
		if source == nil {
			continue
		}
		sources[idx] = source
	}
	return sources
}

// CIDRRules returns a slice of api.CIDRRule for Selectors.
//
// Note: Only used in unit tests, but in multiple packages
// Minimal implementation to cover the needs of current tests.
func (ps Selectors) CIDRRules() api.CIDRRuleSlice {
	result := make(api.CIDRRuleSlice, 0)
	for _, v := range ps {
		if ps, ok := v.(*CIDRSelector); ok && len(ps.requirements) > 0 {
			var cidrRule api.CIDRRule
			for lbl, exists := range ps.requirements.KeyOnlyRequirements() {
				str, err := lbl.ToCIDRString()
				if err != nil {
					// Not a CIDR label
					continue
				}
				if exists {
					cidrRule.Cidr = api.CIDR(str)
				} else if lbl.Source == labels.LabelSourceCIDR {
					cidrRule.ExceptCIDRs = append(cidrRule.ExceptCIDRs, api.CIDR(str))
				}
			}
			cidrRule.Generated = ps.generated
			result = append(result, cidrRule)
		}
	}
	return result
}

// GetRuleTypes returns booleans for some features used in Selectors.
// Only used from pkg/metrics/features/policy.go
func (s Selectors) GetRuleTypes() (fqdn, host, cidrGroup bool) {
	for idx := range s {
		if !fqdn {
			if _, ok := s[idx].(*FQDNSelector); ok {
				fqdn = true
				continue
			}
		}
		if !host {
			if ls, ok := s[idx].(*LabelSelector); ok {
				if ls.ls == nil {
					continue
				}
				if ls.HasKeyPrefix(labels.LabelSourceNode) {
					host = true
				}
			}
		}
		if !cidrGroup {
			if cs, ok := s[idx].(*CIDRSelector); ok {
				for i := range cs.requirements {
					if cs.requirements[i].HasKeySource(labels.LabelSourceCIDRGroup) {
						cidrGroup = true
						break
					}
				}
			}
		}
		if fqdn && host && cidrGroup {
			break
		}
	}
	return
}

// Selector is a generic representation of a policy selector.
type Selector interface {
	Key() string

	IsWildcard() bool

	SelectedNamespaces() []string // allowed namespaces, or nil for no requirement

	Matches(logger *slog.Logger, labels labels.LabelArray) bool

	GetFQDNSelector() (*api.FQDNSelector, bool)

	GetCIDRPrefixes() []netip.Prefix

	MetricsClass() string
}

// +deepequal-gen=true
type LabelSelector struct {
	key          string
	ls           *slim_metav1.LabelSelector
	requirements Requirements
	class        string
	namespaces   []string // allowed namespaces, or nil for no namespace requirement
}

func (p *LabelSelector) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.ls)
}

func NewLabelSelector(es api.EndpointSelector) *LabelSelector {
	requirements := LabelSelectorToRequirements(es.LabelSelector)
	namespaces, _ := requirements.GetFirstK8sMatch(k8sConst.PodNamespaceLabel)
	key := es.KeyString()

	class := LabelValueSCOther
	for _, entity := range api.EntitySelectorMapping[api.EntityCluster] {
		if entity.KeyString() == key {
			class = LabelValueSCCluster
		}
	}
	for _, entity := range api.EntitySelectorMapping[api.EntityWorld] {
		if entity.KeyString() == key {
			class = LabelValueSCWorld
		}
	}

	return &LabelSelector{
		key:          key,
		ls:           es.LabelSelector,
		requirements: requirements,
		class:        class,
		namespaces:   namespaces,
	}
}

func NewLabelSelectorFromLabels(lbls ...labels.Label) *LabelSelector {
	ml := map[string]string{}
	for _, lbl := range lbls {
		ml[lbl.GetExtendedKey()] = lbl.Value
	}

	labelSelector := &slim_metav1.LabelSelector{
		MatchLabels: ml,
	}

	return NewLabelSelector(api.EndpointSelector{LabelSelector: labelSelector})
}

func (p *LabelSelector) Key() string {
	return p.key
}

func (p *LabelSelector) IsWildcard() bool {
	return len(p.requirements) == 0
}

func (p *LabelSelector) SelectedNamespaces() []string {
	return p.namespaces
}

// matchesLabels returns true if the CachedSelector matches given labels.
func (p *LabelSelector) Matches(logger *slog.Logger, lbls labels.LabelArray) bool {
	return MatchesRequirements(logger, p.requirements, lbls)
}

func (p *LabelSelector) GetFQDNSelector() (*api.FQDNSelector, bool) {
	return nil, false
}

func (p *LabelSelector) GetCIDRPrefixes() []netip.Prefix {
	return nil
}

func (p *LabelSelector) MetricsClass() string {
	return p.class
}

// LabelSelector is also used directly as a subject selector. Additional functions outside of the
// Selector interface are defined for this use below.

func Matches[T labels.LabelMatcher](logger *slog.Logger, s *LabelSelector, ls T) bool {
	return MatchesRequirements(logger, s.requirements, ls)
}

// HasKeyPrefix checks if the label selector contains the given key prefix in
// its MatchLabels map and MatchExpressions slice.
func (p *LabelSelector) HasKeyPrefix(prefix string) bool {
	for k := range p.ls.MatchLabels {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	for _, v := range p.ls.MatchExpressions {
		if strings.HasPrefix(v.Key, prefix) {
			return true
		}
	}
	return false
}

// +deepequal-gen=true
type FQDNSelector struct {
	key          string
	requirements api.FQDNSelector
	label        labels.Label
}

func (p *FQDNSelector) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.key)
}

func NewFqdnSelector(s api.FQDNSelector) *FQDNSelector {
	return &FQDNSelector{
		key:          s.KeyString(),
		requirements: s,
		label:        s.IdentityLabel(),
	}
}

func (p *FQDNSelector) Key() string {
	return p.key
}

func (p *FQDNSelector) IsWildcard() bool {
	return false
}

func (p *FQDNSelector) SelectedNamespaces() []string {
	return nil
}

func (p *FQDNSelector) GetFQDNSelector() (*api.FQDNSelector, bool) {
	return &p.requirements, true
}

func (p *FQDNSelector) GetCIDRPrefixes() []netip.Prefix {
	return nil
}

// matches returns true if the identity contains at least one label
// that matches the FQDNSelector's IdentityLabel string
func (p *FQDNSelector) Matches(_ *slog.Logger, lbls labels.LabelArray) bool {
	return lbls.IntersectsLabel(p.label)
}

func (p *FQDNSelector) MetricsClass() string {
	return LabelValueSCFQDN
}

// +deepequal-gen=true
type CIDRSelector struct {
	key          string
	requirements Requirements
	generated    bool // only needed for current unit tests via Selectors.CIDRRules()
}

func (p *CIDRSelector) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.key)
}

func newCIDRSelectorFromRequirements(key string, prefix netip.Prefix, reqs Requirements, except []api.CIDR) *CIDRSelector {
	for _, exCIDR := range except {
		pfx, err := netip.ParsePrefix(string(exCIDR))
		if err != nil {
			panic(fmt.Sprintf("%q is not a CIDR except: %v", exCIDR, err))
		}
		lbl := labels.GetCIDRLabel(pfx.Masked())
		reqs = append(reqs, NewExceptRequirement(lbl))
	}

	return &CIDRSelector{
		key:          key,
		requirements: reqs,
	}
}

func NewCIDRSelector(key string, cidr api.CIDR, except []api.CIDR) *CIDRSelector {
	var prefix netip.Prefix
	var err error
	i := strings.LastIndexByte(string(cidr), '/')
	if i < 0 {
		parsedIP, err := netip.ParseAddr(string(cidr))
		if err != nil {
			// input is sanitized, so this panic should never fire
			panic(fmt.Errorf("%q is not an IP address: %w", cidr, err))
		}
		prefix, err = parsedIP.Prefix(parsedIP.BitLen())
		if err != nil {
			// input is sanitized, so this panic should never fire
			panic(fmt.Errorf("%q could not be made a Prefix: %w", cidr, err))
		}
	} else {
		prefix, err = netip.ParsePrefix(string(cidr))
		if err != nil {
			// input is sanitized, so this panic should never fire
			panic(fmt.Errorf("%q is not a CIDR: %w", cidr, err))
		}
	}
	lbl := labels.GetCIDRLabel(prefix)
	return newCIDRSelectorFromRequirements(key, prefix, Requirements{NewExistRequirement(lbl)}, except)
}

func newCIDRSelectorFromLabel(key string, lbl labels.Label, except []api.CIDR) *CIDRSelector {
	return newCIDRSelectorFromRequirements(key, netip.Prefix{}, Requirements{NewExistRequirement(lbl)}, except)
}

func newCIDRRuleSelector(rule api.CIDRRule) (ps *CIDRSelector) {
	key := rule.KeyString()
	switch {
	case rule.CIDRGroupRef != "":
		lbl := api.LabelForCIDRGroupRef(string(rule.CIDRGroupRef))
		ps = newCIDRSelectorFromLabel(key, lbl, rule.ExceptCIDRs)
	case rule.CIDRGroupSelector.LabelSelector != nil:
		es := rule.CIDRGroupSelector
		requirements := LabelSelectorToRequirements(es.LabelSelector)
		except := rule.ExceptCIDRs
		ps = newCIDRSelectorFromRequirements(key, netip.Prefix{}, requirements, except)
	default: // rule.Cidr != ""
		ps = NewCIDRSelector(key, rule.Cidr, rule.ExceptCIDRs)
	}
	ps.generated = rule.Generated
	return ps
}

func (p *CIDRSelector) Key() string {
	return p.key
}

func (p *CIDRSelector) IsWildcard() bool {
	return false
}

func (p *CIDRSelector) SelectedNamespaces() []string {
	return nil
}

func (p *CIDRSelector) Matches(logger *slog.Logger, ls labels.LabelArray) bool {
	return MatchesRequirements(logger, p.requirements, ls)
}

func (p *CIDRSelector) GetFQDNSelector() (*api.FQDNSelector, bool) {
	return nil, false
}

// Includes prefixes referenced solely by "ExceptCIDRs" entries.
func (p *CIDRSelector) GetCIDRPrefixes() (prefixes []netip.Prefix) {
	for idx := range p.requirements {
		pfx := p.requirements[idx].GetKeyPrefix()
		if pfx != nil {
			prefixes = append(prefixes, *pfx)
		}
	}
	return prefixes
}

func (p *CIDRSelector) MetricsClass() string {
	return LabelValueSCWorld
}

type SelectorId uint64
type SelectorRevision uint64

func init() {
	part.RegisterKeyType[SelectorId](func(x SelectorId) []byte { return binary.BigEndian.AppendUint64(nil, uint64(x)) })
}

type SelectionsMap = part.Map[SelectorId, identity.NumericIdentitySlice]
type SelectorTxn = part.MapTxn[SelectorId, identity.NumericIdentitySlice]
type SelectorWriteTxn = part.MapTxn[SelectorId, identity.NumericIdentitySlice]

// SelectorReadTxn contains state needed to observe a coherent set of selectors
type SelectorReadTxn struct {
	Revision   SelectorRevision
	selections SelectionsMap
	open       bool
}

func GetSelectorReadTxn(selections SelectionsMap, rev SelectorRevision) SelectorReadTxn {
	return SelectorReadTxn{selections: selections, Revision: rev, open: true}
}

// used for testing only
func MockSelectorReadTxn() SelectorReadTxn {
	return SelectorReadTxn{Revision: 1, open: true}
}

func (s *SelectorReadTxn) Get(id SelectorId) identity.NumericIdentitySlice {
	v, _ := s.selections.Get(id)
	if len(v) == 0 {
		return nil
	}
	return v
}

func (s *SelectorReadTxn) Close() {
	s.selections = SelectionsMap{}
	s.open = false
}

func (s *SelectorReadTxn) After(rev SelectorRevision) bool {
	return s.Revision > rev
}

func (s *SelectorReadTxn) IsOpen() bool {
	return s.open
}

func (s *SelectorReadTxn) String() string {
	str := " (closed)"
	if s.IsOpen() {
		str = " (open)"
	}
	return strconv.FormatUint(uint64(s.Revision), 10) + str
}

// CachedSelector represents an identity selector owned by the selector cache
type CachedSelector interface {
	// GetSelections returns the cached set of numeric identities
	// selected by the CachedSelector.  The retuned slice must NOT
	// be modified, as it is shared among multiple users.
	GetSelections() identity.NumericIdentitySlice

	// GetSelections returns the cached set of numeric identities
	// selected by the CachedSelector.  The retuned slice must NOT
	// be modified, as it is shared among multiple users.
	GetSelectionsAt(SelectorReadTxn) identity.NumericIdentitySlice

	// GetMetadataLabels returns metadata labels for additional context
	// surrounding the selector. These are typically the labels associated with
	// Cilium rules.
	GetMetadataLabels() labels.LabelArray

	// Selects return 'true' if the CachedSelector selects the given
	// numeric identity. Always uses the latest revision of the selector cache.
	Selects(identity.NumericIdentity) bool

	// IsWildcard returns true if the endpoint selector selects
	// all endpoints.
	IsWildcard() bool

	// IsNone returns true if the selector never selects anything
	IsNone() bool

	// String returns the string representation of this selector.
	// Used as a map key.
	String() string
}

// CachedSelectorSlice is a slice of CachedSelectors that can be sorted.
type CachedSelectorSlice []CachedSelector

// MarshalJSON returns the CachedSelectors as JSON formatted buffer
func (s CachedSelectorSlice) MarshalJSON() ([]byte, error) {
	buffer := bytes.NewBufferString("[")
	for i, selector := range s {
		buf, err := json.Marshal(selector.String())
		if err != nil {
			return nil, err
		}

		buffer.Write(buf)
		if i < len(s)-1 {
			buffer.WriteString(",")
		}
	}
	buffer.WriteString("]")
	return buffer.Bytes(), nil
}

func (s CachedSelectorSlice) Len() int      { return len(s) }
func (s CachedSelectorSlice) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

func (s CachedSelectorSlice) Less(i, j int) bool {
	return strings.Compare(s[i].String(), s[j].String()) < 0
}

// SelectsAllEndpoints returns whether the CachedSelectorSlice selects all
// endpoints, which is true if the wildcard endpoint selector is present in the
// slice.
func (s CachedSelectorSlice) SelectsAllEndpoints() bool {
	for _, selector := range s {
		if selector.IsWildcard() {
			return true
		}
	}
	return false
}

// CachedSelectionUser inserts selectors into the cache and gets update
// callbacks whenever the set of selected numeric identities change for
// the CachedSelectors pushed by it.
// Callbacks are executed from a separate goroutine that does not take the
// selector cache lock, so the implemenations generally may call back to
// the selector cache.
type CachedSelectionUser interface {
	// The caller is responsible for making sure the same identity is not
	// present in both 'added' and 'deleted'.
	IdentitySelectionUpdated(logger *slog.Logger, selector CachedSelector, added, deleted []identity.NumericIdentity)

	// IdentitySelectionCommit tells the user that all IdentitySelectionUpdated calls relating
	// to a specific added or removed identity have been made.
	IdentitySelectionCommit(*slog.Logger, SelectorReadTxn)
}
