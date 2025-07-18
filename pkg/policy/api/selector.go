// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"encoding/json"
	"fmt"
	"strings"

	k8sLbls "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1/validation"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
)

// EndpointSelector is a wrapper for k8s LabelSelector.
type EndpointSelector struct {
	*slim_metav1.LabelSelector `json:",inline"`

	// requirements provides a cache for a k8s-friendly format of the
	// LabelSelector, which allows more efficient matching in Matches().
	//
	// Kept as a pointer to allow EndpointSelector to be used as a map key.
	requirements *k8sLbls.Requirements `json:"-"`

	// cachedLabelSelectorString is the cached representation of the
	// LabelSelector for this EndpointSelector. It is populated when
	// EndpointSelectors are created via `NewESFromMatchRequirements`. It is
	// immutable after its creation.
	cachedLabelSelectorString string `json:"-"`

	// Generated indicates whether the rule was generated based on other rules
	// or provided by user
	Generated bool `json:"-"`

	// sanitized indicates if the EndpointSelector has been validated and converted
	// to Cilium's internal representation for usage. Internally Cilium uses k8s label
	// APIs which doesn't allow for `:` in label keys. When sanitizing we convert
	// keys to the format expected by k8s with prefix `<source>.`
	//
	// Cilium's Label key conversion logic as part of sanitization is:
	// 1. `<prefix>:<string>` -> `<prefix>.<string>` (Source: <prefix>)
	// 2. `<prefix>.<string>` -> `any.<prefix>.<string>` (Source: any)
	// 3. `<string>` -> `any.<string>` (Source: any)
	sanitized bool `json:"-"`
}

// Used for `omitzero` json tag.
func (n *EndpointSelector) IsZero() bool {
	return n.LabelSelector == nil
}

// LabelSelectorString returns a user-friendly string representation of
// EndpointSelector.
func (n *EndpointSelector) LabelSelectorString() string {
	if n != nil && n.LabelSelector == nil {
		return "<all>"
	}
	return slim_metav1.FormatLabelSelector(n.LabelSelector)
}

// String returns a string representation of EndpointSelector.
func (n EndpointSelector) String() string {
	j, _ := n.MarshalJSON()
	return string(j)
}

// CachedString returns the cached string representation of the LabelSelector
// for this EndpointSelector.
func (n EndpointSelector) CachedString() string {
	return n.cachedLabelSelectorString
}

// UnmarshalJSON unmarshals the endpoint selector from the byte array.
func (n *EndpointSelector) UnmarshalJSON(b []byte) error {
	n.LabelSelector = &slim_metav1.LabelSelector{}
	return json.Unmarshal(b, n.LabelSelector)
}

// MarshalJSON returns a JSON representation of the byte array.
// If the object is not sanitized, we return the seralized value of
// underlying selector without the custom handling.
// When sanitized, we convert the label keys to Cilium specific representation
// with source prefix in format `<source>:<key>` before serialization.
func (n EndpointSelector) MarshalJSON() ([]byte, error) {
	ls := slim_metav1.LabelSelector{}
	if n.LabelSelector == nil {
		return json.Marshal(ls)
	}

	if !n.sanitized {
		return json.Marshal(n.LabelSelector)
	}

	if n.MatchLabels != nil {
		newLabels := map[string]string{}
		for k, v := range n.MatchLabels {
			newLabels[labels.GetCiliumKeyFrom(k)] = v
		}
		ls.MatchLabels = newLabels
	}
	if n.MatchExpressions != nil {
		newMatchExpr := make([]slim_metav1.LabelSelectorRequirement, len(n.MatchExpressions))
		for i, v := range n.MatchExpressions {
			v.Key = labels.GetCiliumKeyFrom(v.Key)
			newMatchExpr[i] = v
		}
		ls.MatchExpressions = newMatchExpr
	}
	return json.Marshal(ls)
}

// HasKeyPrefix checks if the endpoint selector contains the given key prefix in
// its MatchLabels map and MatchExpressions slice.
func (n EndpointSelector) HasKeyPrefix(prefix string) bool {
	for k := range n.MatchLabels {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	for _, v := range n.MatchExpressions {
		if strings.HasPrefix(v.Key, prefix) {
			return true
		}
	}
	return false
}

// HasKey checks if the endpoint selector contains the given key in
// its MatchLabels map or in its MatchExpressions slice.
func (n EndpointSelector) HasKey(key string) bool {
	if _, ok := n.MatchLabels[key]; ok {
		return true
	}
	for _, v := range n.MatchExpressions {
		if v.Key == key {
			return true
		}
	}
	return false
}

// GetMatch checks for a match on the specified key, and returns the value that
// the key must match, and true. If a match cannot be found, returns nil, false.
func (n EndpointSelector) GetMatch(key string) ([]string, bool) {
	if value, ok := n.MatchLabels[key]; ok {
		return []string{value}, true
	}
	for _, v := range n.MatchExpressions {
		if v.Key == key && v.Operator == slim_metav1.LabelSelectorOpIn {
			return v.Values, true
		}
	}
	return nil, false
}

// labelSelectorToRequirements turns a kubernetes Selector into a slice of
// requirements equivalent to the selector. These are cached internally in the
// EndpointSelector to speed up Matches().
//
// This validates the labels, which can be expensive (and may fail..)
// If there's an error, the selector will be nil and the Matches()
// implementation will refuse to match any labels.
func labelSelectorToRequirements(labelSelector *slim_metav1.LabelSelector) *k8sLbls.Requirements {
	selector, err := slim_metav1.LabelSelectorAsSelector(labelSelector)
	if err != nil {
		metrics.PolicyChangeTotal.WithLabelValues(metrics.LabelValueOutcomeFail).Inc()
		// slogloggercheck: it's safe to use the default logger here as it has been initialized by the program up to this point.
		logging.DefaultSlogLogger.Error(
			"unable to construct selector in label selector",
			logfields.LogSubsys, "policy-api",
			logfields.Error, err,
			logfields.EndpointLabelSelector, labelSelector,
		)
		return nil
	}
	metrics.PolicyChangeTotal.WithLabelValues(metrics.LabelValueOutcomeSuccess).Inc()

	requirements, selectable := selector.Requirements()
	if !selectable {
		return nil
	}
	return &requirements
}

// NewESFromLabels creates a new endpoint selector from the given labels.
func NewESFromLabels(lbls ...labels.Label) EndpointSelector {
	ml := map[string]string{}
	for _, lbl := range lbls {
		ml[lbl.GetExtendedKey()] = lbl.Value
	}

	return NewESFromMatchRequirements(ml, nil)
}

// NewESFromMatchRequirements creates a new endpoint selector from the given
// match specifications: An optional set of labels that must match, and
// an optional slice of LabelSelectorRequirements.
// The returned selector object is marked as sanitized, the caller is responsible
// for ensuring that the Label keys are prefixed correctly with the required source.
//
// If the caller intends to reuse 'matchLabels' or 'reqs' after creating the
// EndpointSelector, they must make a copy of the parameter.
func NewESFromMatchRequirements(matchLabels map[string]string, reqs []slim_metav1.LabelSelectorRequirement) EndpointSelector {
	labelSelector := &slim_metav1.LabelSelector{
		MatchLabels:      matchLabels,
		MatchExpressions: reqs,
	}
	return EndpointSelector{
		LabelSelector:             labelSelector,
		requirements:              labelSelectorToRequirements(labelSelector),
		cachedLabelSelectorString: labelSelector.String(),
		sanitized:                 true,
	}
}

// SyncRequirementsWithLabelSelector ensures that the requirements within the
// specified EndpointSelector are in sync with the LabelSelector. This is
// because the LabelSelector has publicly accessible fields, which can be
// updated without concurrently updating the requirements, so the two fields can
// become out of sync.
func (n *EndpointSelector) SyncRequirementsWithLabelSelector() {
	n.requirements = labelSelectorToRequirements(n.LabelSelector)
}

// newReservedEndpointSelector returns a selector that matches on all
// endpoints with the specified reserved label.
func newReservedEndpointSelector(ID string) EndpointSelector {
	reservedLabels := labels.NewLabel(ID, "", labels.LabelSourceReserved)
	return NewESFromLabels(reservedLabels)
}

var (
	// WildcardEndpointSelector is a wildcard endpoint selector matching
	// all endpoints that can be described with labels.
	WildcardEndpointSelector = NewESFromLabels()

	// ReservedEndpointSelectors map reserved labels to EndpointSelectors
	// that will match those endpoints.
	ReservedEndpointSelectors = map[string]EndpointSelector{
		labels.IDNameHost:       newReservedEndpointSelector(labels.IDNameHost),
		labels.IDNameRemoteNode: newReservedEndpointSelector(labels.IDNameRemoteNode),
		labels.IDNameWorld:      newReservedEndpointSelector(labels.IDNameWorld),
		labels.IDNameWorldIPv4:  newReservedEndpointSelector(labels.IDNameWorldIPv4),
		labels.IDNameWorldIPv6:  newReservedEndpointSelector(labels.IDNameWorldIPv6),
	}
)

func NewESFromK8sLabelSelectorWithExtender(extender labels.KeyExtender, lss ...*slim_metav1.LabelSelector) EndpointSelector {
	var (
		matchLabels      map[string]string
		matchExpressions []slim_metav1.LabelSelectorRequirement
	)
	for _, ls := range lss {
		if ls == nil {
			continue
		}
		if ls.MatchLabels != nil {
			if matchLabels == nil {
				matchLabels = map[string]string{}
			}
			for k, v := range ls.MatchLabels {
				matchLabels[extender(k)] = v
			}
		}
		if ls.MatchExpressions != nil {
			if matchExpressions == nil {
				matchExpressions = make([]slim_metav1.LabelSelectorRequirement, 0, len(ls.MatchExpressions))
			}
			for _, v := range ls.MatchExpressions {
				v.Key = extender(v.Key)
				matchExpressions = append(matchExpressions, v)
			}
		}
	}
	return NewESFromMatchRequirements(matchLabels, matchExpressions)
}

// NewESFromK8sLabelSelector returns a new endpoint selector from the label
// where it the given srcPrefix will be encoded in the label's keys.
func NewESFromK8sLabelSelector(srcPrefix string, lss ...*slim_metav1.LabelSelector) EndpointSelector {
	return NewESFromK8sLabelSelectorWithExtender(labels.GetSourcePrefixKeyExtender(srcPrefix), lss...)
}

// AddMatch adds a match for 'key' == 'value' to the endpoint selector.
func (n *EndpointSelector) AddMatch(key, value string) {
	if n.MatchLabels == nil {
		n.MatchLabels = map[string]string{}
	}
	n.MatchLabels[key] = value
	n.requirements = labelSelectorToRequirements(n.LabelSelector)
	n.cachedLabelSelectorString = n.LabelSelector.String()
}

// AddMatchExpression adds a match expression to label selector of the endpoint selector.
func (n *EndpointSelector) AddMatchExpression(key string, op slim_metav1.LabelSelectorOperator, values []string) {
	n.MatchExpressions = append(n.MatchExpressions, slim_metav1.LabelSelectorRequirement{
		Key:      key,
		Operator: op,
		Values:   values,
	})

	// Update cache of the EndopintSelector from the embedded label selector.
	// This is to make sure we have updates caches containing the required selectors.
	n.requirements = labelSelectorToRequirements(n.LabelSelector)
	n.cachedLabelSelectorString = n.LabelSelector.String()
}

// Matches returns true if the endpoint selector Matches the `lblsToMatch`.
// Returns always true if the endpoint selector contains the reserved label for
// "all".
func (n *EndpointSelector) Matches(lblsToMatch k8sLbls.Labels) bool {
	// Try to update cached requirements for this EndpointSelector if possible.
	if n.requirements == nil {
		n.requirements = labelSelectorToRequirements(n.LabelSelector)
		// Nil indicates that requirements failed validation in some way,
		// so we cannot parse the labels for matching purposes; thus, we cannot
		// match if labels cannot be parsed, so return false.
		if n.requirements == nil {
			return false
		}
	}
	reqs := *n.requirements
	for i := range reqs {
		if !reqs[i].Matches(lblsToMatch) {
			return false
		}
	}
	return true
}

// IsWildcard returns true if the endpoint selector selects all endpoints.
func (n *EndpointSelector) IsWildcard() bool {
	return n.LabelSelector != nil &&
		len(n.LabelSelector.MatchLabels)+len(n.LabelSelector.MatchExpressions) == 0
}

// ConvertToLabelSelectorRequirementSlice converts the MatchLabels and
// MatchExpressions within the specified EndpointSelector into a list of
// LabelSelectorRequirements.
func (n *EndpointSelector) ConvertToLabelSelectorRequirementSlice() []slim_metav1.LabelSelectorRequirement {
	requirements := make([]slim_metav1.LabelSelectorRequirement, 0, len(n.MatchExpressions)+len(n.MatchLabels))
	// Append already existing match expressions.
	requirements = append(requirements, n.MatchExpressions...)
	// Convert each MatchLables to LabelSelectorRequirement.
	for key, value := range n.MatchLabels {
		requirementFromMatchLabels := slim_metav1.LabelSelectorRequirement{
			Key:      key,
			Operator: slim_metav1.LabelSelectorOpIn,
			Values:   []string{value},
		}
		requirements = append(requirements, requirementFromMatchLabels)
	}
	return requirements
}

// Sanitize returns an error if the EndpointSelector's LabelSelector is invalid.
// It also muatates all label selector keys into Cilium's internal representation.
// Check documentation of `EndpointSelector.sanitized` for more details.
func (n *EndpointSelector) Sanitize() error {
	es := n
	if !n.sanitized {
		sanitizedEndpointSelector := NewESFromK8sLabelSelectorWithExtender(labels.DefaultKeyExtender, n.LabelSelector)
		es = &sanitizedEndpointSelector
	}

	errList := validation.ValidateLabelSelector(es.LabelSelector, validation.LabelSelectorValidationOptions{AllowInvalidLabelValueInSelector: false}, nil)
	if len(errList) > 0 {
		return fmt.Errorf("invalid label selector: %w", errList.ToAggregate())
	}

	if !n.sanitized {
		n.sanitized = true
		n.LabelSelector = es.LabelSelector
		n.requirements = es.requirements
		n.cachedLabelSelectorString = es.cachedLabelSelectorString
	}

	return nil
}

// EndpointSelectorSlice is a slice of EndpointSelectors that can be sorted.
type EndpointSelectorSlice []EndpointSelector

func (s EndpointSelectorSlice) Len() int      { return len(s) }
func (s EndpointSelectorSlice) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

func (s EndpointSelectorSlice) Less(i, j int) bool {
	strI := s[i].LabelSelectorString()
	strJ := s[j].LabelSelectorString()

	return strings.Compare(strI, strJ) < 0
}

// Matches returns true if any of the EndpointSelectors in the slice match the
// provided labels
func (s EndpointSelectorSlice) Matches(ctx labels.LabelArray) bool {
	for _, selector := range s {
		if selector.Matches(ctx) {
			return true
		}
	}

	return false
}

// SelectsAllEndpoints returns whether the EndpointSelectorSlice selects all
// endpoints, which is true if the wildcard endpoint selector is present in the
// slice.
func (s EndpointSelectorSlice) SelectsAllEndpoints() bool {
	for _, selector := range s {
		if selector.IsWildcard() {
			return true
		}
	}
	return false
}
