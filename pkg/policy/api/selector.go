// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"encoding/json"
	"fmt"
	"strings"

	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1/validation"
	"github.com/cilium/cilium/pkg/labels"
)

// EndpointSelector is a wrapper for k8s LabelSelector.
type EndpointSelector struct {
	*slim_metav1.LabelSelector `json:",inline"`

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

func (n EndpointSelector) SelectorKey() string {
	// Use pre-computed string when available
	if n.cachedLabelSelectorString != "" {
		return n.cachedLabelSelectorString
	}
	return n.LabelSelector.String()
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
// If the object is not sanitized, we return the serialized value of
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
		cachedLabelSelectorString: labelSelector.String(),
		sanitized:                 true,
	}
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
	n.cachedLabelSelectorString = n.LabelSelector.String()
}

// AddMatchExpression adds a match expression to label selector of the endpoint selector.
func (n *EndpointSelector) AddMatchExpression(key string, op slim_metav1.LabelSelectorOperator, values []string) {
	n.MatchExpressions = append(n.MatchExpressions, slim_metav1.LabelSelectorRequirement{
		Key:      key,
		Operator: op,
		Values:   values,
	})
	n.cachedLabelSelectorString = n.LabelSelector.String()
}

// IsWildcard returns true if the endpoint selector selects all endpoints.
func (n *EndpointSelector) IsWildcard() bool {
	return n.LabelSelector != nil &&
		len(n.LabelSelector.MatchLabels)+len(n.LabelSelector.MatchExpressions) == 0
}

// Sanitize returns an error if the EndpointSelector's LabelSelector is invalid.
// It also mutates all label selector keys into Cilium's internal representation.
// Check documentation of `EndpointSelector.sanitized` for more details.
func (n *EndpointSelector) Sanitize() error {
	return n.SanitizeWithKeyExtender(labels.DefaultKeyExtender)
}

func (n *EndpointSelector) SanitizeWithKeyExtender(extender labels.KeyExtender) error {
	es := n
	if !n.sanitized {
		sanitizedEndpointSelector := NewESFromK8sLabelSelectorWithExtender(extender, n.LabelSelector)
		es = &sanitizedEndpointSelector
	}

	errList := validation.ValidateLabelSelector(es.LabelSelector, validation.LabelSelectorValidationOptions{AllowInvalidLabelValueInSelector: false}, nil)
	if len(errList) > 0 {
		return fmt.Errorf("invalid label selector: %w", errList.ToAggregate())
	}

	if !n.sanitized {
		n.sanitized = true
		n.LabelSelector = es.LabelSelector
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
