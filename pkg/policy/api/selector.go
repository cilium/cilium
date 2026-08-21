// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"encoding/json"
	"fmt"
	"strings"

	ciliumcel "github.com/cilium/cilium/pkg/cel"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
)

// CELExpression is a CEL (Common Expression Language) boolean expression string.
// An empty CELExpression is considered as no-op requirement.
type CELExpression string

// IsZero reports whether the CEL expression is empty.
func (c CELExpression) IsZero() bool { return len(c) == 0 }

// SelectorKey returns the internal representation of the CEL expression.
func (c CELExpression) SelectorKey() string {
	return fmt.Sprintf("CEL{%s}", c)
}

// EndpointSelector is a wrapper for k8s LabelSelector.
type EndpointSelector struct {
	*slim_metav1.LabelSelector `json:",inline"`

	// MatchCELExpression is an optional, serialized, boolean CEL expression
	// that provides additional label match conditions for this selector.
	// When set, an endpoint must satisfy this expression **AND** the
	// k8s LabelSelector constraints.
	// The environment for CEL expression provides a 'label(<key>)' macro
	// to lookup value of key(with source prefix) against the Label being
	// evaluated for selection.
	// The return type of this macro is the label value wrapped in an optional type:
	// https://pkg.go.dev/github.com/google/cel-go/cel#OptionalTypes
	//
	// Example Usage:
	//
	// * Check if a key exist in the input Labels:
	// 		* label("k8s:app").hasValue()
	// 		* label("any:missing") == optional.none()
	// * Get value of a known existing key:
	// 		* label("k8s:app").value()
	// 		* Note: Unwrapping a non existing key through `value()` will cause evaluation error.
	// * Get value of an unknown key:
	// 		* label("k8s:app").orValue("")
	// * Compare value of an unknown key:
	// 		* label("k8s:app") == optional.of("myapp")
	// * Set membership for a label value:
	// 		* label("k8s:env").value() in ["prod", "staging", "dev"]
	// * Common string operations on label values:
	// 		* label("k8s:env").orValue("").startsWith("prod")
	// 		* label("k8s:env").orValue("").endsWith("-us-east")
	// 		* label("k8s:env").orValue("").contains("db-staging")
	// * Boolean composition:
	// 		* label("k8s:env").value() == "dev" || label("k8s:env").value() == "staging"
	// 		* label("k8s:env") == optional.of("prod") && label("k8s:app") == optional.of("myapp")
	// 		* label("k8s:env") != optional.of("prod")
	// * Iterators:
	// 		* ["k8s:app", "k8s:env"].all(k, label(k).hasValue())
	// 		* ["k8s:app", "k8s:env"].map(k, label(k).orValue("")) == ["myapp", "prod"]
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxLength=4096
	MatchCELExpression CELExpression `json:"matchCELExpression,omitzero"`

	// cachedSelectorKey is the cached representation of this EndpointSelector.
	cachedSelectorKey string `json:"-"`

	// Generated indicates whether the rule was generated based on other rules
	// or provided by user
	Generated bool `json:"-"`
}

func (n EndpointSelector) buildSelectorKey() string {
	if n.MatchCELExpression.IsZero() {
		return n.LabelSelector.String()
	}
	return fmt.Sprintf("%s && %s", n.LabelSelector.String(), n.MatchCELExpression.SelectorKey())
}

func (n EndpointSelector) SelectorKey() string {
	// Use pre-computed string when available
	if n.cachedSelectorKey != "" {
		return n.cachedSelectorKey
	}
	return n.buildSelectorKey()
}

// Used for `omitzero` json tag.
func (n *EndpointSelector) IsZero() bool {
	return n.LabelSelector == nil && n.MatchCELExpression.IsZero()
}

// String returns a string representation of EndpointSelector.
func (n EndpointSelector) String() string {
	j, _ := json.Marshal(n)
	return string(j)
}

// CachedString returns the cached string representation of the LabelSelector
// for this EndpointSelector.
func (n EndpointSelector) CachedString() string {
	return n.cachedSelectorKey
}

// UnmarshalJSON unmarshals the endpoint selector from the byte array.
func (n *EndpointSelector) UnmarshalJSON(b []byte) error {
	// Always initialize LabelSelector to distinguish an empty selector
	// (matches all endpoints) from an absent selector, matching historical
	// behavior relied on by policyapi.Rule field disambiguation.
	n.LabelSelector = &slim_metav1.LabelSelector{}
	// Use a type alias to invoke standard JSON unmarshaling without triggering
	// this method recursively. The embedded *LabelSelector fields are inlined
	// at the JSON level (json:",inline"), and MatchCELExpression carries its
	// own tag, so the standard decoder handles everything correctly.
	type plain EndpointSelector
	return json.Unmarshal(b, (*plain)(n))
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
//
// If the caller intends to reuse 'matchLabels' or 'reqs' after creating the
// EndpointSelector, they must make a copy of the parameter.
func NewESFromMatchRequirements(matchLabels map[string]string, reqs []slim_metav1.LabelSelectorRequirement) EndpointSelector {
	es := EndpointSelector{
		LabelSelector: &slim_metav1.LabelSelector{
			MatchLabels:      matchLabels,
			MatchExpressions: reqs,
		},
	}
	es.cachedSelectorKey = es.SelectorKey()
	return es
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

// NewEndpointSelector returns a new endpoint selector from the provided selector.
func NewEndpointSelector(srcPrefix string, src *EndpointSelector) EndpointSelector {
	es := NewESFromK8sLabelSelector(srcPrefix, src.LabelSelector)
	es.MatchCELExpression = src.MatchCELExpression
	es.cachedSelectorKey = es.buildSelectorKey()
	return es
}

// NewESFromK8sLabelSelector returns a new endpoint selector from the label
// where it the given srcPrefix will be encoded in the label's keys.
func NewESFromK8sLabelSelector(srcPrefix string, lss ...*slim_metav1.LabelSelector) EndpointSelector {
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
				matchLabels[labels.NewSourceEncodedLabelKey(srcPrefix, k)] = v
			}
		}
		if ls.MatchExpressions != nil {
			if matchExpressions == nil {
				matchExpressions = make([]slim_metav1.LabelSelectorRequirement, 0, len(ls.MatchExpressions))
			}
			for _, v := range ls.MatchExpressions {
				v.Key = labels.NewSourceEncodedLabelKey(srcPrefix, v.Key)
				matchExpressions = append(matchExpressions, v)
			}
		}
	}
	return NewESFromMatchRequirements(matchLabels, matchExpressions)
}

// AddMatch adds a match for 'key' == 'value' to the endpoint selector.
func (n *EndpointSelector) AddMatch(key, value string) {
	if n.MatchLabels == nil {
		n.MatchLabels = map[string]string{}
	}
	n.MatchLabels[key] = value
	n.cachedSelectorKey = n.buildSelectorKey()
}

// AddMatchExpression adds a match expression to label selector of the endpoint selector.
func (n *EndpointSelector) AddMatchExpression(key string, op slim_metav1.LabelSelectorOperator, values []string) {
	n.MatchExpressions = append(n.MatchExpressions, slim_metav1.LabelSelectorRequirement{
		Key:      key,
		Operator: op,
		Values:   values,
	})
	n.cachedSelectorKey = n.buildSelectorKey()
}

// IsWildcard returns true if the endpoint selector selects all endpoints.
func (n *EndpointSelector) IsWildcard() bool {
	return n.LabelSelector != nil &&
		len(n.LabelSelector.MatchLabels)+len(n.LabelSelector.MatchExpressions) == 0 &&
		n.MatchCELExpression.IsZero()
}

func (n *EndpointSelector) Sanitize() error {
	errList := labels.ValidateLabelSelector(n.LabelSelector, labels.LabelSelectorValidationOptions{AllowInvalidLabelValueInSelector: false}, nil)
	if len(errList) > 0 {
		return fmt.Errorf("invalid label selector: %w", errList.ToAggregate())
	}

	if !n.MatchCELExpression.IsZero() {
		res := ciliumcel.Env.Compile(ciliumcel.EnvTypeLabelSelector, string(n.MatchCELExpression))
		if res.Error != nil {
			return fmt.Errorf("failed to compile CEL expression: %w", res.Error)
		}
	}

	es := NewESFromK8sLabelSelector(labels.LabelSourceAnyKeyPrefix, n.LabelSelector)
	n.LabelSelector = es.LabelSelector
	n.cachedSelectorKey = n.buildSelectorKey()

	return nil
}

// EndpointSelectorSlice is a slice of EndpointSelectors that can be sorted.
type EndpointSelectorSlice []EndpointSelector

func (s EndpointSelectorSlice) Len() int      { return len(s) }
func (s EndpointSelectorSlice) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

func (s EndpointSelectorSlice) Less(i, j int) bool {
	strI := s[i].SelectorKey()
	strJ := s[j].SelectorKey()

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
