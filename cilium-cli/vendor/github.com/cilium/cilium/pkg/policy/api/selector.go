// Copyright 2016-2020 Authors of Cilium
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

package api

import (
	"encoding/json"
	"fmt"
	"strings"

	k8sLbls "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	validation "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1/validation"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "policy-api")

// EndpointSelector is a wrapper for k8s LabelSelector.
type EndpointSelector struct {
	*slim_metav1.LabelSelector `json:",inline"`

	// TODO: The following fields were exported to stop govet warnings. The
	// govet warnings were because the CRD generation tool needs every struct
	// field that's within a CRD, to have a json tag. JSON tags cannot be
	// applied to unexported fields, hence this change. Refactor these fields
	// out of this struct. GH issue:
	// https://github.com/cilium/cilium/issues/12697. Once
	// https://go-review.googlesource.com/c/tools/+/245857 is merged, this
	// would no longer be required.

	// Requirements provides a cache for a k8s-friendly format of the
	// LabelSelector, which allows more efficient matching in Matches().
	//
	// Kept as a pointer to allow EndpointSelector to be used as a map key.
	Requirements *k8sLbls.Requirements `json:"-"`

	// CachedLabelSelectorString is the cached representation of the
	// LabelSelector for this EndpointSelector. It is populated when
	// EndpointSelectors are created via `NewESFromMatchRequirements`. It is
	// immutable after its creation.
	CachedLabelSelectorString string `json:"-"`
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
	return n.CachedLabelSelectorString
}

// UnmarshalJSON unmarshals the endpoint selector from the byte array.
func (n *EndpointSelector) UnmarshalJSON(b []byte) error {
	n.LabelSelector = &slim_metav1.LabelSelector{}
	err := json.Unmarshal(b, n.LabelSelector)
	if err != nil {
		return err
	}
	if n.MatchLabels != nil {
		ml := map[string]string{}
		for k, v := range n.MatchLabels {
			ml[labels.GetExtendedKeyFrom(k)] = v
		}
		n.MatchLabels = ml
	}
	if n.MatchExpressions != nil {
		newMatchExpr := make([]slim_metav1.LabelSelectorRequirement, len(n.MatchExpressions))
		for i, v := range n.MatchExpressions {
			v.Key = labels.GetExtendedKeyFrom(v.Key)
			newMatchExpr[i] = v
		}
		n.MatchExpressions = newMatchExpr
	}
	n.Requirements = labelSelectorToRequirements(n.LabelSelector)
	n.CachedLabelSelectorString = n.LabelSelector.String()
	return nil
}

// MarshalJSON returns a JSON representation of the byte array.
func (n EndpointSelector) MarshalJSON() ([]byte, error) {
	ls := slim_metav1.LabelSelector{}

	if n.LabelSelector == nil {
		return json.Marshal(ls)
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
		metrics.PolicyImportErrors.Inc()
		metrics.PolicyImportErrorsTotal.Inc()
		log.WithError(err).WithField(logfields.EndpointLabelSelector,
			logfields.Repr(labelSelector)).Error("unable to construct selector in label selector")
		return nil
	}

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
		Requirements:              labelSelectorToRequirements(labelSelector),
		CachedLabelSelectorString: labelSelector.String(),
	}
}

// SyncRequirementsWithLabelSelector ensures that the requirements within the
// specified EndpointSelector are in sync with the LabelSelector. This is
// because the LabelSelector has publicly accessible fields, which can be
// updated without concurrently updating the requirements, so the two fields can
// become out of sync.
func (n *EndpointSelector) SyncRequirementsWithLabelSelector() {
	n.Requirements = labelSelectorToRequirements(n.LabelSelector)
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
	}
)

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
				matchLabels[srcPrefix+k] = v
			}
		}
		if ls.MatchExpressions != nil {
			if matchExpressions == nil {
				matchExpressions = make([]slim_metav1.LabelSelectorRequirement, 0, len(ls.MatchExpressions))
			}
			for _, v := range ls.MatchExpressions {
				v.Key = srcPrefix + v.Key
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
	n.Requirements = labelSelectorToRequirements(n.LabelSelector)
	n.CachedLabelSelectorString = n.LabelSelector.String()
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
	n.Requirements = labelSelectorToRequirements(n.LabelSelector)
	n.CachedLabelSelectorString = n.LabelSelector.String()
}

// Matches returns true if the endpoint selector Matches the `lblsToMatch`.
// Returns always true if the endpoint selector contains the reserved label for
// "all".
func (n *EndpointSelector) Matches(lblsToMatch k8sLbls.Labels) bool {
	// Try to update cached requirements for this EndpointSelector if possible.
	if n.Requirements == nil {
		n.Requirements = labelSelectorToRequirements(n.LabelSelector)
		// Nil indicates that requirements failed validation in some way,
		// so we cannot parse the labels for matching purposes; thus, we cannot
		// match if labels cannot be parsed, so return false.
		if n.Requirements == nil {
			return false
		}
	}
	for _, req := range *n.Requirements {
		if !req.Matches(lblsToMatch) {
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

// sanitize returns an error if the EndpointSelector's LabelSelector is invalid.
func (n *EndpointSelector) sanitize() error {
	errList := validation.ValidateLabelSelector(n.LabelSelector, nil)
	if len(errList) > 0 {
		return fmt.Errorf("invalid label selector: %s", errList.ToAggregate().Error())
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
