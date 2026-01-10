// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"iter"
	"net/netip"
	"strconv"
	"strings"

	"github.com/cilium/cilium/pkg/container/set"
	k8sLbls "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/selection"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
)

// Version of k8sLbls.Requirement where the key is pre-parsed and values are stored as a Set optimal
// for single-valued values.
// +deepequal-gen=true
type Requirement struct {
	key      labels.Label       // pre-parsed Label
	operator selection.Operator // requirement operator
	values   set.Set[string]    // usually only one value
}

func (r Requirement) WriteString(sb *strings.Builder) {
	sb.WriteString(r.key.String())

	sb.WriteRune('<')
	sb.WriteString(string(r.operator))
	sb.WriteRune('>')

	sb.WriteRune('[')
	i := 0
	for v := range r.values.Members() {
		if i > 0 {
			sb.WriteRune(',')
		}
		sb.WriteString(v)
		i++
	}
	sb.WriteRune(']')
}

// Requirements is AND of all requirements.
type Requirements []Requirement

func (rs Requirements) WriteString(sb *strings.Builder) {
	sb.WriteRune('[')
	for i, req := range rs {
		if i > 0 {
			sb.WriteRune(',')
		}
		req.WriteString(sb)
	}
	sb.WriteRune(']')
}

// LabelSelectorToRequirements turns a kubernetes Selector into a slice of
// requirements equivalent to the selector. These are cached internally in the
// EndpointSelector to speed up Matches().
//
// This validates the labels, which can be expensive (and may fail..)
// If there's an error, the selector will be nil and the Matches()
// implementation will refuse to match any labels.
func LabelSelectorToRequirements(labelSelector *slim_metav1.LabelSelector) Requirements {
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

	k8sReqs, selectable := selector.Requirements()
	if !selectable {
		return nil
	}
	return RequirementsFromK8s(k8sReqs)
}

func NewExistRequirement(lbl labels.Label) Requirement {
	return Requirement{
		key:      lbl,
		operator: selection.Exists,
	}
}

func NewExistRequirements(lbls labels.LabelArray) (reqs Requirements) {
	for _, lbl := range lbls {
		reqs = append(reqs, NewExistRequirement(lbl))
	}
	return reqs
}

func NewExceptRequirement(lbl labels.Label) Requirement {
	return Requirement{
		key:      lbl,
		operator: selection.DoesNotExist,
	}
}

func NewEqualsRequirement(lbl labels.Label) Requirement {
	return Requirement{
		key:      labels.Label{Key: lbl.Key, Source: lbl.Source},
		operator: selection.Equals,
		values:   set.NewSet(lbl.Value),
	}
}

func NewRequirement(key string, op selection.Operator, values []string) Requirement {
	return Requirement{
		key:      labels.ParseSelectDotLabel(key),
		operator: op,
		values:   set.NewSet(values...),
	}
}

func (r *Requirement) GetKeyPrefix() *netip.Prefix {
	return r.key.GetCIDRPrefix()
}

func (r *Requirement) HasKeySource(source string) bool {
	return r.key.Source == source
}

func (r *Requirement) HasValue(value string) bool {
	return r.values.Has(value)
}

func RequirementsFromK8s(k8sReqs k8sLbls.Requirements) Requirements {
	reqs := make(Requirements, 0, len(k8sReqs))
	for _, req := range k8sReqs {
		reqs = append(reqs, Requirement{
			key:      labels.ParseSelectDotLabel(req.Key()),
			operator: req.Operator(),
			values:   set.NewSet[string](req.ShallowValues()...),
		})
	}
	return reqs
}

// Matches returns true if the Requirement matches the input Labels.
// This is structurally the same as k8sLbls.Requirement.Matches(),
// but takes LabelArray as an argument instead of a string.
//
// MatchesRequirement is defined as a generic function on labels.LabelMatcher rather than taking
// the interface as the parameter due to the interface parameter causing Go compiler (1.25.2) to
// escape labels.LabelArray implementing the interface to the heap, causing large memory
// overhead. When the compiler specializes the generic type to a concrete type (not an interface),
// it can perform correct escape analysis and avoid unnecessary heap allocations.
func MatchesRequirement[T labels.LabelMatcher](r *Requirement, ls T) bool {
	val, exists := ls.LookupLabel(&r.key)
	switch r.operator {
	case selection.In, selection.Equals, selection.DoubleEquals:
		return exists && r.HasValue(val)
	case selection.NotIn, selection.NotEquals:
		return !exists || !r.HasValue(val)
	case selection.Exists:
		return exists
	case selection.DoesNotExist:
		return !exists
	case selection.GreaterThan, selection.LessThan:
		if !exists {
			return false
		}
		lsValue, err := strconv.ParseInt(val, 10, 64)
		if err != nil {
			// 'r.key' has been validated, so an error here would be a regression in
			// validation.
			// slogloggercheck: Using Error as a "soft panic" to fail Cilium CI
			logging.DefaultSlogLogger.Error(
				"ParseInt failed",
				logfields.Error, err,
				logfields.EndpointLabelSelector, ls,
				logfields.Value, val,
			)
			return false
		}

		// There should be only one string value in r.values, and can be converted to an
		// integer.
		if r.values.Len() != 1 {
			// 'r.values' has been validated, so an error here would be a regression in
			// validation.
			// slogloggercheck: Using Error as a "soft panic" to fail Cilium CI
			logging.DefaultSlogLogger.Error(
				"Invalid values count for 'Gt', 'Lt' operators, exactly one value is required",
				logfields.Label, r.key,
				logfields.Value, r.values,
				logfields.LenEntries, r.values.Len())
			return false
		}

		var rValue int64
		for val := range r.values.Members() {
			rValue, err = strconv.ParseInt(val, 10, 64)
			if err != nil {
				// 'val' has been validated, so an error here would be a regression
				// in validation.
				// slogloggercheck: Using Error as a "soft panic" to fail Cilium CI
				logging.DefaultSlogLogger.Error(
					"ParseInt failed, for 'Gt', 'Lt' operators, the value must be an integer",
					logfields.Error, err,
					logfields.Label, r.key,
					logfields.Value, val,
				)
				return false
			}
		}
		return (r.operator == selection.GreaterThan && lsValue > rValue) || (r.operator == selection.LessThan && lsValue < rValue)
	}
	return false
}

// MatchesRequirements is defined as a generic function on labels.LabelMatcher rather than taking
// the interface as the parameter due to the interface parameter causing Go compiler (1.25.2) to
// escape labels.LabelArray implementing the interface to the heap, causing large memory
// overhead. When the compiler specializes the generic type to a concrete type (not an interface),
// it can perform correct escape analysis and avoid unnecessary heap allocations.
func MatchesRequirements[T labels.LabelMatcher](reqs Requirements, ls T) bool {
	for i := range reqs {
		if !MatchesRequirement(&reqs[i], ls) {
			return false
		}
	}
	return true
}

// GetFirstK8sMatch checks for a match on the specified k8s key, and returns the values that the key
// must match, and true. If a match cannot be found, or is with operator other than "In", "Equals",
// or "DoubleEquals", returns nil, false.  Note: The values of first requirement with the given k8s
// key are returned. If there are multiple requirements with the same key, technically we should
// return the intersection of all them. The caller must perform a full match operation to prune out
// values not in such intersection.
func (reqs Requirements) GetFirstK8sMatch(key string) ([]string, bool) {
	for _, r := range reqs {
		if r.key.Source == labels.LabelSourceK8s && r.key.Key == key {
			switch r.operator {
			case selection.In, selection.Equals, selection.DoubleEquals:
				return r.values.AsSlice(), true
			default:
				// any other operator on the key may negate match
				break
			}
		}
	}
	return nil, false
}

func (reqs Requirements) KeyOnlyRequirements() iter.Seq2[labels.Label, bool] {
	return func(yield func(labels.Label, bool) bool) {
		for _, req := range reqs {
			if req.values.Empty() && req.operator == selection.Exists || req.operator == selection.DoesNotExist {
				if !yield(req.key, req.operator == selection.Exists) {
					break
				}
			}
		}
	}
}
