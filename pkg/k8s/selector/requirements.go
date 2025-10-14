// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package selector

import (
	"log/slog"
	"strconv"

	"github.com/cilium/cilium/pkg/container/set"
	k8sLbls "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/selection"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// Version of k8sLbls.Requirement where the key is pre-parsed and values are stored as a Set optimal
// for single-valued values.
type Requirement struct {
	key      labels.Label       // pre-parsed Label
	operator selection.Operator // requirement operator
	values   set.Set[string]    // usually only one value
}

// Requirements is AND of all requirements.
type Requirements []Requirement

func (r *Requirement) HasValue(value string) bool {
	return r.values.Has(value)
}

func FromK8sRequirements(k8sReqs k8sLbls.Requirements) Requirements {
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
func (r *Requirement) Matches(logger *slog.Logger, ls labels.LabelArray) bool {
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
			logger.Info(
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
			logger.Info(
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
				logger.Info(
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

func (reqs Requirements) Matches(logger *slog.Logger, labels labels.LabelArray) bool {
	for i := range reqs {
		if !reqs[i].Matches(logger, labels) {
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
