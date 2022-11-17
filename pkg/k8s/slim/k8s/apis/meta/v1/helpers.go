// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Copyright 2016 The Kubernetes Authors.

package v1

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/selection"
)

// LabelSelectorAsSelector converts the LabelSelector api type into a struct that implements
// labels.Selector
// Note: This function should be kept in sync with the selector methods in pkg/labels/selector.go
func LabelSelectorAsSelector(ps *LabelSelector) (labels.Selector, error) {
	if ps == nil {
		return labels.Nothing(), nil
	}
	if len(ps.MatchLabels)+len(ps.MatchExpressions) == 0 {
		return labels.Everything(), nil
	}
	requirements := make([]labels.Requirement, 0, len(ps.MatchLabels)+len(ps.MatchExpressions))
	for k, v := range ps.MatchLabels {
		r, err := labels.NewRequirement(k, selection.Equals, []string{v})
		if err != nil {
			return nil, err
		}
		requirements = append(requirements, *r)
	}
	for _, expr := range ps.MatchExpressions {
		var op selection.Operator
		switch expr.Operator {
		case LabelSelectorOpIn:
			op = selection.In
		case LabelSelectorOpNotIn:
			op = selection.NotIn
		case LabelSelectorOpExists:
			op = selection.Exists
		case LabelSelectorOpDoesNotExist:
			op = selection.DoesNotExist
		default:
			return nil, fmt.Errorf("%q is not a valid pod selector operator", expr.Operator)
		}
		r, err := labels.NewRequirement(expr.Key, op, append([]string(nil), expr.Values...))
		if err != nil {
			return nil, err
		}
		requirements = append(requirements, *r)
	}
	selector := labels.NewSelector()
	selector = selector.Add(requirements...)
	return selector, nil
}

// FormatLabelSelector convert labelSelector into plain string
func FormatLabelSelector(labelSelector *LabelSelector) string {
	selector, err := LabelSelectorAsSelector(labelSelector)
	if err != nil {
		return "<error>"
	}

	l := selector.String()
	if len(l) == 0 {
		l = "<none>"
	}
	return l
}

// FullOwnerReferences converts slim OwnerReferences to original OwnerReferences
func FullOwnerReferences(references []OwnerReference) []metav1.OwnerReference {

	var fullRefs []metav1.OwnerReference
	for _, ref := range references {
		full := metav1.OwnerReference{
			Name:       ref.Name,
			Kind:       ref.Kind,
			Controller: ref.Controller,
		}
		fullRefs = append(fullRefs, full)
	}
	return fullRefs
}

// SlimOwnerReferences converts original OwnerReferences to slim OwnerReferences
func SlimOwnerReferences(references []metav1.OwnerReference) []OwnerReference {

	var slimRefs []OwnerReference
	for _, ref := range references {
		slim := OwnerReference{
			Name:       ref.Name,
			Kind:       ref.Kind,
			Controller: ref.Controller,
		}
		slimRefs = append(slimRefs, slim)
	}
	return slimRefs
}
