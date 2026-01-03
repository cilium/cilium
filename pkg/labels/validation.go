// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Copyright 2015 The Kubernetes Authors.
// Adapted From: https://github.com/kubernetes/apimachinery/tree/master/pkg/apis/meta/v1/validation

package labels

import (
	"regexp"
	"strings"

	"k8s.io/apimachinery/pkg/api/validate/content"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"

	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

const (
	labelSourceREGroup     string = "[A-Za-z0-9]+"
	labelSourceRegexErrMsg string = "label source should be a non empty string with only alphanumeric characters"

	labelKeyErrMultipleSourceDelimiter string = "a valid label key only support ':' character as a source separator with non empty value"
)

var (
	LabelSourceRegexp = regexp.MustCompile("^" + labelSourceREGroup + "$")
)

// LabelSelectorValidationOptions is a struct that can be passed to ValidateLabelSelector to record the validate options
type LabelSelectorValidationOptions struct {
	// Allow invalid label value in selector
	AllowInvalidLabelValueInSelector bool

	// Allows an operator that is not interpretable to pass validation.  This is useful for cases where a broader check
	// can be performed, as in a *SubjectAccessReview
	AllowUnknownOperatorInRequirement bool
}

// ValidateLabelSelector validate the LabelSelector according to the opts and returns any validation errors.
// opts.AllowInvalidLabelValueInSelector is only expected to be set to true when required for backwards compatibility with existing invalid data.
func ValidateLabelSelector(ps *slim_metav1.LabelSelector, opts LabelSelectorValidationOptions, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}
	if ps == nil {
		return allErrs
	}
	allErrs = append(allErrs, ValidateLabels(ps.MatchLabels, fldPath.Child("matchLabels"))...)
	for i, expr := range ps.MatchExpressions {
		allErrs = append(allErrs, ValidateLabelSelectorRequirement(expr, opts, fldPath.Child("matchExpressions").Index(i))...)
	}
	return allErrs
}

// ValidateLabelSelectorRequirement validate the requirement according to the opts and returns any validation errors.
// opts.AllowInvalidLabelValueInSelector is only expected to be set to true when required for backwards compatibility with existing invalid data.
func ValidateLabelSelectorRequirement(sr slim_metav1.LabelSelectorRequirement, opts LabelSelectorValidationOptions, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}
	switch sr.Operator {
	case slim_metav1.LabelSelectorOpIn, slim_metav1.LabelSelectorOpNotIn:
		if len(sr.Values) == 0 {
			allErrs = append(allErrs, field.Required(fldPath.Child("values"), "must be specified when `operator` is 'In' or 'NotIn'"))
		}
	case slim_metav1.LabelSelectorOpExists, slim_metav1.LabelSelectorOpDoesNotExist:
		if len(sr.Values) > 0 {
			allErrs = append(allErrs, field.Forbidden(fldPath.Child("values"), "may not be specified when `operator` is 'Exists' or 'DoesNotExist'"))
		}
	default:
		if !opts.AllowUnknownOperatorInRequirement {
			allErrs = append(allErrs, field.Invalid(fldPath.Child("operator"), sr.Operator, "not a valid selector operator"))
		}
	}
	allErrs = append(allErrs, ValidateLabelName(sr.Key, fldPath.Child("key"))...)
	if !opts.AllowInvalidLabelValueInSelector {
		for valueIndex, value := range sr.Values {
			for _, msg := range validation.IsValidLabelValue(value) {
				allErrs = append(allErrs, field.Invalid(fldPath.Child("values").Index(valueIndex), value, msg))
			}
		}
	}
	return allErrs
}

// ValidateLabelName validates that the label name is correctly defined.
func ValidateLabelName(labelName string, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}
	for _, msg := range IsValidCiliumLabelKey(labelName) {
		allErrs = append(allErrs, field.Invalid(fldPath, labelName, msg).WithOrigin("format=label-key"))
	}
	return allErrs
}

// ValidateLabels validates that a set of labels are correctly defined.
func ValidateLabels(labels map[string]string, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}
	for k, v := range labels {
		allErrs = append(allErrs, ValidateLabelName(k, fldPath)...)
		for _, msg := range content.IsLabelValue(v) {
			allErrs = append(allErrs, field.Invalid(fldPath, v, msg).WithOrigin("format=label-value"))
		}
	}
	return allErrs
}

// IsValidCiliumLabelKey tests whether the value passed is a valid cilium's representation of
// label key.
// Cilium label key supports an additional optional source prefix along with k8s label key.
// The label source prefix is delimited with ':'
func IsValidCiliumLabelKey(key string) []string {
	var (
		source   string
		labelKey string
		errs     []string
	)

	parts := strings.Split(key, SourceDelimiter)
	switch len(parts) {
	case 1:
		labelKey = parts[0]
	case 2:
		source, labelKey = parts[0], parts[1]
		if !LabelSourceRegexp.MatchString(source) {
			errs = append(errs, labelSourceRegexErrMsg)
		}
	default:
		return append(errs, labelKeyErrMultipleSourceDelimiter)
	}

	return append(errs, content.IsLabelKey(labelKey)...)
}
