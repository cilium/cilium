// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Copyright 2015 The Kubernetes Authors.

package validation

import (
	"fmt"
	"regexp"
	"unicode"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/apimachinery/pkg/util/validation/field"

	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// LabelSelectorValidationOptions is a struct that can be passed to ValidateLabelSelector to record the validate options
type LabelSelectorValidationOptions struct {
	// Allow invalid label value in selector
	AllowInvalidLabelValueInSelector bool
}

// LabelSelectorHasInvalidLabelValue returns true if the given selector contains an invalid label value in a match expression.
// This is useful for determining whether AllowInvalidLabelValueInSelector should be set to true when validating an update
// based on existing persisted invalid values.
func LabelSelectorHasInvalidLabelValue(ps *slim_metav1.LabelSelector) bool {
	if ps == nil {
		return false
	}
	for _, e := range ps.MatchExpressions {
		for _, v := range e.Values {
			if len(validation.IsValidLabelValue(v)) > 0 {
				return true
			}
		}
	}
	return false
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
		allErrs = append(allErrs, field.Invalid(fldPath.Child("operator"), sr.Operator, "not a valid selector operator"))
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
	for _, msg := range validation.IsQualifiedName(labelName) {
		allErrs = append(allErrs, field.Invalid(fldPath, labelName, msg))
	}
	return allErrs
}

// ValidateLabels validates that a set of labels are correctly defined.
func ValidateLabels(labels map[string]string, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}
	for k, v := range labels {
		allErrs = append(allErrs, ValidateLabelName(k, fldPath)...)
		for _, msg := range validation.IsValidLabelValue(v) {
			allErrs = append(allErrs, field.Invalid(fldPath, v, msg))
		}
	}
	return allErrs
}

var FieldManagerMaxLength = 128

// ValidateFieldManager valides that the fieldManager is the proper length and
// only has printable characters.
func ValidateFieldManager(fieldManager string, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}
	// the field can not be set as a `*string`, so a empty string ("") is
	// considered as not set and is defaulted by the rest of the process
	// (unless apply is used, in which case it is required).
	if len(fieldManager) > FieldManagerMaxLength {
		allErrs = append(allErrs, field.TooLong(fldPath, fieldManager, FieldManagerMaxLength))
	}
	// Verify that all characters are printable.
	for i, r := range fieldManager {
		if !unicode.IsPrint(r) {
			allErrs = append(allErrs, field.Invalid(fldPath, fieldManager, fmt.Sprintf("invalid character %#U (at position %d)", r, i)))
		}
	}

	return allErrs
}

var allowedFieldValidationValues = sets.NewString("", slim_metav1.FieldValidationIgnore, slim_metav1.FieldValidationWarn, slim_metav1.FieldValidationStrict)

// ValidateFieldValidation validates that a fieldValidation query param only contains allowed values.
func ValidateFieldValidation(fldPath *field.Path, fieldValidation string) field.ErrorList {
	allErrs := field.ErrorList{}
	if !allowedFieldValidationValues.Has(fieldValidation) {
		allErrs = append(allErrs, field.NotSupported(fldPath, fieldValidation, allowedFieldValidationValues.List()))
	}
	return allErrs

}

const MaxSubresourceNameLength = 256

func ValidateConditions(conditions []slim_metav1.Condition, fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	conditionTypeToFirstIndex := map[string]int{}
	for i, condition := range conditions {
		if _, ok := conditionTypeToFirstIndex[condition.Type]; ok {
			allErrs = append(allErrs, field.Duplicate(fldPath.Index(i).Child("type"), condition.Type))
		} else {
			conditionTypeToFirstIndex[condition.Type] = i
		}

		allErrs = append(allErrs, ValidateCondition(condition, fldPath.Index(i))...)
	}

	return allErrs
}

// validConditionStatuses is used internally to check validity and provide a good message
var validConditionStatuses = sets.NewString(string(slim_metav1.ConditionTrue), string(slim_metav1.ConditionFalse), string(slim_metav1.ConditionUnknown))

const (
	maxReasonLen  = 1 * 1024
	maxMessageLen = 32 * 1024
)

func ValidateCondition(condition slim_metav1.Condition, fldPath *field.Path) field.ErrorList {
	var allErrs field.ErrorList

	// type is set and is a valid format
	allErrs = append(allErrs, ValidateLabelName(condition.Type, fldPath.Child("type"))...)

	// status is set and is an accepted value
	if !validConditionStatuses.Has(string(condition.Status)) {
		allErrs = append(allErrs, field.NotSupported(fldPath.Child("status"), condition.Status, validConditionStatuses.List()))
	}

	if condition.ObservedGeneration < 0 {
		allErrs = append(allErrs, field.Invalid(fldPath.Child("observedGeneration"), condition.ObservedGeneration, "must be greater than or equal to zero"))
	}

	if condition.LastTransitionTime.IsZero() {
		allErrs = append(allErrs, field.Required(fldPath.Child("lastTransitionTime"), "must be set"))
	}

	if len(condition.Reason) == 0 {
		allErrs = append(allErrs, field.Required(fldPath.Child("reason"), "must be set"))
	} else {
		for _, currErr := range isValidConditionReason(condition.Reason) {
			allErrs = append(allErrs, field.Invalid(fldPath.Child("reason"), condition.Reason, currErr))
		}
		if len(condition.Reason) > maxReasonLen {
			allErrs = append(allErrs, field.TooLong(fldPath.Child("reason"), condition.Reason, maxReasonLen))
		}
	}

	if len(condition.Message) > maxMessageLen {
		allErrs = append(allErrs, field.TooLong(fldPath.Child("message"), condition.Message, maxMessageLen))
	}

	return allErrs
}

const conditionReasonFmt string = "[A-Za-z]([A-Za-z0-9_,:]*[A-Za-z0-9_])?"
const conditionReasonErrMsg string = "a condition reason must start with alphabetic character, optionally followed by a string of alphanumeric characters or '_,:', and must end with an alphanumeric character or '_'"

var conditionReasonRegexp = regexp.MustCompile("^" + conditionReasonFmt + "$")

// isValidConditionReason tests for a string that conforms to rules for condition reasons. This checks the format, but not the length.
func isValidConditionReason(value string) []string {
	if !conditionReasonRegexp.MatchString(value) {
		return []string{validation.RegexError(conditionReasonErrMsg, conditionReasonFmt, "my_name", "MY_NAME", "MyName", "ReasonA,ReasonB", "ReasonA:ReasonB")}
	}
	return nil
}
