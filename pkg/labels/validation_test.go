// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Copyright 2016 The Kubernetes Authors.

package labels

import (
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/util/validation/field"

	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func TestValidateLabels(t *testing.T) {
	successCases := []map[string]string{
		{"simple": "bar"},
		{"now-with-dashes": "bar"},
		{"1-starts-with-num": "bar"},
		{"1234": "bar"},
		{"simple/simple": "bar"},
		{"now-with-dashes/simple": "bar"},
		{"now-with-dashes/now-with-dashes": "bar"},
		{"now.with.dots/simple": "bar"},
		{"now-with.dashes-and.dots/simple": "bar"},
		{"1-num.2-num/3-num": "bar"},
		{"1234/5678": "bar"},
		{"1.2.3.4/5678": "bar"},
		{"UpperCaseAreOK123": "bar"},
		{"goodvalue": "123_-.BaR"},
		{"k8s:key": "validvalue"},
		{"any:simple/simple": "value"},
		{"k8s:app.kubernetes.io": "value"},
		{"k8s:app.k8s.io/name": "value"},
		{"reserved:k8s-app": "foo"},
	}
	for i := range successCases {
		errs := ValidateLabels(successCases[i], field.NewPath("field"))
		if len(errs) != 0 {
			t.Errorf("case[%d] expected success, got %#v", i, errs)
		}
	}

	namePartErrMsg := "name part must consist of"
	nameErrMsg := "a valid label key must consist of"
	labelErrMsg := "a valid label must be an empty string or consist of"
	maxLengthErrMsg := "must be no more than"

	labelNameErrorCases := []struct {
		labels map[string]string
		expect string
	}{
		{map[string]string{"nospecialchars^=@": "bar"}, namePartErrMsg},
		{map[string]string{"cantendwithadash-": "bar"}, namePartErrMsg},
		{map[string]string{"only/one/slash": "bar"}, nameErrMsg},
		{map[string]string{strings.Repeat("a", 254): "bar"}, maxLengthErrMsg},
		{map[string]string{":empty-source": "bar"}, labelSourceRegexErrMsg},
		{map[string]string{"k8s:empty:source": "bar"}, labelKeyErrMultipleSourceDelimiter},
	}
	for i := range labelNameErrorCases {
		errs := ValidateLabels(labelNameErrorCases[i].labels, field.NewPath("field"))
		if len(errs) != 1 {
			t.Errorf("case[%d]: expected failure", i)
		} else {
			if !strings.Contains(errs[0].Detail, labelNameErrorCases[i].expect) {
				t.Errorf("case[%d]: error details do not include %q: %q", i, labelNameErrorCases[i].expect, errs[0].Detail)
			}
		}
	}

	labelValueErrorCases := []struct {
		labels map[string]string
		expect string
	}{
		{map[string]string{"toolongvalue": strings.Repeat("a", 64)}, maxLengthErrMsg},
		{map[string]string{"backslashesinvalue": "some\\bad\\value"}, labelErrMsg},
		{map[string]string{"nocommasallowed": "bad,value"}, labelErrMsg},
		{map[string]string{"strangecharsinvalue": "?#$notsogood"}, labelErrMsg},
	}
	for i := range labelValueErrorCases {
		errs := ValidateLabels(labelValueErrorCases[i].labels, field.NewPath("field"))
		if len(errs) != 1 {
			t.Errorf("case[%d]: expected failure", i)
		} else {
			if !strings.Contains(errs[0].Detail, labelValueErrorCases[i].expect) {
				t.Errorf("case[%d]: error details do not include %q: %q", i, labelValueErrorCases[i].expect, errs[0].Detail)
			}
		}
	}
}

func TestLabelSelectorMatchExpression(t *testing.T) {
	testCases := []struct {
		name            string
		labelSelector   *slim_metav1.LabelSelector
		wantErrorNumber int
		validateErrs    func(t *testing.T, errs field.ErrorList)
	}{{
		name: "Valid LabelSelector",
		labelSelector: &slim_metav1.LabelSelector{
			MatchExpressions: []slim_metav1.LabelSelectorRequirement{{
				Key:      "key",
				Operator: slim_metav1.LabelSelectorOpIn,
				Values:   []string{"value"},
			}},
		},
		wantErrorNumber: 0,
		validateErrs:    nil,
	}, {
		name: "MatchExpression's key name isn't valid",
		labelSelector: &slim_metav1.LabelSelector{
			MatchExpressions: []slim_metav1.LabelSelectorRequirement{{
				Key:      "-key",
				Operator: slim_metav1.LabelSelectorOpIn,
				Values:   []string{"value"},
			}},
		},
		wantErrorNumber: 1,
		validateErrs: func(t *testing.T, errs field.ErrorList) {
			errMessage := "name part must consist of alphanumeric characters"
			if !partStringInErrorMessage(errs, errMessage) {
				t.Errorf("missing %q in\n%v", errMessage, errorsAsString(errs))
			}
		},
	}, {
		name: "MatchExpression's operator isn't valid",
		labelSelector: &slim_metav1.LabelSelector{
			MatchExpressions: []slim_metav1.LabelSelectorRequirement{{
				Key:      "key",
				Operator: "abc",
				Values:   []string{"value"},
			}},
		},
		wantErrorNumber: 1,
		validateErrs: func(t *testing.T, errs field.ErrorList) {
			errMessage := "not a valid selector operator"
			if !partStringInErrorMessage(errs, errMessage) {
				t.Errorf("missing %q in\n%v", errMessage, errorsAsString(errs))
			}
		},
	}, {
		name: "MatchExpression's value name isn't valid",
		labelSelector: &slim_metav1.LabelSelector{
			MatchExpressions: []slim_metav1.LabelSelectorRequirement{{
				Key:      "key",
				Operator: slim_metav1.LabelSelectorOpIn,
				Values:   []string{"-value"},
			}},
		},
		wantErrorNumber: 1,
		validateErrs: func(t *testing.T, errs field.ErrorList) {
			errMessage := "a valid label must be an empty string or consist of"
			if !partStringInErrorMessage(errs, errMessage) {
				t.Errorf("missing %q in\n%v", errMessage, errorsAsString(errs))
			}
		},
	}}
	for index, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			allErrs := ValidateLabelSelector(testCase.labelSelector, LabelSelectorValidationOptions{AllowInvalidLabelValueInSelector: false}, field.NewPath("labelSelector"))
			if len(allErrs) != testCase.wantErrorNumber {
				t.Errorf("case[%d]: expected failure", index)
			}
			if len(allErrs) >= 1 && testCase.validateErrs != nil {
				testCase.validateErrs(t, allErrs)
			}
		})
	}
}

func partStringInErrorMessage(errs field.ErrorList, prefix string) bool {
	for _, curr := range errs {
		if strings.Contains(curr.Error(), prefix) {
			return true
		}
	}
	return false
}

func errorsAsString(errs field.ErrorList) string {
	messages := []string{}
	for _, curr := range errs {
		messages = append(messages, curr.Error())
	}
	return strings.Join(messages, "\n")
}
