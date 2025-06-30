// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"testing"

	"github.com/stretchr/testify/assert"

	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func TestParseNodeLabelSelector(t *testing.T) {
	testCases := []struct {
		desc                  string
		input                 string
		expectedLabelSelector *slim_metav1.LabelSelector
	}{
		{
			desc:                  "Empty",
			input:                 "",
			expectedLabelSelector: nil,
		},
		{
			desc:  "Single label value",
			input: "a=b",
			expectedLabelSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]slim_metav1.MatchLabelsValue{
				"a": "b",
			}},
		},
		{
			desc:  "Multiple label values",
			input: "a=b,c=d,e=f",
			expectedLabelSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]slim_metav1.MatchLabelsValue{
				"a": "b",
				"c": "d",
				"e": "f",
			}},
		},
		{
			desc:  "Empty key is not allowed",
			input: "a=b,c=d,=f",
			expectedLabelSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]slim_metav1.MatchLabelsValue{
				"a": "b",
				"c": "d",
			}},
		},
		{
			desc:  "Empty value",
			input: "a=b,c=d,e=",
			expectedLabelSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]slim_metav1.MatchLabelsValue{
				"a": "b",
				"c": "d",
				"e": "",
			}},
		},
		{
			desc:  "No value",
			input: "a=b,c=d,e",
			expectedLabelSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]slim_metav1.MatchLabelsValue{
				"a": "b",
				"c": "d",
			}},
		},
		{
			desc:  "Space before value",
			input: "a=b,c=d,e= f",
			expectedLabelSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]slim_metav1.MatchLabelsValue{
				"a": "b",
				"c": "d",
				"e": " f",
			}},
		},
		{
			desc:  "Space after value",
			input: "a=b,c=d,e=f ",
			expectedLabelSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]slim_metav1.MatchLabelsValue{
				"a": "b",
				"c": "d",
				"e": "f ",
			}},
		},
		{
			desc:  "Space before key",
			input: "a=b,c=d, e=f",
			expectedLabelSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]slim_metav1.MatchLabelsValue{
				"a":  "b",
				"c":  "d",
				" e": "f",
			}},
		},
		{
			desc:  "Space after key",
			input: "a=b,c=d,e =f",
			expectedLabelSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]slim_metav1.MatchLabelsValue{
				"a":  "b",
				"c":  "d",
				"e ": "f",
			}},
		},
	}
	for _, tC := range testCases {
		t.Run(tC.desc, func(t *testing.T) {
			ls := ParseNodeLabelSelector(tC.input)

			assert.Equal(t, tC.expectedLabelSelector, ls)
		})
	}
}
