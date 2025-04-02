// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package key

import (
	"testing"

	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
)

func TestGetCIDKeyFromLabels(t *testing.T) {
	labelsfilter.ParseLabelPrefixCfg(nil, nil, "")

	tests := []struct {
		name     string
		labels   map[string]string
		source   string
		expected *GlobalIdentity
	}{
		{
			name:   "Valid Labels",
			labels: map[string]string{"source1:label1": "value1", "source2:label2": "value2", "irrelevant": "foo"},
			source: "source1",
			expected: &GlobalIdentity{LabelArray: []labels.Label{
				labels.NewLabel("label1", "value1", "source1"),
				labels.NewLabel("label2", "value2", "source1"),
				labels.NewLabel("irrelevant", "foo", "source1"),
			}},
		},
		{
			name:     "Empty Labels",
			labels:   map[string]string{},
			source:   "source",
			expected: &GlobalIdentity{LabelArray: []labels.Label{}},
		},
		{
			name:   "Empty source",
			labels: map[string]string{"source1:foo1": "value1", "source2:foo2": "value2", "foo3": "value3"},
			source: "",
			expected: &GlobalIdentity{LabelArray: []labels.Label{
				labels.NewLabel("foo1", "value1", "source1"),
				labels.NewLabel("foo2", "value2", "source2"),
				labels.NewLabel("foo3", "value3", labels.LabelSourceUnspec),
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			result := GetCIDKeyFromLabels(tt.labels, tt.source)

			if result == nil {
				t.Fatalf("Expected a GlobalIdentity result, but got nil")
			}

			result.LabelArray.Sort()
			tt.expected.LabelArray.Sort()

			if !tt.expected.LabelArray.Equals(result.LabelArray) {
				t.Errorf("Unexpected result:\nGot: %v\nExpected: %v", result.LabelArray, tt.expected.LabelArray)
			}

		})
	}
}
