// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"reflect"
	"testing"
)

func TestWithFeatureRequirements(t *testing.T) {
	tests := map[string]struct {
		requirements []FeatureRequirement
		in           []FeatureRequirement
		want         []FeatureRequirement
	}{
		"Adding a feature to an empty list": {
			requirements: nil,
			in:           []FeatureRequirement{{feature: FeatureL7Proxy}},
			want:         []FeatureRequirement{{feature: FeatureL7Proxy}},
		},
		"Adding several features to an existing list with no duplicate": {
			requirements: []FeatureRequirement{{feature: FeatureCNP}, {feature: FeatureIPv6}},
			in:           []FeatureRequirement{{feature: FeatureL7Proxy}, {feature: FeatureEncryptionNode}},
			want:         []FeatureRequirement{{feature: FeatureCNP}, {feature: FeatureIPv6}, {feature: FeatureL7Proxy}, {feature: FeatureEncryptionNode}},
		},
		"Adding one duplicate": {
			requirements: []FeatureRequirement{{feature: FeatureCNP}, {feature: FeatureIPv6}},
			in:           []FeatureRequirement{{feature: FeatureL7Proxy}, {feature: FeatureIPv6}},
			want:         []FeatureRequirement{{feature: FeatureCNP}, {feature: FeatureIPv6}, {feature: FeatureL7Proxy}},
		},
		"Adding two same features as input": {
			requirements: []FeatureRequirement{{feature: FeatureCNP}, {feature: FeatureIPv6}},
			in:           []FeatureRequirement{{feature: FeatureL7Proxy}, {feature: FeatureL7Proxy}},
			want:         []FeatureRequirement{{feature: FeatureCNP}, {feature: FeatureIPv6}, {feature: FeatureL7Proxy}},
		},
		"Adding an empty list": {
			requirements: []FeatureRequirement{{feature: FeatureCNP}, {feature: FeatureIPv6}},
			in:           []FeatureRequirement{},
			want:         []FeatureRequirement{{feature: FeatureCNP}, {feature: FeatureIPv6}},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			test := Test{requirements: tc.requirements}
			if got := test.WithFeatureRequirements(tc.in...); !reflect.DeepEqual(got.requirements, tc.want) {
				t.Errorf("WithFeatureRequirements() = %v, want %v", got.requirements, tc.want)
			}
		})
	}
}
