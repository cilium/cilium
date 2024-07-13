// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"reflect"
	"testing"

	"github.com/cilium/cilium/cilium-cli/utils/features"
)

func TestWithFeatureRequirements(t *testing.T) {
	tests := map[string]struct {
		requirements []features.Requirement
		in           []features.Requirement
		want         []features.Requirement
	}{
		"Adding a feature to an empty list": {
			requirements: nil,
			in:           []features.Requirement{{Feature: features.L7Proxy}},
			want:         []features.Requirement{{Feature: features.L7Proxy}},
		},
		"Adding several features to an existing list with no duplicate": {
			requirements: []features.Requirement{{Feature: features.CNP}, {Feature: features.IPv6}},
			in:           []features.Requirement{{Feature: features.L7Proxy}, {Feature: features.EncryptionNode}},
			want:         []features.Requirement{{Feature: features.CNP}, {Feature: features.IPv6}, {Feature: features.L7Proxy}, {Feature: features.EncryptionNode}},
		},
		"Adding one duplicate": {
			requirements: []features.Requirement{{Feature: features.CNP}, {Feature: features.IPv6}},
			in:           []features.Requirement{{Feature: features.L7Proxy}, {Feature: features.IPv6}},
			want:         []features.Requirement{{Feature: features.CNP}, {Feature: features.IPv6}, {Feature: features.L7Proxy}},
		},
		"Adding two same features as input": {
			requirements: []features.Requirement{{Feature: features.CNP}, {Feature: features.IPv6}},
			in:           []features.Requirement{{Feature: features.L7Proxy}, {Feature: features.L7Proxy}},
			want:         []features.Requirement{{Feature: features.CNP}, {Feature: features.IPv6}, {Feature: features.L7Proxy}},
		},
		"Adding an empty list": {
			requirements: []features.Requirement{{Feature: features.CNP}, {Feature: features.IPv6}},
			in:           []features.Requirement{},
			want:         []features.Requirement{{Feature: features.CNP}, {Feature: features.IPv6}},
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
