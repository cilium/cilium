// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"

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

func TestWithCondition(t *testing.T) {
	mytest := NewTest("my-test", false, false)
	assert.True(t, mytest.checkConditions())

	mytest = NewTest("my-test", false, false).
		WithCondition(func() bool { return true })
	assert.True(t, mytest.checkConditions())

	mytest = NewTest("my-test", false, false).
		WithCondition(func() bool { return false })
	assert.False(t, mytest.checkConditions())

	mytest = NewTest("my-test", false, false).
		WithCondition(func() bool { return true }).
		WithCondition(func() bool { return false })
	assert.False(t, mytest.checkConditions())

	mytest = NewTest("my-test", false, false).
		WithCondition(func() bool { return false }).
		WithCondition(func() bool { return true })
	assert.False(t, mytest.checkConditions())
}
