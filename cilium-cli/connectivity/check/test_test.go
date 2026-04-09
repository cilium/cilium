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
	run, reason := mytest.checkConditions()
	assert.True(t, run)
	assert.Empty(t, reason)

	mytest = NewTest("my-test", false, false).
		WithCondition(func() bool { return true })
	run, reason = mytest.checkConditions()
	assert.True(t, run)
	assert.Empty(t, reason)

	mytest = NewTest("my-test", false, false).
		WithCondition(func() bool { return false })
	run, reason = mytest.checkConditions()
	assert.False(t, run)
	assert.Equal(t, "skipped by condition", reason)

	mytest = NewTest("my-test", false, false).
		WithCondition(func() bool { return true }).
		WithCondition(func() bool { return false })
	run, reason = mytest.checkConditions()
	assert.False(t, run)
	assert.Equal(t, "skipped by condition", reason)

	mytest = NewTest("my-test", false, false).
		WithCondition(func() bool { return false }).
		WithCondition(func() bool { return true })
	run, reason = mytest.checkConditions()
	assert.False(t, run)
	assert.Equal(t, "skipped by condition", reason)

	mytest = NewTest("my-test", false, false).
		WithCondition(func() bool { return false }).
		WithCondition(func() bool { return true }, "reason")
	run, reason = mytest.checkConditions()
	assert.False(t, run)
	assert.Equal(t, "skipped by condition", reason)

	mytest = NewTest("my-test", false, false).
		WithCondition(func() bool { return false }, "reason 1").
		WithCondition(func() bool { return true }, "reason 2")
	run, reason = mytest.checkConditions()
	assert.False(t, run)
	assert.Equal(t, "reason 1", reason)

}

func TestWithUnsafeTests(t *testing.T) {
	mytest := NewTest("my-test", false, false).WithUnsafeTests()
	mytest.ctx = &ConnectivityTest{params: Parameters{IncludeUnsafeTests: true}}
	run, reason := mytest.checkConditions()
	assert.True(t, run)
	assert.Empty(t, reason)

	mytest = NewTest("my-test", false, false).WithUnsafeTests()
	mytest.ctx = &ConnectivityTest{params: Parameters{IncludeUnsafeTests: false}}
	run, reason = mytest.checkConditions()
	assert.False(t, run)
	assert.Equal(t, "unsafe test which can modify state of cluster nodes", reason)
}

func TestWithMultiNodeOnly(t *testing.T) {
	mytest := NewTest("my-test", false, false).WithMultiNodeOnly()
	mytest.ctx = &ConnectivityTest{params: Parameters{SingleNode: false}}
	run, reason := mytest.checkConditions()
	assert.True(t, run)
	assert.Empty(t, reason)

	mytest = NewTest("my-test", false, false).WithMultiNodeOnly()
	mytest.ctx = &ConnectivityTest{params: Parameters{SingleNode: true}}
	run, reason = mytest.checkConditions()
	assert.False(t, run)
	assert.Equal(t, "test requires a multi-node cluster", reason)
}

func TestWithPerf(t *testing.T) {
	mytest := NewTest("my-test", false, false).WithPerf()
	mytest.ctx = &ConnectivityTest{params: Parameters{Perf: true}}
	run, reason := mytest.checkConditions()
	assert.True(t, run)
	assert.Empty(t, reason)

	mytest = NewTest("my-test", false, false).WithPerf()
	mytest.ctx = &ConnectivityTest{params: Parameters{Perf: false}}
	run, reason = mytest.checkConditions()
	assert.False(t, run)
	assert.Equal(t, "network performance tests excluded", reason)
}
