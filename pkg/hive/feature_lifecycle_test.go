// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hive

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

const (
	feature = "feature"
)

var (
	goodHook = cell.Hook{
		OnStart: func(cell.HookContext) error {
			return nil
		},
		OnStop: func(cell.HookContext) error {
			return nil
		},
	}

	failToStartHook = cell.Hook{
		OnStart: func(cell.HookContext) error {
			return fmt.Errorf("start failed")
		},
		OnStop: func(cell.HookContext) error {
			return nil
		},
	}
	failToStopHook = cell.Hook{
		OnStart: func(cell.HookContext) error {
			return nil
		},
		OnStop: func(cell.HookContext) error {
			return fmt.Errorf("stop failed")
		},
	}
)

func TestFeatureLifecycle_Append(t *testing.T) {
	testCases := []struct {
		name          string
		initialHooks  map[Feature][]cell.Hook
		initialStatus map[Feature]bool
		feature       Feature
		hook          cell.Hook
		wantError     string
		wantStatus    map[Feature]bool
	}{
		{
			name:          "new_feature",
			initialHooks:  map[Feature][]cell.Hook{},
			initialStatus: map[Feature]bool{},
			feature:       feature,
			hook:          goodHook,
			wantStatus:    map[Feature]bool{feature: false},
		},
		{
			name:          "existing_feature",
			initialHooks:  map[Feature][]cell.Hook{feature: {goodHook}},
			initialStatus: map[Feature]bool{feature: false},
			feature:       feature,
			hook:          goodHook,
			wantStatus:    map[Feature]bool{feature: false},
		},
		{
			name:          "running_feature",
			initialHooks:  map[Feature][]cell.Hook{feature: {goodHook}},
			initialStatus: map[Feature]bool{feature: true},
			feature:       feature,
			hook:          goodHook,
			wantError:     "cannot add hooks to a running feature: " + feature,
			wantStatus:    map[Feature]bool{feature: true},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fl := NewFeatureLifecycle()

			fl.hooks = tc.initialHooks
			fl.status = tc.initialStatus

			err := fl.Append(tc.feature, tc.hook)

			if err != nil && err.Error() != tc.wantError {
				t.Errorf("unexpected error: got %v, want %v", err, tc.wantError)
			}

			if !reflect.DeepEqual(fl.status, tc.wantStatus) {
				t.Errorf("unexpected status: got %v, want %v", fl.status, tc.wantStatus)
			}

		})
	}
}

func TestFeatureLifecycle_Start(t *testing.T) {
	testCases := []struct {
		name          string
		initialHooks  map[Feature][]cell.Hook
		initialStatus map[Feature]bool
		feature       Feature
		wantError     string
		wantStatus    map[Feature]bool
	}{
		{
			name:          "successful",
			initialHooks:  map[Feature][]cell.Hook{feature: {goodHook}},
			initialStatus: map[Feature]bool{feature: false},
			feature:       feature,
			wantStatus:    map[Feature]bool{feature: true},
		},
		{
			name:          "failing_hook",
			initialHooks:  map[Feature][]cell.Hook{feature: {failToStartHook}},
			initialStatus: map[Feature]bool{feature: false},
			feature:       feature,
			wantError:     fmt.Sprintf("starting hook for feature %s: start failed", feature),
			wantStatus:    map[Feature]bool{feature: false},
		},
		{
			name:          "already_running",
			initialHooks:  map[Feature][]cell.Hook{feature: {goodHook}},
			initialStatus: map[Feature]bool{feature: true},
			feature:       feature,
			wantError:     fmt.Sprintf("feature %s is already running", feature),
			wantStatus:    map[Feature]bool{feature: true},
		},
		{
			name: "second_hook_failing",
			initialHooks: map[Feature][]cell.Hook{feature: {
				goodHook,
				failToStartHook,
			}},
			feature:       feature,
			initialStatus: map[Feature]bool{feature: false},
			wantError:     fmt.Sprintf("starting hook for feature %s: start failed", feature),
			wantStatus:    map[Feature]bool{feature: false},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fl := NewFeatureLifecycle()

			fl.hooks = tc.initialHooks
			fl.status = tc.initialStatus

			err := fl.Start(tc.feature, context.Background(), slog.Default())

			if err != nil && err.Error() != tc.wantError {
				t.Errorf("unexpected error, got: %v, want: %v", err, tc.wantError)
			}
			if !reflect.DeepEqual(fl.status, tc.wantStatus) {
				t.Errorf("unexpected status, got: %v, want: %v", fl.status, tc.wantStatus)
			}
		})
	}
}

func TestFeatureLifecycle_Stop(t *testing.T) {
	testCases := []struct {
		name          string
		initialHooks  map[Feature][]cell.Hook
		initialStatus map[Feature]bool
		feature       Feature
		wantError     string
		wantStatus    map[Feature]bool
	}{
		{
			name:          "successful",
			initialHooks:  map[Feature][]cell.Hook{feature: {goodHook}},
			initialStatus: map[Feature]bool{feature: true},
			feature:       feature,
			wantStatus:    map[Feature]bool{feature: false},
		},
		{
			name:          "failing_hook",
			initialHooks:  map[Feature][]cell.Hook{feature: {failToStopHook}},
			initialStatus: map[Feature]bool{feature: true},
			feature:       feature,
			wantError:     "stop failed",
			wantStatus:    map[Feature]bool{feature: false},
		},
		{
			name: "second_hook_failing",
			initialHooks: map[Feature][]cell.Hook{feature: {
				goodHook,
				failToStopHook,
			}},
			initialStatus: map[Feature]bool{feature: true},
			feature:       feature,
			wantError:     "stop failed",
			wantStatus:    map[Feature]bool{feature: false},
		},
		{
			name:          "already_stopped",
			initialHooks:  map[Feature][]cell.Hook{feature: {goodHook}},
			initialStatus: map[Feature]bool{feature: false},
			feature:       feature,
			wantError:     fmt.Sprintf("feature %s is already stopped", feature),
			wantStatus:    map[Feature]bool{feature: false},
		},
		{
			name: "reverse_order",
			initialHooks: map[Feature][]cell.Hook{feature: {
				cell.Hook{
					OnStop: func(cell.HookContext) error {
						return fmt.Errorf("cell1")
					}},
				cell.Hook{
					OnStop: func(cell.HookContext) error {
						return fmt.Errorf("cell2")
					}},
			}},
			initialStatus: map[Feature]bool{feature: true},
			feature:       feature,
			wantError:     errors.Join(fmt.Errorf("cell2"), fmt.Errorf("cell1")).Error(),
			wantStatus:    map[Feature]bool{feature: false},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fl := NewFeatureLifecycle()

			fl.hooks = tc.initialHooks
			fl.status = tc.initialStatus

			err := fl.Stop(tc.feature, context.Background(), slog.Default())

			if err != nil && err.Error() != tc.wantError {
				t.Errorf("unexpected error, got: %v, want: %v", err, tc.wantError)
			}
			if !reflect.DeepEqual(fl.status, tc.wantStatus) {
				t.Errorf("unexpected status: got %v, want %v", fl.status, tc.wantStatus)
			}
		})
	}
}

func TestFeatureLifecycle_IsRunning(t *testing.T) {
	testCases := []struct {
		name          string
		initialStatus map[Feature]bool
		feature       Feature
		wantIsRunning bool
	}{
		{
			name:          "running",
			initialStatus: map[Feature]bool{feature: true},
			feature:       feature,
			wantIsRunning: true,
		},
		{
			name:          "stopped",
			initialStatus: map[Feature]bool{feature: false},
			feature:       feature,
			wantIsRunning: false,
		},
		{
			name:          "nonexistent",
			initialStatus: map[Feature]bool{feature: true},
			feature:       "another_feature",
			wantIsRunning: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fl := NewFeatureLifecycle()
			fl.status = tc.initialStatus

			isRunning := fl.IsRunning(tc.feature)

			if isRunning != tc.wantIsRunning {
				t.Errorf("unexpected result for status, got: %v, want: %v", isRunning, tc.wantIsRunning)
			}
		})
	}
}

func TestFeatureLifecycle_GetFeatures(t *testing.T) {
	testCases := []struct {
		name         string
		initialHooks map[Feature][]cell.Hook
		wantFeatures []Feature
	}{
		{
			name:         "empty",
			initialHooks: map[Feature][]cell.Hook{},
			wantFeatures: nil,
		},
		{
			name: "single",
			initialHooks: map[Feature][]cell.Hook{
				feature: {goodHook},
			},
			wantFeatures: []Feature{feature},
		},
		{
			name: "multiple",
			initialHooks: map[Feature][]cell.Hook{
				feature:           {goodHook},
				"another_feature": {goodHook, failToStopHook, failToStartHook},
				"third_feature":   {},
			},
			wantFeatures: []Feature{feature, "another_feature", "third_feature"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fl := NewFeatureLifecycle()
			fl.hooks = tc.initialHooks

			gotFeatures := fl.List()

			diff := cmp.Diff(tc.wantFeatures, gotFeatures, cmpopts.SortSlices(func(x, y Feature) bool { return x < y }))
			if diff != "" {
				t.Errorf("unexpected features (-want, +got):\n%s", diff)
			}

		})
	}
}
