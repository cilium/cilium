// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumidentity

import (
	"testing"
	"time"

	clocktesting "k8s.io/utils/clock/testing"
)

func TestEnqueueTimeTracker(t *testing.T) {
	const item = "item"
	startTime := time.Now()

	testCases := []struct {
		name             string
		actions          []func(tracker *EnqueueTimeTracker)
		expectedTime     time.Time
		expectedExists   bool
		advanceClockBy   time.Duration
		initialClockTime time.Time
	}{
		{
			name: "track_new_item",
			actions: []func(tracker *EnqueueTimeTracker){
				func(tracker *EnqueueTimeTracker) { tracker.Track(item) },
			},
			expectedTime:     startTime,
			expectedExists:   true,
			advanceClockBy:   0,
			initialClockTime: startTime,
		},
		{
			name: "track_existing_item",
			actions: []func(tracker *EnqueueTimeTracker){
				func(tracker *EnqueueTimeTracker) { tracker.Track(item) },
				func(tracker *EnqueueTimeTracker) { tracker.Track(item) },
			},
			expectedTime:     startTime,
			expectedExists:   true,
			advanceClockBy:   time.Second * 5,
			initialClockTime: startTime,
		},
		{
			name: "get_and_reset",
			actions: []func(tracker *EnqueueTimeTracker){
				func(tracker *EnqueueTimeTracker) { tracker.Track(item) },
			},
			expectedTime:     startTime,
			expectedExists:   true,
			advanceClockBy:   0,
			initialClockTime: startTime,
		},
		{
			name: "non_existent_item",
			actions: []func(tracker *EnqueueTimeTracker){
				func(tracker *EnqueueTimeTracker) { tracker.Track("random_item") },
			},
			expectedTime:     time.Time{},
			expectedExists:   false,
			advanceClockBy:   0,
			initialClockTime: startTime,
		},
		{
			name: "already_reset",
			actions: []func(tracker *EnqueueTimeTracker){
				func(tracker *EnqueueTimeTracker) { tracker.Track(item) },
				func(tracker *EnqueueTimeTracker) { tracker.GetAndReset(item) },
			},
			expectedTime:     time.Time{},
			expectedExists:   false,
			advanceClockBy:   0,
			initialClockTime: startTime,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fakeClock := clocktesting.NewFakeClock(tc.initialClockTime)

			tracker := &EnqueueTimeTracker{
				enqueuedAt: make(map[string]time.Time),
				clock:      fakeClock,
			}

			for _, action := range tc.actions {
				action(tracker)
				fakeClock.Step(tc.advanceClockBy)
			}

			actualTime, actualExists := tracker.GetAndReset(item)
			if !actualTime.Equal(tc.expectedTime) {
				t.Errorf("Expected time %v, but got %v", tc.expectedTime, actualTime)
			}
			if actualExists != tc.expectedExists {
				t.Errorf("Expected exists %v, but got %v", tc.expectedExists, actualExists)
			}
		})
	}
}
