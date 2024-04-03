// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package synced

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/lock"
)

// waitForCacheTest is a table test case for testing WaitForCacheSyncWithTimeout.
// Each test case will similate waiting for sync of every key in resourceNamesToSyncDuration
// with their respective timeout duration.
type waitForCacheTest struct {
	timeout time.Duration
	// This maps resource names (ex. "core/v1::Pods") onto the duration the simulated
	// cache sync will take to complete.
	resourceNamesToSyncDuration map[string]time.Duration
	// Maps resource names to a duration to wait after init upon which an "event" will
	// be emitted. Used to test cases where events cause pushing out of timeout.
	resourceNamesToEvent map[string]time.Duration
	// Array which is passed to WaitForCacheSync... function.
	// Only resources in this array should cause return of timeout error when doing test.
	resourceNames []string
	expectErr     error
	// Used to test edge cases where controller doesn't actually invoke BlockWaitGroupToSyncResources.
	dontStartBlockWaitGroupToSyncResources bool
}

func TestWaitForCacheSyncWithTimeout(t *testing.T) {
	unit := func(d int) time.Duration { return syncedPollPeriod * time.Duration(d) }
	assert := assert.New(t)
	for msg, test := range map[string]waitForCacheTest{
		"Should complete due to event causing timeout to be extended past initial timeout": {
			timeout: unit(5),
			resourceNamesToSyncDuration: map[string]time.Duration{
				"foo": unit(7),
				"bar": unit(7),
			},
			resourceNamesToEvent: map[string]time.Duration{
				"foo": unit(4),
			},
			resourceNames: []string{"foo"},
		},
		"Should timeout due to watched resource exceeding timeout": {
			timeout: unit(1),
			resourceNamesToSyncDuration: map[string]time.Duration{
				"foo": unit(3),
			},
			resourceNamesToEvent: map[string]time.Duration{},
			resourceNames:        []string{"foo"},
			expectErr:            fmt.Errorf("timed out after 100ms, never received event for resource \"foo\""),
		},
		"Any one timeout should cause error": {
			timeout: unit(5),
			resourceNamesToSyncDuration: map[string]time.Duration{
				"foo": unit(3),
				"bar": unit(7),
			},
			resourceNamesToEvent: map[string]time.Duration{
				"foo": unit(4),
			},
			resourceNames: []string{"foo", "bar"},
			expectErr:     fmt.Errorf("timed out after 500ms, never received event for resource \"bar\""),
		},
		"Waiting for no resources should always sync": {
			timeout: unit(5),
			resourceNamesToSyncDuration: map[string]time.Duration{
				"foo": unit(10),
				"bar": unit(10),
			},
		},
		// One expectation of the BlockWaitGroupToSyncResources is that waits without starting
		// the controller sync will complete without waiting.
		"Not invoking BlockWaitGroupToSyncResources should cause wait to succeed immediately": {
			timeout: unit(60),
			resourceNamesToSyncDuration: map[string]time.Duration{
				"foo": unit(360),
				"bar": unit(360),
			},
			resourceNames:                          []string{"foo", "bar"},
			dontStartBlockWaitGroupToSyncResources: true,
		},
	} {
		func(test waitForCacheTest) {
			t.Run(msg, func(t *testing.T) {
				t.Parallel()
				r := &Resources{}
				stop := make(chan struct{})
				swg := lock.NewStoppableWaitGroup()
				start := time.Now()
				// Create synced functions that will begin to return true after the resource timeout duration.
				for resourceName, syncDurations := range test.resourceNamesToSyncDuration {
					hasSyncedFn := func(d time.Duration) func() bool {
						return func() bool {
							return time.Now().After(start.Add(d))
						}
					}(syncDurations)
					if test.dontStartBlockWaitGroupToSyncResources {
						continue
					}
					r.BlockWaitGroupToSyncResources(
						stop,
						swg,
						hasSyncedFn,
						resourceName,
					)
				}

				// Schedule resource events to happen after specified duration.
				for resourceName, waitForEvent := range test.resourceNamesToEvent {
					// schedule an event.
					rname := resourceName
					time.AfterFunc(waitForEvent, func() {
						r.SetEventTimestamp(rname)
					})
				}

				err := r.WaitForCacheSyncWithTimeout(test.timeout, test.resourceNames...)
				if test.expectErr == nil {
					assert.NoError(err)
				} else {
					assert.EqualError(err, test.expectErr.Error())
				}
			})
		}(test)
	}
}
