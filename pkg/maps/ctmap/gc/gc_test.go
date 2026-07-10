// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gc

import (
	"context"
	"log/slog"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/signal"
)

// TestGCEnable tests the overall *flow* of ctmap GC scheduling
// while abstracting out the underlying garbage collection logic.
func TestGCEnableDualStack(t *testing.T) {
	signalChan := make(chan SignalData)
	defer close(signalChan) // Ensure cleanup

	gc := &GC{
		ipv4:             true,
		ipv6:             true,
		logger:           slog.Default(),
		endpointsManager: &fakeEPM{},
		signalHandler: SignalHandler{
			signals: signalChan,
			manager: &fakeSignalMan{},
		},
	}

	// start GC

	var ipv4Passes atomic.Int32
	var dualPasses atomic.Int32

	reset := func() {
		ipv4Passes.Store(0)
		dualPasses.Store(0)
	}

	returnRatio := 0.1 // low -> high next interval
	// Use local variables instead of modifying global state
	localConntrackGCMaxInterval := time.Millisecond * 500
	localGCIntervalRounding := gcIntervalRounding
	localMinGCInterval := minGCInterval

	gc.enableWithConfig(func(ipv4, ipv6, triggeredBySignal bool, filter ctmap.GCFilter) (maxDeleteRatio float64, success bool) {
		if ipv4 {
			ipv4Passes.Add(1)
			if ipv6 {
				dualPasses.Add(1)
			}
		}
		return returnRatio, true
	}, false, 0, localConntrackGCMaxInterval, localGCIntervalRounding, localMinGCInterval)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, 1, int(dualPasses.Load()))
		assert.Equal(c, 1, int(ipv4Passes.Load()))
	}, time.Second, time.Millisecond*10, "initial pass should be full pass")

	signalChan <- SignalProtoV4

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, 1, int(dualPasses.Load()))
		assert.Equal(c, 2, int(ipv4Passes.Load())) // This will only do ipv4 based pass.
	}, time.Second, time.Millisecond*10, "we should receive a signal based ipv4 pass now")

	reset()

	feedSignals := func(ctx context.Context, done chan any, ch chan SignalData, sigs ...SignalData) {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.Context().Done():
				return
			case <-time.After(time.Millisecond * 50):
				for _, s := range sigs {
					ch <- s
				}
			}
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// feed ipv4 signals to simulate high pressure on *one* ip family.
	done := make(chan any)
	go feedSignals(ctx, done, gc.signalHandler.signals, SignalProtoV4)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.NotZero(c, dualPasses.Load())
	}, time.Second, time.Millisecond*10, "Despite high signal load, ipv6 should not be starved")

	cancel()
	<-done
	reset()

	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	// feed ipv4 signals to simulate high pressure on *one* ip family.
	done = make(chan any)
	go feedSignals(ctx, done, gc.signalHandler.signals, SignalProtoV6)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.NotZero(c, dualPasses.Load())
	}, time.Second, time.Millisecond*10, "Despite high signal load, ipv4 should not be starved")

	cancel()
	<-done
	reset()

	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	// feed ipv4 signals to simulate high pressure on *one* ip family.
	done = make(chan any)
	go feedSignals(ctx, done, gc.signalHandler.signals, SignalProtoV6, SignalProtoV4)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.NotZero(c, dualPasses.Load())
	}, time.Second, time.Millisecond*10, "Should start full pass")

	cancel()
	<-done
}

// TestGCEnableRatchet tests the behavior of low, then high, purge ratios
// causing the interval to ratchet up/down in successive GC passes.
func TestGCEnableRatchet(t *testing.T) {
	// Use local configuration variables instead of modifying global state
	localGCIntervalRounding := 10 * time.Millisecond
	localMinGCInterval := time.Millisecond
	localConntrackGCMaxInterval := 2 * time.Second // Set reasonable max for testing

	// Channel to signal test completion to ensure proper cleanup ordering
	testDone := make(chan struct{})

	defer func() {
		close(testDone)
		// Wait to ensure goroutines fully exit
		time.Sleep(200 * time.Millisecond)
		// Force garbage collection and yield to help ensure goroutines are done
		runtime.GC()
		runtime.Gosched()
		time.Sleep(50 * time.Millisecond)
	}()

	// Test interval ratcheting down then up
	{
		signalChan := make(chan SignalData, 10)
		gc := &GC{
			ipv4:             true,
			ipv6:             true,
			logger:           slog.Default(),
			endpointsManager: &fakeEPM{},
			signalHandler: SignalHandler{
				signals: signalChan,
				manager: &fakeSignalMan{},
			},
		}

		var passCount atomic.Int32
		var lastPassTime time.Time
		var lastRealDuration atomic.Int64 // Store as nanoseconds
		var currentDeleteRatio atomic.Pointer[float64]

		initialRatio := 0.9
		currentDeleteRatio.Store(&initialRatio)

		initialPassDone := make(chan struct{})
		var initialPassSignaled atomic.Bool

		gc.enableWithConfig(func(ipv4, ipv6, triggeredBySignal bool, filter ctmap.GCFilter) (maxDeleteRatio float64, success bool) {
			// Check if test is done
			select {
			case <-testDone:
				return 0, false
			default:
			}

			if ipv4 {
				passCount.Add(1)
				now := time.Now()
				if !lastPassTime.IsZero() {
					duration := now.Sub(lastPassTime)
					lastRealDuration.Store(int64(duration))
				}
				lastPassTime = now
			}

			// Signal initial pass completion once
			if !initialPassSignaled.Swap(true) {
				close(initialPassDone)
			}

			ratio := *currentDeleteRatio.Load()
			return ratio, true
		}, false, 0, localConntrackGCMaxInterval, localGCIntervalRounding, localMinGCInterval)

		// Wait for initial pass
		<-initialPassDone

		// Phase 1: Ratchet DOWN (High delete ratio 0.9)
		t.Log("Phase 1: Ratcheting DOWN")

		var prevDuration time.Duration
		initialCount := passCount.Load()
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			assert.Greater(c, passCount.Load(), initialCount)

			currentDuration := time.Duration(lastRealDuration.Load())
			if currentDuration > 0 {
				if prevDuration == 0 {
					prevDuration = currentDuration
				} else if currentDuration < prevDuration {
					prevDuration = currentDuration
				}
				// Verify it drops close to min interval
				assert.LessOrEqual(c, currentDuration, localMinGCInterval*200, "Interval should drop significantly") // 200ms
			}
		}, 5*time.Second, 10*time.Millisecond)

		// Phase 2: Ratchet UP (Low delete ratio 0.01)
		t.Log("Phase 2: Ratcheting UP")
		lowRatio := 0.01
		currentDeleteRatio.Store(&lowRatio)

		// Reset prevDuration to track increase from the low point
		prevDuration = 0
		initialCount = passCount.Load()

		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			assert.Greater(c, passCount.Load(), initialCount)

			currentDuration := time.Duration(lastRealDuration.Load())
			if currentDuration > 0 {
				if prevDuration == 0 {
					prevDuration = currentDuration
				} else if currentDuration > prevDuration {
					prevDuration = currentDuration
				}

				// Verify it increases.
				assert.Greater(c, currentDuration, localMinGCInterval*200, "Interval should increase back up")
			}
		}, 5*time.Second, 10*time.Millisecond)

		// Stop
		close(signalChan)
	}

	t.Log("GC interval ratcheting test completed successfully")
}

type fakeEPM struct{}

func (f *fakeEPM) GetEndpoints() []*endpoint.Endpoint {
	return []*endpoint.Endpoint{{
		DNSZombies: fqdn.NewDNSZombieMappings(slog.Default(), 0, 0),
	}}
}

type fakeSignalMan struct{}

// RegisterHandler must be called during initialization of the cells using signals.
func (f *fakeSignalMan) RegisterHandler(handler signal.SignalHandler, signals ...signal.SignalType) error {
	return nil
}

func (f *fakeSignalMan) MuteSignals(signals ...signal.SignalType) error {
	return nil
}

func (f *fakeSignalMan) UnmuteSignals(signals ...signal.SignalType) error {
	return nil
}

func TestCalculateInterval(t *testing.T) {
	require.Equal(t, time.Minute, calculateInterval(time.Minute, 0.1))  // no change
	require.Equal(t, time.Minute, calculateInterval(time.Minute, 0.2))  // no change
	require.Equal(t, time.Minute, calculateInterval(time.Minute, 0.25)) // no change

	require.Equal(t, 36*time.Second, calculateInterval(time.Minute, 0.40))
	require.Equal(t, 24*time.Second, calculateInterval(time.Minute, 0.60))

	require.Equal(t, 15*time.Second, calculateInterval(10*time.Second, 0.01))
	require.Equal(t, 15*time.Second, calculateInterval(10*time.Second, 0.04))

	require.Equal(t, defaults.ConntrackGCMinInterval, calculateInterval(1*time.Second, 0.9))

	require.Equal(t, defaults.ConntrackGCMaxLRUInterval, calculateInterval(24*time.Hour, 0.01))
}

func TestGetInterval(t *testing.T) {
	actualLast := time.Minute
	expectedLast := time.Minute
	logger := hivetest.Logger(t)
	interval := getInterval(logger, actualLast, expectedLast, 0.1, 0, 0)
	require.Equal(t, time.Minute, interval)
	expectedLast = interval

	interval = getInterval(logger, actualLast, expectedLast, 0.1, 10*time.Second, 0)
	require.Equal(t, 10*time.Second, interval)

	interval = getInterval(logger, actualLast, expectedLast, 0.1, 0, 0)
	require.Equal(t, time.Minute, interval)

	// Setting ConntrackGCMaxInterval limits the maximum interval
	require.Equal(t, 20*time.Second, getInterval(logger, actualLast, expectedLast, 0.1, 0, 20*time.Second))
	require.Equal(t, time.Minute, getInterval(logger, actualLast, expectedLast, 0.1, 0, 0))
}

func calculateInterval(prevInterval time.Duration, maxDeleteRatio float64) (interval time.Duration) {
	return calculateIntervalWithConfig(prevInterval, maxDeleteRatio, gcIntervalRounding, minGCInterval)
}

func getInterval(logger *slog.Logger, actualPrevInterval, expectedPrevInterval time.Duration, maxDeleteRatio float64, gcInterval time.Duration, gcMaxInterval time.Duration) time.Duration {
	return getIntervalWithConfig(logger, actualPrevInterval, expectedPrevInterval, maxDeleteRatio, gcInterval, gcMaxInterval, gcIntervalRounding, minGCInterval)
}
