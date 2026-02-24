// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gc

import (
	"context"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/signal"
)

// TestGCEnable tests the overall *flow* of ctmap GC scheduling
// while abstracting out the underlying garbage collection logic.
func TestGCEnableDualStack(t *testing.T) {
	gc := &GC{
		ipv4:             true,
		ipv6:             true,
		logger:           slog.Default(),
		endpointsManager: &fakeEPM{},
		signalHandler: SignalHandler{
			signals: make(chan SignalData),
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
	option.Config.ConntrackGCMaxInterval = time.Millisecond * 500
	gc.enable(func(ipv4, ipv6, triggeredBySignal bool, filter ctmap.GCFilter) (maxDeleteRatio float64, success bool) {
		if ipv4 {
			ipv4Passes.Add(1)
			if ipv6 {
				dualPasses.Add(1)
			}
		}
		return returnRatio, true
	}, false)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, 1, int(dualPasses.Load()))
		assert.Equal(c, 1, int(ipv4Passes.Load()))
	}, time.Second, time.Millisecond*10, "initial pass should be full pass")

	gc.signalHandler.signals <- SignalProtoV4

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, 1, int(dualPasses.Load()))
		assert.Equal(c, 2, int(ipv4Passes.Load())) // This will only do ipv4 based pass.
	}, time.Second, time.Millisecond*10, "we should receive a signal based ipv4 pass now")

	reset()

	feedSignals := func(ctx context.Context, sigs ...SignalData) {
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.Context().Done():
				return
			case <-time.After(time.Millisecond * 50):
				for _, s := range sigs {
					gc.signalHandler.signals <- s
				}
			}
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// feed ipv4 signals to simulate high pressure on *one* ip family.
	go feedSignals(ctx, SignalProtoV4)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.NotZero(c, dualPasses.Load())
	}, time.Second, time.Millisecond*10, "Despite high signal load, ipv6 should not be starved")

	cancel()
	reset()

	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	// feed ipv4 signals to simulate high pressure on *one* ip family.
	go feedSignals(ctx, SignalProtoV6)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.NotZero(c, dualPasses.Load())
	}, time.Second, time.Millisecond*10, "Despite high signal load, ipv4 should not be starved")

	cancel()
	reset()

	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	// feed ipv4 signals to simulate high pressure on *one* ip family.
	go feedSignals(ctx, SignalProtoV6, SignalProtoV4)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.NotZero(c, dualPasses.Load())
	}, time.Second, time.Millisecond*10, "Should start full pass")
}

// TestGCEnableRatchet tests the behavior of low, then high, purge ratios
// causing the interval to ratched up/down in successive GC passes.
func TestGCEnableRatchet(t *testing.T) {
	gc := &GC{
		ipv4:             true,
		ipv6:             true,
		logger:           slog.Default(),
		endpointsManager: &fakeEPM{},
		signalHandler: SignalHandler{
			signals: make(chan SignalData),
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

	ctmap.GCIntervalRounding = 10 * time.Millisecond
	returnRatio := 0.00000000000000001 // low -> high next interval
	option.Config.ConntrackGCMaxInterval = 500 * time.Millisecond
	initialPass := make(chan struct{})
	// 1. First we allow at least one initial pass to happen with the following conditions:
	// * ConntrackGCMaxInterval = Seconod
	// * Delete Ratio -> very small (meaning we quickly increase next interval)
	//	Note: This does not affect the first interval, as that runs right away
	//	instead a first pass must be run that returns this value.
	// 	The next interval then uses this to compute next interval duration.
	gc.enable(func(ipv4, ipv6, triggeredBySignal bool, filter ctmap.GCFilter) (maxDeleteRatio float64, success bool) {
		if ipv4 {
			ipv4Passes.Add(1)
			if ipv6 {
				dualPasses.Add(1)
			}
		}
		if initialPass != nil {
			close(initialPass)
			reset()
			initialPass = nil
		}
		return returnRatio, true
	}, false)

	<-initialPass                            // wait for initial pass to complete.
	option.Config.ConntrackGCMaxInterval = 0 // allow for large interval but expect shortk

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.NotZero(c, int(ipv4Passes.Load()))
	}, 10*time.Second, time.Millisecond)

	prev := ipv4Passes.Load()
	lastPassTime := time.Now()
	var lastRealDuration time.Duration
	// Wait for the gc to happen 3 times, each time we expect the interval
	// to ratched up (note: these are rounded up to seconds, so to avoid
	// making tests run too long we just wait for three iterations).
	for range 2 {
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			assert.Greater(c, ipv4Passes.Load(), prev)
		}, time.Second*5, time.Millisecond*10)
		prev = ipv4Passes.Load()
		if lastRealDuration != 0 {
			assert.Greater(t, time.Since(lastPassTime), lastRealDuration)
		}
		lastRealDuration = time.Since(lastPassTime)
		lastPassTime = time.Now()
	}

	reset()
	ctmap.MinGCInterval = time.Millisecond
	gc.signalHandler.signals <- SignalProtoV4
	// make purge ratio very big -> ratched down intervals.
	// This ratchets *fast* and will go to the min value (i.e. MinGCInterval)
	// very fast, so we just do one iteration.
	returnRatio = 0.9
	lastRealDuration = 0
	lastPassTime = time.Now()
	prev = ipv4Passes.Load()

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Greater(c, ipv4Passes.Load(), prev)
	}, time.Second*5, time.Millisecond*10)
	prev = ipv4Passes.Load()
	assert.Greater(t, time.Since(lastPassTime), lastRealDuration)
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
