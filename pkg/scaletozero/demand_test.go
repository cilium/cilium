// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package scaletozero

import (
	"bytes"
	"encoding/binary"
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
	clocktesting "k8s.io/utils/clock/testing"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/loadbalancer"
	scaletozerofake "github.com/cilium/cilium/pkg/maps/scaletozero/fake"
	"github.com/cilium/cilium/pkg/signal"
	"github.com/cilium/cilium/pkg/time"
)

const window = 5 * time.Minute

// wakeSignal is the payload the datapath sends with a scale-from-zero signal:
// the service ID in network byte order, widened to the size of the union member.
func wakeSignal(id loadbalancer.ServiceID) io.Reader {
	var buf bytes.Buffer
	binary.Write(&buf, binary.NativeEndian, uint32(byteorder.HostToNetwork16(uint16(id))))
	return &buf
}

// newTestServices returns a scale-to-zero map tracking ID 1 for "test/echo".
func newTestServices(t *testing.T) *scaletozerofake.FakeScaleToZeroMap {
	t.Helper()

	m := scaletozerofake.NewFakeScaleToZeroMap()
	require.NoError(t, m.Track(1, loadbalancer.NewServiceName("test", "echo")))

	return m
}

// newTestTracker returns a tracker for a service "test/echo" with ID 1.
func newTestTracker(t *testing.T) (*demandTracker, *clocktesting.FakeClock) {
	t.Helper()

	clock := clocktesting.NewFakeClock(time.Now())
	return &demandTracker{
		services: newTestServices(t),
		window:   window,
		demand:   newServiceDemand(clock),
	}, clock
}

const expectedDemand = `
# HELP cilium_scale_to_zero_service_demand 1 while a scale-to-zero service is within its idle window since the last wake signal
# TYPE cilium_scale_to_zero_service_demand gauge
cilium_scale_to_zero_service_demand{name="echo",namespace="test"} 1
`

func TestDemandTracker(t *testing.T) {
	t.Run("wake puts the service in demand", func(t *testing.T) {
		tracker, clock := newTestTracker(t)

		data, err := tracker.handleWake(wakeSignal(1))
		require.NoError(t, err)
		require.Equal(t, signalMetricData, data)
		require.NoError(t, testutil.CollectAndCompare(tracker.demand, strings.NewReader(expectedDemand)))

		// Still in demand just before the window closes.
		clock.Step(window - time.Second)
		require.NoError(t, testutil.CollectAndCompare(tracker.demand, strings.NewReader(expectedDemand)))
	})

	t.Run("demand expires with the window", func(t *testing.T) {
		tracker, clock := newTestTracker(t)

		_, err := tracker.handleWake(wakeSignal(1))
		require.NoError(t, err)

		clock.Step(window)
		require.Equal(t, 0, testutil.CollectAndCount(tracker.demand))
		require.Empty(t, tracker.demand.expiry, "expired services are dropped on scrape")
	})

	t.Run("a wake extends the window", func(t *testing.T) {
		tracker, clock := newTestTracker(t)

		_, err := tracker.handleWake(wakeSignal(1))
		require.NoError(t, err)

		clock.Step(window - time.Second)
		_, err = tracker.handleWake(wakeSignal(1))
		require.NoError(t, err)

		clock.Step(window - time.Second)
		require.NoError(t, testutil.CollectAndCompare(tracker.demand, strings.NewReader(expectedDemand)))
	})

	t.Run("signal for an untracked service is dropped", func(t *testing.T) {
		tracker, _ := newTestTracker(t)

		data, err := tracker.handleWake(wakeSignal(2))
		require.NoError(t, err)
		require.Equal(t, signalMetricData, data)
		require.Equal(t, 0, testutil.CollectAndCount(tracker.demand))
	})

	t.Run("an expanded node-address frontend wakes its service", func(t *testing.T) {
		// The reconciler expands a NodePort, LoadBalancer or ExternalIP
		// frontend into one datapath entry per node address, and north/south
		// traffic only ever hits one of those. They exist in no StateDB
		// table, which is why the name comes from the tracking layer.
		services := newTestServices(t)
		require.NoError(t, services.Track(2, loadbalancer.NewServiceName("test", "echo")))

		tracker := &demandTracker{
			services: services,
			window:   window,
			demand:   newServiceDemand(clocktesting.NewFakeClock(time.Now())),
		}

		_, err := tracker.handleWake(wakeSignal(2))
		require.NoError(t, err)
		require.NoError(t, testutil.CollectAndCompare(tracker.demand, strings.NewReader(expectedDemand)))
	})

	t.Run("untracking stops the service from being resolved", func(t *testing.T) {
		tracker, _ := newTestTracker(t)

		require.NoError(t, tracker.services.Untrack(1))

		_, err := tracker.handleWake(wakeSignal(1))
		require.NoError(t, err)
		require.Equal(t, 0, testutil.CollectAndCount(tracker.demand))
	})

	t.Run("the payload the datapath writes decodes to a service ID", func(t *testing.T) {
		// SEND_SIGNAL puts the value into the __u32 member of the signal_msg
		// union, and the value the socket and tc paths pass is
		// svc->rev_nat_index, which the services map holds in network byte
		// order. Service ID 1 therefore travels as htons(1) = 0x0001 widened to
		// a native-endian u32. Hard-coding those bytes is the only assertion
		// here that would notice wakeSignal() and the handler agreeing on the
		// wrong layout. The perf ring itself is out of reach of a unit test, so
		// the emission side is covered by the live validation run.
		if binary.NativeEndian.Uint32([]byte{0x00, 0x01, 0x00, 0x00}) != 0x0100 {
			t.Skip("byte literal describes a little-endian host")
		}

		tracker, _ := newTestTracker(t)

		_, err := tracker.handleWake(bytes.NewReader([]byte{0x00, 0x01, 0x00, 0x00}))
		require.NoError(t, err)
		require.NoError(t, testutil.CollectAndCompare(tracker.demand, strings.NewReader(expectedDemand)))
	})

	t.Run("truncated signal is an error", func(t *testing.T) {
		tracker, _ := newTestTracker(t)

		_, err := tracker.handleWake(bytes.NewReader([]byte{0x1}))
		require.Error(t, err)
	})

	t.Run("closing the handler is not an error", func(t *testing.T) {
		tracker, _ := newTestTracker(t)

		_, err := tracker.handleWake(nil)
		require.NoError(t, err)
	})
}

// fakeSignalManager keeps the handler registered for each signal so that a test
// can feed it what the datapath would send.
type fakeSignalManager struct {
	handlers map[signal.SignalType]signal.SignalHandler
}

func (f *fakeSignalManager) RegisterHandler(handler signal.SignalHandler, signals ...signal.SignalType) error {
	if f.handlers == nil {
		f.handlers = map[signal.SignalType]signal.SignalHandler{}
	}
	for _, s := range signals {
		f.handlers[s] = handler
	}
	return nil
}

func (f *fakeSignalManager) MuteSignals(...signal.SignalType) error   { return nil }
func (f *fakeSignalManager) UnmuteSignals(...signal.SignalType) error { return nil }

func TestRegisterDemandTracker(t *testing.T) {
	newParams := func(sm signal.SignalManager, enabled bool) params {
		cfg := loadbalancer.DefaultConfig
		cfg.EnableScaleToZero = enabled

		return params{
			Logger:         slog.New(slog.DiscardHandler),
			Config:         cfg,
			ScaleToZeroMap: newTestServices(t),
			SignalManager:  sm,
			Metrics:        newMetrics(),
		}
	}

	t.Run("disabled drops the signals of a stale datapath", func(t *testing.T) {
		sm := &fakeSignalManager{}
		p := newParams(sm, false)
		require.NoError(t, registerDemandTracker(p))

		handler, ok := sm.handlers[signal.SignalScaleFromZero]
		require.True(t, ok, "the signal is handled so that it is not counted as unregistered")

		_, err := handler(wakeSignal(1))
		require.NoError(t, err)
		require.Equal(t, 0, testutil.CollectAndCount(p.Metrics.ServiceDemand))
	})

	t.Run("enabled publishes the demand a wake reports", func(t *testing.T) {
		sm := &fakeSignalManager{}
		p := newParams(sm, true)
		require.NoError(t, registerDemandTracker(p))

		handler, ok := sm.handlers[signal.SignalScaleFromZero]
		require.True(t, ok)

		data, err := handler(wakeSignal(1))
		require.NoError(t, err)
		require.Equal(t, signalMetricData, data)
		require.NoError(t, testutil.CollectAndCompare(p.Metrics.ServiceDemand, strings.NewReader(expectedDemand)))
	})
}

func TestScaleToZeroDefines(t *testing.T) {
	cfg := loadbalancer.DefaultConfig
	require.Empty(t, scaleToZeroDefines(cfg).NodeDefines)

	cfg.EnableScaleToZero = true
	require.Equal(t, "1", scaleToZeroDefines(cfg).NodeDefines["ENABLE_SCALE_TO_ZERO"])
}
