package gc

import (
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/signal"
	"github.com/stretchr/testify/assert"
)

// TestGCEnable tests the overall *flow* of ctmap GC scheduling
// while abstracting out the underlying garbage collection logic.
func TestGCEnable(t *testing.T) {
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
		assert.Equal(c, int(dualPasses.Load()), 1)
		assert.Equal(c, int(ipv4Passes.Load()), 1)
	}, time.Second, time.Millisecond*10, "initial pass should be full pass")

	gc.signalHandler.signals <- SignalProtoV4

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.Equal(c, int(dualPasses.Load()), 1)
		assert.Equal(c, int(ipv4Passes.Load()), 2) // This will only do ipv4 based pass.
	}, time.Second, time.Millisecond*10, "we should receive a signal based ipv4 pass now")

	reset()

	// feed ipv4 signals to simulate high pressure on *one* ip family.
	go func() {
		for {
			select {
			case <-t.Context().Done():
				return
			case <-time.After(time.Millisecond * 50):
				gc.signalHandler.signals <- SignalProtoV4
			}
		}
	}()

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.NotZero(c, dualPasses.Load())
	}, time.Second*3, time.Millisecond*10, "Despite high signal load, ipv6 should not be starve")
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
