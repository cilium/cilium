// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package scaletozero

import (
	"context"
	"errors"
	"io"
	"iter"
	"log/slog"
	"os"
	"syscall"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/scaletozero/fake"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/time"
)

// fakeCTMaps yields no active conntrack maps, modelling a socket-LB-only
// service whose connections never create a service conntrack entry.
type fakeCTMaps struct{}

func (fakeCTMaps) ActiveMaps() []*ctmap.Map { return nil }

// fakeSockRevNat injects a fixed per-service live socket-LB connection count.
type fakeSockRevNat struct {
	counts map[loadbalancer.ServiceID]int
}

func (f fakeSockRevNat) addCounts(_ map[loadbalancer.ServiceID]loadbalancer.ServiceName, into map[loadbalancer.ServiceID]int) error {
	for id, n := range f.counts {
		into[id] += n
	}
	return nil
}

func newTestController() (*controller, *fake.ScaleToZeroMap) {
	fm := fake.NewFakeScaleToZeroMap()
	c := &controller{
		log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		metrics:        newMetrics(),
		s2zMap:         fm,
		lastActivation: map[loadbalancer.ServiceName]time.Time{},
		published:      map[loadbalancer.ServiceName]struct{}{},
	}
	return c, fm
}

func demand(t *testing.T, c *controller, name loadbalancer.ServiceName) float64 {
	g, err := c.metrics.Demand.GetMetricWithLabelValues(name.Namespace(), name.Name())
	require.NoError(t, err)
	return g.Get()
}

func TestSignalServiceIDByteOrder(t *testing.T) {
	// The datapath sends rev_nat_index (network byte order) widened to 32 bits.
	sig := ScaleToZeroSignal{SvcID: uint32(byteorder.HostToNetwork16(1234))}
	assert.Equal(t, loadbalancer.ServiceID(1234), sig.serviceID())
	assert.Equal(t, "1234", sig.String())
}

// A datapath signal carries an expanded NodePort service id, which is not the
// statedb Frontend ID; it must resolve through the map's tracked-set.
func TestActivateResolvesExpandedNodePortID(t *testing.T) {
	c, fm := newTestController()
	echo := loadbalancer.NewServiceName("ns", "echo")
	fm.Entries[8] = echo  // ClusterIP id
	fm.Entries[11] = echo // expanded NodePort id

	c.activate(fm.Tracked(), 11, time.Now())
	assert.Equal(t, float64(1), demand(t, c, echo))

	// An untracked id is a no-op.
	c.activate(fm.Tracked(), 99, time.Now())
	assert.Equal(t, 1, testutil.CollectAndCount(c.metrics.Demand))
}

func TestConsumeActivationsFloorsDemand(t *testing.T) {
	c, fm := newTestController()
	svc := loadbalancer.NewServiceName("ns", "svc")
	fm.Entries[7] = svc

	ch := make(chan ScaleToZeroSignal, 2)
	ch <- ScaleToZeroSignal{SvcID: uint32(byteorder.HostToNetwork16(7))} // tracked
	ch <- ScaleToZeroSignal{SvcID: uint32(byteorder.HostToNetwork16(9))} // untracked
	close(ch)

	c.consumeActivations(context.Background(), ch)

	assert.Equal(t, float64(1), demand(t, c, svc))
	assert.Equal(t, 1, testutil.CollectAndCount(c.metrics.Demand))
}

func TestConsumeActivationsStopsOnContextCancel(t *testing.T) {
	c, _ := newTestController()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan struct{})
	go func() {
		c.consumeActivations(ctx, make(chan ScaleToZeroSignal))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("consumeActivations did not return after context cancel")
	}
}

func TestPublishDemandCountsConnections(t *testing.T) {
	c, fm := newTestController()
	echo := loadbalancer.NewServiceName("ns", "svc")
	fm.Entries[1] = echo

	c.publishDemand(fm.Tracked(), map[loadbalancer.ServiceID]int{1: 5}, time.Now())
	assert.Equal(t, float64(5), demand(t, c, echo))

	// No connections and no recent activation -> demand drops to 0.
	c.publishDemand(fm.Tracked(), map[loadbalancer.ServiceID]int{}, time.Now())
	assert.Equal(t, float64(0), demand(t, c, echo))
}

func TestPublishDemandAggregatesExpandedIDs(t *testing.T) {
	c, fm := newTestController()
	echo := loadbalancer.NewServiceName("ns", "svc")
	// One service, several datapath ids (ClusterIP + expanded NodePorts).
	fm.Entries[8], fm.Entries[10], fm.Entries[11] = echo, echo, echo

	c.publishDemand(fm.Tracked(), map[loadbalancer.ServiceID]int{10: 2, 11: 3}, time.Now())
	assert.Equal(t, float64(5), demand(t, c, echo))
	assert.Equal(t, 1, testutil.CollectAndCount(c.metrics.Demand))
}

func TestActivationFloorAndHold(t *testing.T) {
	c, fm := newTestController()
	echo := loadbalancer.NewServiceName("ns", "svc")
	fm.Entries[11] = echo

	now := time.Now()
	// Activation floors demand to 1 even with zero live connections.
	c.activate(fm.Tracked(), 11, now)
	assert.Equal(t, float64(1), demand(t, c, echo))

	// A scan landing during scale-up (still no connections) keeps demand at 1.
	c.publishDemand(fm.Tracked(), map[loadbalancer.ServiceID]int{}, now.Add(scanInterval))
	assert.Equal(t, float64(1), demand(t, c, echo))

	// Once connections establish, demand reflects the real count.
	c.publishDemand(fm.Tracked(), map[loadbalancer.ServiceID]int{11: 4}, now.Add(2*scanInterval))
	assert.Equal(t, float64(4), demand(t, c, echo))

	// An activation is a floor: it must not lower a demand above 1.
	c.activate(fm.Tracked(), 11, now.Add(2*scanInterval))
	assert.Equal(t, float64(4), demand(t, c, echo))

	// After the hold window with no connections, demand drops to 0.
	c.publishDemand(fm.Tracked(), map[loadbalancer.ServiceID]int{}, now.Add(2*scanInterval+activationHoldWindow+time.Second))
	assert.Equal(t, float64(0), demand(t, c, echo))
}

// Short-lived connections are never open at the scan instant, so counting live
// connections alone would scale the service to zero. While traffic flows the
// datapath re-signals every rate-limit interval, and each activation refreshes
// the hold, keeping demand >= 1 across scans that see no connections.
func TestPeriodicActivationsHoldDemandAcrossScans(t *testing.T) {
	c, fm := newTestController()
	echo := loadbalancer.NewServiceName("ns", "echo")
	fm.Entries[7] = echo

	start := time.Now()
	noConns := map[loadbalancer.ServiceID]int{}

	// Six rate-limit intervals of traffic, with a scan landing between signals.
	for i := 0; i < 6; i++ {
		at := start.Add(time.Duration(i) * scanInterval)
		c.activate(fm.Tracked(), 7, at)            // datapath re-signal
		c.publishDemand(fm.Tracked(), noConns, at) // scan sees no open conns
		assert.Equal(t, float64(1), demand(t, c, echo),
			"demand must stay >= 1 while traffic keeps re-signalling")
	}

	// Traffic stops, so the datapath stops signalling. Once the hold lapses the
	// next scan with no connections drops demand to 0 to allow scale-down.
	quiet := start.Add(6*scanInterval + activationHoldWindow + time.Second)
	c.publishDemand(fm.Tracked(), noConns, quiet)
	assert.Equal(t, float64(0), demand(t, c, echo))
}

// An east-west socket-LB connection creates no service conntrack entry; it
// must still count toward demand via the reverse-NAT sock map, or the service
// would be scaled away under a live client.
func TestCountLiveConnectionsIncludesSocketLB(t *testing.T) {
	c, fm := newTestController()
	pg := loadbalancer.NewServiceName("ns", "pg")
	fm.Entries[8] = pg
	c.ctMaps = fakeCTMaps{}
	c.sockRevNat = fakeSockRevNat{counts: map[loadbalancer.ServiceID]int{8: 1}}

	counts, err := c.countLiveConnections(fm.Tracked())
	require.NoError(t, err)
	require.Equal(t, 1, counts[8])

	c.publishDemand(fm.Tracked(), counts, time.Now())
	assert.Equal(t, float64(1), demand(t, c, pg))
}

func TestServiceCTEntryLive(t *testing.T) {
	const now = uint32(1000)
	const bothClosing = ctmap.RxClosing | ctmap.TxClosing
	tests := []struct {
		name string
		e    ctmap.CtEntry
		now  uint32
		want bool
	}{
		{"established", ctmap.CtEntry{Lifetime: now + 100, Flags: ctmap.SeenNonSyn}, now, true},
		{"expired", ctmap.CtEntry{Lifetime: now - 1, Flags: ctmap.SeenNonSyn}, now, false},
		{"closed-both-directions", ctmap.CtEntry{Lifetime: now + 100, Flags: ctmap.SeenNonSyn | bothClosing}, now, false},
		{"half-closed-still-live", ctmap.CtEntry{Lifetime: now + 100, Flags: ctmap.SeenNonSyn | ctmap.RxClosing}, now, true},
		{"clock-unknown-skips-expiry", ctmap.CtEntry{Lifetime: 1, Flags: ctmap.SeenNonSyn}, 0, true},
		{"clock-unknown-still-drops-closed", ctmap.CtEntry{Lifetime: 1, Flags: bothClosing}, 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, serviceCTEntryLive(&tc.e, tc.now))
		})
	}
}

// countingCTMaps / countingSockRevNat record whether the scan dumped them.
type countingCTMaps struct{ dumped *int }

func (c countingCTMaps) ActiveMaps() []*ctmap.Map { *c.dumped++; return nil }

type countingSockRevNat struct{ called *int }

func (c countingSockRevNat) addCounts(map[loadbalancer.ServiceID]loadbalancer.ServiceName, map[loadbalancer.ServiceID]int) error {
	*c.called++
	return nil
}

func TestScanSkipsDumpWhenNoTrackedServices(t *testing.T) {
	c, fm := newTestController()
	ctCalls, srnCalls := 0, 0
	c.ctMaps = countingCTMaps{&ctCalls}
	c.sockRevNat = countingSockRevNat{&srnCalls}

	fm.Entries[1] = loadbalancer.NewServiceName("ns", "svc")
	require.NoError(t, c.scan(context.Background()))
	assert.Equal(t, 1, ctCalls)
	assert.Equal(t, 1, srnCalls)
	require.Equal(t, 1, testutil.CollectAndCount(c.metrics.Demand))

	delete(fm.Entries, 1)
	require.NoError(t, c.scan(context.Background()))
	assert.Equal(t, 1, ctCalls, "scan must skip the conntrack dump when nothing is tracked")
	assert.Equal(t, 1, srnCalls, "scan must skip the sock-revnat dump when nothing is tracked")
	assert.Equal(t, 0, testutil.CollectAndCount(c.metrics.Demand), "stale series must still be pruned")
}

// fakeNetnsOps yields no namespaces but reports the given iteration errors.
func fakeNetnsOps(iterErrs ...error) netnsOps {
	return netnsOps{
		current: func() (*netns.NetNS, error) { return &netns.NetNS{}, nil },
		do:      func(*netns.NetNS, func() error) error { return nil },
		all: func() (iter.Seq2[string, *netns.NetNS], <-chan error) {
			errs := make(chan error, len(iterErrs))
			for _, e := range iterErrs {
				errs <- e
			}
			close(errs)
			return func(func(string, *netns.NetNS) bool) {}, errs
		},
	}
}

// A namespace deleted between the netns listing and opening its pin (pod
// churn) must not abort the liveness sweep; any other error must, so the
// caller falls back to counting all entries.
func TestLiveCookiesToleratesVanishedNetns(t *testing.T) {
	vanished := &os.PathError{Op: "open", Path: "/var/run/cilium/netns/gone", Err: syscall.ENOENT}
	s := lbSockRevNat{netns: fakeNetnsOps(vanished)}
	_, err := s.liveCookies()
	require.NoError(t, err)

	s = lbSockRevNat{netns: fakeNetnsOps(vanished, errors.New("netlink: permission denied"))}
	_, err = s.liveCookies()
	require.Error(t, err)
}

func TestPublishDemandPrunesUntrackedSeries(t *testing.T) {
	c, fm := newTestController()
	echo := loadbalancer.NewServiceName("ns", "svc")
	fm.Entries[1] = echo

	c.publishDemand(fm.Tracked(), map[loadbalancer.ServiceID]int{1: 2}, time.Now())
	require.Equal(t, 1, testutil.CollectAndCount(c.metrics.Demand))

	// Service stops being tracked (deleted) -> its series is pruned.
	delete(fm.Entries, 1)
	c.publishDemand(fm.Tracked(), map[loadbalancer.ServiceID]int{}, time.Now())
	assert.Equal(t, 0, testutil.CollectAndCount(c.metrics.Demand))
}
