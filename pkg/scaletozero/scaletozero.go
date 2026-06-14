// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package scaletozero exports a per-service demand metric for services that
// opted into scale-to-zero. Demand is the number of live connections, held at
// >= 1 for a short window after a datapath demand signal so an external
// autoscaler can scale the service up from zero.
//
// Connections are counted from two sources, both keyed by rev_nat_index:
// service conntrack entries (north-south traffic) and the reverse-NAT sock map
// (pod->ClusterIP under socket-LB, translated at connect() time, never creates
// a conntrack entry). Ids resolve through the map's tracked-set, since NodePort
// services expand into one id per node address that the Frontend ID does not
// capture.
package scaletozero

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"iter"
	"log/slog"
	"strconv"
	"syscall"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/datapath/sockets"
	"github.com/cilium/cilium/pkg/loadbalancer"
	lbmaps "github.com/cilium/cilium/pkg/loadbalancer/maps"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	s2zmap "github.com/cilium/cilium/pkg/maps/scaletozero"
	"github.com/cilium/cilium/pkg/maps/timestamp"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/netns"
	"github.com/cilium/cilium/pkg/signal"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/tuple"
)

const (
	// scanInterval is how often the conntrack table is scanned to recompute
	// the per-service live-connection count.
	scanInterval = 30 * time.Second

	// activationHoldWindow holds demand at >= 1 after the last signal, long
	// enough for a pod cold start plus one scan so a scan landing mid-startup
	// does not reset demand to 0.
	activationHoldWindow = 90 * time.Second
)

// Cell exports the scale-to-zero demand metric. It does nothing unless
// --enable-scale-to-zero is set.
var Cell = cell.Module(
	"scale-to-zero",
	"Per-service scale-to-zero demand metric from datapath signal and conntrack scan",

	metrics.Metric(newMetrics),
	cell.ProvidePrivate(func() netnsOps {
		return netnsOps{
			current: netns.Current,
			do:      (*netns.NetNS).Do,
			all:     netns.All,
		}
	}),
	cell.Invoke(registerController),
)

// netnsOps captures the network-namespace operations used to enumerate live
// socket cookies, injectable for tests.
type netnsOps struct {
	current func() (*netns.NetNS, error)
	do      func(*netns.NetNS, func() error) error
	all     func() (iter.Seq2[string, *netns.NetNS], <-chan error)
}

type Metrics struct {
	Demand metric.DeletableVec[metric.Gauge]
}

func newMetrics() Metrics {
	return Metrics{
		Demand: metric.NewGaugeVec(metric.GaugeOpts{
			ConfigName: metrics.Namespace + "_scale_to_zero_service_demand",
			Namespace:  metrics.Namespace,
			Subsystem:  "scale_to_zero",
			Name:       "service_demand",
			Help: "Per-service scale-to-zero demand: the number of live connections to the " +
				"service, held at >= 1 for a short window after an activation request so an " +
				"autoscaler can scale the service up from zero.",
		}, []string{"namespace", "name"}),
	}
}

type params struct {
	cell.In

	Conf      s2zmap.Config
	Log       *slog.Logger
	Jobs      job.Group
	Metrics   Metrics
	SignalMgr signal.SignalManager
	CTMaps    ctmap.CTMaps
	S2ZMap    s2zmap.Map
	// LBMaps gives access to the reverse-NAT sock map. Optional so hives
	// without the full LB maps still construct; counting then falls back to
	// conntrack only.
	LBMaps lbmaps.LBMaps `optional:"true"`
	NetNS  netnsOps
}

func registerController(p params) error {
	if !p.Conf.EnableScaleToZero {
		return nil
	}

	c := &controller{
		log:            p.Log,
		metrics:        p.Metrics,
		ctMaps:         p.CTMaps,
		s2zMap:         p.S2ZMap,
		sockRevNat:     lbSockRevNat{lb: p.LBMaps, netns: p.NetNS, log: p.Log},
		lastActivation: map[loadbalancer.ServiceName]time.Time{},
		published:      map[loadbalancer.ServiceName]struct{}{},
	}

	// An overflowing burst just drops signals, which the datapath re-emits
	// after its rate-limit interval.
	ch := make(chan ScaleToZeroSignal, 1024)
	if err := p.SignalMgr.RegisterHandler(signal.ChannelHandler(ch), signal.SignalScaleToZero); err != nil {
		return fmt.Errorf("register scale-to-zero signal handler: %w", err)
	}

	p.Jobs.Add(job.OneShot("scale-to-zero-activations",
		func(ctx context.Context, _ cell.Health) error {
			c.consumeActivations(ctx, ch)
			return nil
		}))
	p.Jobs.Add(job.Timer("scale-to-zero-scan", c.scan, scanInterval))

	return nil
}

// ScaleToZeroSignal is the payload of a SignalScaleToZero datapath signal,
// matching the 'svc_id' union member of struct signal_msg in
// "bpf/lib/signal.h".
type ScaleToZeroSignal struct {
	// SvcID is rev_nat_index in network byte order, widened to 32 bits.
	SvcID uint32
}

func (s ScaleToZeroSignal) String() string {
	return strconv.Itoa(int(s.serviceID()))
}

func (s ScaleToZeroSignal) serviceID() loadbalancer.ServiceID {
	return loadbalancer.ServiceID(byteorder.NetworkToHost16(uint16(s.SvcID)))
}

type controller struct {
	log        *slog.Logger
	metrics    Metrics
	ctMaps     ctmap.CTMaps
	s2zMap     s2zmap.Map
	sockRevNat sockRevNatCounter

	mu lock.Mutex
	// lastActivation holds the last activation time per service, to keep
	// demand above zero across the scale-up.
	lastActivation map[loadbalancer.ServiceName]time.Time
	// published is the set of services that currently have a metric series.
	published map[loadbalancer.ServiceName]struct{}
}

// consumeActivations drains datapath activation signals, flooring the demand
// of the activated service to 1 without waiting for the next conntrack scan.
func (c *controller) consumeActivations(ctx context.Context, ch <-chan ScaleToZeroSignal) {
	for {
		select {
		case <-ctx.Done():
			return
		case sig, ok := <-ch:
			if !ok {
				return
			}
			c.activate(c.s2zMap.Tracked(), sig.serviceID(), time.Now())
		}
	}
}

func (c *controller) activate(tracked map[loadbalancer.ServiceID]loadbalancer.ServiceName, svcID loadbalancer.ServiceID, now time.Time) {
	name, ok := tracked[svcID]
	if !ok {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastActivation[name] = now
	c.published[name] = struct{}{}
	// A floor, not Set(1): draining connections can hold the scanned demand
	// above 1 and a signal must not lower it.
	g := c.metrics.Demand.WithLabelValues(name.Namespace(), name.Name())
	if g.Get() < 1 {
		g.Set(1)
	}
}

func (c *controller) scan(ctx context.Context) error {
	tracked := c.s2zMap.Tracked()

	// With nothing tracked, skip the potentially large dumps. publishDemand
	// still runs to prune series of services that just stopped being tracked.
	var counts map[loadbalancer.ServiceID]int
	if len(tracked) > 0 {
		var err error
		counts, err = c.countLiveConnections(tracked)
		if err != nil {
			return fmt.Errorf("scan conntrack for scale-to-zero demand: %w", err)
		}
	}
	c.publishDemand(tracked, counts, time.Now())
	return nil
}

// publishDemand aggregates per-id connection counts into per-service demand,
// holding it at >= 1 within the activation window, and prunes stale series.
func (c *controller) publishDemand(tracked map[loadbalancer.ServiceID]loadbalancer.ServiceName, counts map[loadbalancer.ServiceID]int, now time.Time) {
	// Aggregate over all (possibly expanded) ids of each service.
	perName := make(map[loadbalancer.ServiceName]int, len(tracked))
	for id, name := range tracked {
		perName[name] += counts[id]
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for name, live := range perName {
		demand := live
		if demand == 0 && now.Sub(c.lastActivation[name]) < activationHoldWindow {
			demand = 1
		}
		c.metrics.Demand.WithLabelValues(name.Namespace(), name.Name()).Set(float64(demand))
		c.published[name] = struct{}{}
	}

	// Prune series for services that are no longer tracked.
	for name := range c.published {
		if _, ok := perName[name]; ok {
			continue
		}
		c.metrics.Demand.DeleteLabelValues(name.Namespace(), name.Name())
		delete(c.published, name)
		delete(c.lastActivation, name)
	}
}

// countLiveConnections returns the number of live connections per tracked
// service id: service conntrack entries for north-south traffic, plus
// reverse-NAT sock map entries for socket-LB connections, which never create
// a service conntrack entry.
func (c *controller) countLiveConnections(tracked map[loadbalancer.ServiceID]loadbalancer.ServiceName) (map[loadbalancer.ServiceID]int, error) {
	counts := make(map[loadbalancer.ServiceID]int, len(tracked))
	if err := c.countServiceConntrack(tracked, counts); err != nil {
		return nil, err
	}
	if err := c.sockRevNat.addCounts(tracked, counts); err != nil {
		return nil, fmt.Errorf("scan reverse-NAT sock map for scale-to-zero demand: %w", err)
	}
	return counts, nil
}

// countServiceConntrack tallies live service conntrack entries per tracked
// service id. Closed or expired entries are skipped: they linger up to
// CT_SERVICE_LIFETIME_TCP (6h) and would stall scale-down until reaped.
func (c *controller) countServiceConntrack(tracked map[loadbalancer.ServiceID]loadbalancer.ServiceName, counts map[loadbalancer.ServiceID]int) error {
	now, err := ctCurTimeSeconds()
	if err != nil {
		// Without the conntrack clock, count all non-closed entries (as CT GC
		// does) rather than under-count and scale a busy service to zero.
		c.log.Warn("scale-to-zero: conntrack clock unavailable; counting all non-closed service entries",
			logfields.Error, err)
		now = 0
	}
	for _, m := range c.ctMaps.ActiveMaps() {
		derr := m.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
			key, ok := k.(ctmap.CtKey)
			if !ok || key.GetFlags()&tuple.TUPLE_F_SERVICE == 0 {
				return
			}
			entry, ok := v.(*ctmap.CtEntry)
			if !ok {
				return
			}
			id := loadbalancer.ServiceID(byteorder.NetworkToHost16(entry.RevNAT))
			if _, ok := tracked[id]; !ok || !serviceCTEntryLive(entry, now) {
				return
			}
			counts[id]++
		})
		if derr != nil {
			return fmt.Errorf("dump %s: %w", m.Name(), derr)
		}
	}
	return nil
}

// serviceCTEntryLive reports whether a service conntrack entry is neither past
// its GC expiry (now == 0 skips the check) nor closed in both directions,
// mirroring the datapath's ct_entry_alive() and the GC's expiry check.
func serviceCTEntryLive(e *ctmap.CtEntry, now uint32) bool {
	if now != 0 && e.Lifetime < now {
		return false
	}
	const bothClosing = ctmap.RxClosing | ctmap.TxClosing
	return e.Flags&bothClosing != bothClosing
}

// ctCurTimeSeconds returns the current conntrack time in the same clock and
// units as CtEntry.Lifetime.
func ctCurTimeSeconds() (uint32, error) {
	t, err := timestamp.GetCTCurTime(timestamp.GetClockSourceFromOptions())
	if err != nil {
		return 0, err
	}
	return uint32(t), nil
}

// sockRevNatCounter tallies live socket-LB connections of tracked services per
// service id, behind an interface so the scan can be tested without BPF maps.
type sockRevNatCounter interface {
	addCounts(tracked map[loadbalancer.ServiceID]loadbalancer.ServiceName, counts map[loadbalancer.ServiceID]int) error
}

// lbSockRevNat counts live socket-LB connections from the reverse-NAT sock
// maps, one entry per connection keyed by socket cookie. Only cookies that map
// to a live socket count: the datapath's sock_release hook does not fire when a
// pod's netns is torn down (and UDP never closes), so stale entries would
// otherwise pin demand above zero forever.
type lbSockRevNat struct {
	lb    lbmaps.LBMaps
	netns netnsOps
	log   *slog.Logger
}

func (s lbSockRevNat) addCounts(tracked map[loadbalancer.ServiceID]loadbalancer.ServiceName, counts map[loadbalancer.ServiceID]int) error {
	if s.lb == nil {
		return nil
	}
	m4, m6 := s.lb.SockRevNat()

	// Collect candidate (cookie, service-id) pairs first; counting is deferred
	// until we know which cookies are still live.
	type candidate struct {
		cookie uint64
		id     loadbalancer.ServiceID
	}
	var cands []candidate
	for _, m := range []*bpf.Map{m4, m6} {
		if m == nil {
			continue
		}
		err := m.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
			var cookie uint64
			switch key := k.(type) {
			case *lbmaps.SockRevNat4Key:
				cookie = key.Cookie
			case *lbmaps.SockRevNat6Key:
				cookie = key.Cookie
			default:
				return
			}
			var revNat uint16
			switch val := v.(type) {
			case *lbmaps.SockRevNat4Value:
				revNat = val.RevNatIndex
			case *lbmaps.SockRevNat6Value:
				revNat = val.RevNatIndex
			default:
				return
			}
			id := loadbalancer.ServiceID(byteorder.NetworkToHost16(revNat))
			if _, ok := tracked[id]; ok {
				cands = append(cands, candidate{cookie: cookie, id: id})
			}
		})
		if err != nil {
			return fmt.Errorf("dump %s: %w", m.Name(), err)
		}
	}
	if len(cands) == 0 {
		return nil
	}

	live, err := s.liveCookies()
	if err != nil {
		// If liveness cannot be established, count every candidate rather than
		// risk scaling a live service down. The next scan retries.
		s.log.Warn("scale-to-zero: could not enumerate live socket cookies; counting all sock rev-nat entries",
			logfields.Error, err)
		for _, c := range cands {
			counts[c.id]++
		}
		return nil
	}
	for _, c := range cands {
		if _, ok := live[c.cookie]; ok {
			counts[c.id]++
		}
	}
	return nil
}

// liveCookies returns the socket cookies of all UDP and TCP sockets across the
// host and pod network namespaces. Errors abort so the caller can fall back to
// counting all entries.
func (s lbSockRevNat) liveCookies() (map[uint64]struct{}, error) {
	live := make(map[uint64]struct{})
	gather := func() error {
		for _, fam := range []uint8{syscall.AF_INET, syscall.AF_INET6} {
			if err := sockets.GetSocketCookies(unix.IPPROTO_UDP, fam, sockets.StateFilterUDP, live); err != nil {
				return err
			}
			if err := sockets.GetSocketCookies(unix.IPPROTO_TCP, fam, sockets.StateFilterTCP, live); err != nil {
				return err
			}
		}
		return nil
	}

	hostNS, err := s.netns.current()
	if err != nil {
		return nil, fmt.Errorf("get host netns: %w", err)
	}
	if err := s.netns.do(hostNS, gather); err != nil {
		return nil, fmt.Errorf("enumerate host sockets: %w", err)
	}

	nsIter, errs := s.netns.all()
	if nsIter != nil {
		for _, ns := range nsIter {
			if err := s.netns.do(ns, gather); err != nil {
				return nil, fmt.Errorf("enumerate pod sockets: %w", err)
			}
		}
	}
	if errs != nil {
		// A namespace that vanished between listing and opening belongs to a
		// deleted pod with no live sockets. Treating it as fatal would push
		// nodes with pod churn onto the count-everything fallback.
		for err := range errs {
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return nil, fmt.Errorf("iterate netns: %w", err)
			}
		}
	}
	return live, nil
}
