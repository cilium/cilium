// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gc

import (
	"log/slog"
	"net/netip"
	"os"
	stdtime "time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/cilium/stream"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

// initialGCInterval sets the time after which the agent will begin to warn
// regarding a long ctmap gc duration.
const initialGCInterval = 30 * time.Second

// EndpointManager is any type which returns the list of Endpoints which are
// globally exposed on the current node.
type EndpointManager interface {
	GetEndpoints() []*endpoint.Endpoint
}

type PerClusterCTMapsRetriever func() []*ctmap.Map

type parameters struct {
	cell.In

	Lifecycle       cell.Lifecycle
	Logger          *slog.Logger
	MetricsRegistry *metrics.Registry
	DB              *statedb.DB
	NodeAddrs       statedb.Table[tables.NodeAddress]
	DaemonConfig    *option.DaemonConfig
	EndpointManager EndpointManager
	NodeAddressing  types.NodeAddressing
	SignalManager   SignalHandler

	PerClusterCTMapsRetriever PerClusterCTMapsRetriever `optional:"true"`
}

type GC struct {
	logger *slog.Logger

	ipv4 bool
	ipv6 bool

	metricsRegistry *metrics.Registry

	db        *statedb.DB
	nodeAddrs statedb.Table[tables.NodeAddress]

	endpointsManager EndpointManager
	signalHandler    SignalHandler

	perClusterCTMapsRetriever PerClusterCTMapsRetriever
	controllerManager         *controller.Manager

	observable4 stream.Observable[ctmap.GCEvent]
	next4       func(ctmap.GCEvent)
	complete4   func(error)

	observable6 stream.Observable[ctmap.GCEvent]
	next6       func(ctmap.GCEvent)
	complete6   func(error)
}

func New(params parameters) *GC {
	gc := &GC{
		logger:          params.Logger,
		metricsRegistry: params.MetricsRegistry,

		ipv4: params.DaemonConfig.EnableIPv4,
		ipv6: params.DaemonConfig.EnableIPv6,

		db:        params.DB,
		nodeAddrs: params.NodeAddrs,

		endpointsManager: params.EndpointManager,
		signalHandler:    params.SignalManager,

		controllerManager: controller.NewManager(),
	}

	gc.observable4, gc.next4, gc.complete4 = stream.Multicast[ctmap.GCEvent]()
	gc.observable6, gc.next6, gc.complete6 = stream.Multicast[ctmap.GCEvent]()

	params.Lifecycle.Append(cell.Hook{
		// OnStart not yet defined pending further modularization of CT map GC.
		OnStop: func(cell.HookContext) error {
			gc.controllerManager.RemoveAllAndWait()
			gc.complete4(nil)
			gc.complete6(nil)
			return nil
		},
	})
	return gc
}

// Enable enables the connection tracking garbage collection.
func (gc *GC) Enable() {
	var (
		initialScan         = true
		initialScanComplete = make(chan struct{})
	)

	go func() {
		ipv4 := gc.ipv4
		ipv6 := gc.ipv6
		triggeredBySignal := false
		var gcPrev time.Time
		for {
			var (
				maxDeleteRatio float64

				// epsMap contains an IP -> EP mapping. It is used by EmitCTEntryCB to
				// avoid doing gc.endpointsManager.LookupIP, which is more expensive.
				epsMap = make(map[netip.Addr]*endpoint.Endpoint)

				// gcStart and emitEntryCB are used to populate DNSZombieMapping fields
				// on endpoints. These hold IPs that are deletable in the DNS caches,
				// but may be in use by connections. Each loop of this GC keeps those
				// entries alive by touching them in emitEntryCB. We also need to
				// record the start of each CT GC loop (further below in the
				// goroutine). In all cases the timestamp used is the start of the GC
				// loop. This simplifies the logic to determine if a marked connection
				// was marked in the most recent GC loop or not: if the active
				// timestamp is before the recorded start of the GC loop then it must
				// mean the next iteration has completed and it is not in-use.
				gcStart = time.Now()

				// aliveTime is offset to the future by ToFQDNsIdleConnectionGracePeriod
				// (default 0), allowing previously active connections to be considerred
				// alive during idle periods of upto ToFQDNsIdleConnectionGracePeriod.
				aliveTime = gcStart.Add(option.Config.ToFQDNsIdleConnectionGracePeriod)

				emitEntryCB = func(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, nextHdr, flags uint8, entry *ctmap.CtEntry) {
					// FQDN related connections can only be outbound
					if flags != ctmap.TUPLE_F_OUT {
						return
					}
					if ep, exists := epsMap[srcIP]; exists {
						ep.MarkDNSCTEntry(dstIP, aliveTime)
					}
				}

				gcFilter = ctmap.GCFilter{
					RemoveExpired: true,
					EmitCTEntryCB: emitEntryCB}

				success = false
			)

			gcInterval := gcStart.Sub(gcPrev)
			if gcPrev.IsZero() {
				gcInterval = time.Duration(0)
			}
			gcPrev = gcStart

			eps := gc.endpointsManager.GetEndpoints()
			for _, e := range eps {
				epsMap[e.IPv4Address()] = e
				epsMap[e.IPv6Address()] = e
			}

			if len(eps) > 0 || initialScan {
				gc.logger.Info("Starting initial GC of connection tracking")
				maxDeleteRatio, success = gc.runGC(ipv4, ipv6, triggeredBySignal, gcFilter)
			}

			// Mark the CT GC as over in each EP DNSZombies instance, if we did a *full* GC run
			interval := ctmap.GetInterval(gc.logger, gcInterval, maxDeleteRatio)
			if success && ipv4 == gc.ipv4 && ipv6 == gc.ipv6 {
				for _, e := range eps {
					e.MarkCTGCTime(gcStart, time.Now().Add(interval))
				}
			}

			if initialScan {
				close(initialScanComplete)
				initialScan = false
				gc.logger.Info("initial gc of ct and nat maps completed",
					logfields.Duration, time.Since(gcStart),
				)
			}

			triggeredBySignal = false
			gc.signalHandler.UnmuteSignals()
			select {
			case x, ok := <-gc.signalHandler.Signals():
				if !ok {
					gc.logger.Info("Signal handler closed. Stopping conntrack garbage collector")
					return
				}
				// mute before draining so that no more wakeups are queued just
				// after we have drained
				gc.signalHandler.MuteSignals()
				triggeredBySignal = true
				ipv4 = false
				ipv6 = false
				if x == SignalProtoV4 {
					ipv4 = true
				} else if x == SignalProtoV6 {
					ipv6 = true
				}
				// Drain current queue since we just woke up anyway.
				for len(gc.signalHandler.Signals()) > 0 {
					x := <-gc.signalHandler.Signals()
					if x == SignalProtoV4 {
						ipv4 = true
					} else if x == SignalProtoV6 {
						ipv6 = true
					}
				}
			case <-time.After(interval):
				gc.signalHandler.MuteSignals()
				ipv4 = gc.ipv4
				ipv6 = gc.ipv6
			}
		}
	}()

	// Start a background go routine that waits to see if either the initial scan completes before
	// our expected time of 30 seconds.
	// This is to notify users of potential issues affecting initial scan performance.
	go func() {
		select {
		case <-initialScanComplete:
		case <-stdtime.After(initialGCInterval):
			gc.logger.Warn("Failed to perform initial ctmap gc scan within expected duration." +
				"This may be caused by large ctmap sizes or by constraint CPU resources upon start." +
				"Delayed initial ctmap scan may result in delayed map pressure metrics for ctmap.")
		}
	}()

	// Wait until after initial scan is complete prior to starting ctmap metrics controller.
	go func() {
		<-initialScanComplete
		gc.logger.Info("Initial scan of connection tracking completed, starting ctmap pressure metrics controller")
		// Not supporting BPF map pressure for local CT maps as of yet.
		ctmap.CalculateCTMapPressure(gc.controllerManager, gc.metricsRegistry, ctmap.GlobalMaps(gc.ipv4, gc.ipv6)...)
	}()
}

func (gc *GC) Run(m *ctmap.Map, filter ctmap.GCFilter) (int, error) {
	return ctmap.GC(m, filter, gc.next4, gc.next6)
}

func (gc *GC) Observe4() stream.Observable[ctmap.GCEvent] {
	return gc.observable4
}

func (gc *GC) Observe6() stream.Observable[ctmap.GCEvent] {
	return gc.observable6
}

// runGC run CT's garbage collector for the global map.
//
// If `isIPv6` is set specifies that is the IPv6 map. `filter` represents the
// filter type to be used while looping all CT entries.
func (gc *GC) runGC(ipv4, ipv6, triggeredBySignal bool, filter ctmap.GCFilter) (maxDeleteRatio float64, success bool) {
	success = true

	maps := ctmap.GlobalMaps(ipv4, ipv6)

	// We treat per-cluster CT Maps as global maps. When we don't enable
	// cluster-aware addressing, perClusterCTMapsRetriever is nil (default).
	if gc.perClusterCTMapsRetriever != nil {
		maps = append(maps, gc.perClusterCTMapsRetriever()...)
	}
	for _, m := range maps {
		path, err := ctmap.OpenCTMap(m)
		if err != nil {
			success = false
			msg := "Skipping CT garbage collection"
			if os.IsNotExist(err) {
				gc.logger.Debug(msg,
					logfields.Path, path,
					logfields.Error, err,
				)
			} else {
				gc.logger.Warn(msg,
					logfields.Path, path,
					logfields.Error, err,
				)
			}
			continue
		}
		defer m.Close()

		deleted, err := ctmap.GC(m, filter, gc.next4, gc.next6)
		if err != nil {
			gc.logger.Error("failed to perform CT garbage collection",
				logfields.Error, err,
			)
			success = false
		}

		if deleted > 0 {
			ratio := float64(deleted) / float64(m.MaxEntries())
			if ratio > maxDeleteRatio {
				maxDeleteRatio = ratio
			}
			gc.logger.Debug("Deleted filtered entries from map",
				logfields.Path, path,
				logfields.Count, deleted,
			)
		}
	}

	if triggeredBySignal {
		vsns := []ctmap.CTMapIPVersion{}
		if ipv4 {
			vsns = append(vsns, ctmap.CTMapIPv4)
		}
		if ipv6 {
			vsns = append(vsns, ctmap.CTMapIPv6)
		}

		for _, vsn := range vsns {
			startTime := time.Now()
			ctMapTCP, ctMapAny := ctmap.FilterMapsByProto(maps, vsn)
			stats := ctmap.PurgeOrphanNATEntries(ctMapTCP, ctMapAny)
			if stats != nil && (stats.EgressDeleted != 0 || stats.IngressDeleted != 0) {
				gc.logger.Info(
					"Deleted orphan SNAT entries from map",
					logfields.IngressDeleted, stats.IngressDeleted,
					logfields.EgressDeleted, stats.EgressDeleted,
					logfields.IngressAlive, stats.IngressAlive,
					logfields.EgressAlive, stats.EgressAlive,
					logfields.CTMapIPVersion, vsn,
					logfields.Duration, time.Since(startTime),
				)
			}
		}
	}

	return
}
