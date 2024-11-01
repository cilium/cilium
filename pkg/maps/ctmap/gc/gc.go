// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gc

import (
	"fmt"
	"net/netip"
	"os"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

// initialGCInterval sets the time after which the agent will begin to warn
// regarding a long ctmap gc duration.
const initialGCInterval = 30 * time.Second

type Enabler interface {
	// Enable enables the connection tracking garbage collection.
	Enable()
}

// EndpointManager is any type which returns the list of Endpoints which are
// globally exposed on the current node.
type EndpointManager interface {
	GetEndpoints() []*endpoint.Endpoint
}

type PerClusterCTMapsRetriever func() []*ctmap.Map

type parameters struct {
	cell.In

	Lifecycle       cell.Lifecycle
	Logger          logrus.FieldLogger
	DB              *statedb.DB
	NodeAddrs       statedb.Table[tables.NodeAddress]
	DaemonConfig    *option.DaemonConfig
	EndpointManager EndpointManager
	NodeAddressing  types.NodeAddressing
	SignalManager   SignalHandler

	PerClusterCTMapsRetriever PerClusterCTMapsRetriever `optional:"true"`
}

type GC struct {
	logger logrus.FieldLogger

	ipv4 bool
	ipv6 bool

	db        *statedb.DB
	nodeAddrs statedb.Table[tables.NodeAddress]

	endpointsManager EndpointManager
	signalHandler    SignalHandler

	perClusterCTMapsRetriever PerClusterCTMapsRetriever
	controllerManager         *controller.Manager
}

func New(params parameters) *GC {
	gc := &GC{
		logger: params.Logger,

		ipv4: params.DaemonConfig.EnableIPv4,
		ipv6: params.DaemonConfig.EnableIPv6,

		db:        params.DB,
		nodeAddrs: params.NodeAddrs,

		endpointsManager: params.EndpointManager,
		signalHandler:    params.SignalManager,

		controllerManager: controller.NewManager(),
	}
	params.Lifecycle.Append(cell.Hook{
		// OnStart not yet defined pending further modularization of CT map GC.
		OnStop: func(cell.HookContext) error {
			gc.controllerManager.RemoveAllAndWait()
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
		ctTimer, ctTimerDone := inctimer.New()
		var gcPrev time.Time
		defer ctTimerDone()
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
				maxDeleteRatio, success = gc.runGC(nil, ipv4, ipv6, triggeredBySignal, gcFilter)
			}
			for _, e := range eps {
				if !e.ConntrackLocal() {
					// Skip because GC was handled above.
					continue
				}
				_, epSuccess := gc.runGC(e, ipv4, ipv6, triggeredBySignal, gcFilter)
				success = success && epSuccess
			}

			// Mark the CT GC as over in each EP DNSZombies instance, if we did a *full* GC run
			interval := ctmap.GetInterval(gcInterval, maxDeleteRatio)
			if success && ipv4 == gc.ipv4 && ipv6 == gc.ipv6 {
				for _, e := range eps {
					e.MarkCTGCTime(gcStart, time.Now().Add(interval))
				}
			}

			if initialScan {
				close(initialScanComplete)
				initialScan = false
				gc.logger.WithField("duration", time.Since(gcStart)).
					Info("initial gc of ct and nat maps completed")
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
			case <-ctTimer.After(interval):
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
		case <-inctimer.After(initialGCInterval):
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
		ctmap.CalculateCTMapPressure(gc.controllerManager, ctmap.GlobalMaps(gc.ipv4, gc.ipv6)...)
	}()
}

// runGC run CT's garbage collector for the given endpoint. `isLocal` refers if
// the CT map is set to local. If `isIPv6` is set specifies that is the IPv6
// map. `filter` represents the filter type to be used while looping all CT
// entries.
//
// The provided endpoint is optional; if it is provided, then its map will be
// garbage collected and any failures will be logged to the endpoint log.
// Otherwise it will garbage-collect the global map and use the global log.
func (gc *GC) runGC(e *endpoint.Endpoint, ipv4, ipv6, triggeredBySignal bool, filter ctmap.GCFilter) (maxDeleteRatio float64, success bool) {
	var maps []*ctmap.Map
	success = true

	if e == nil {
		maps = ctmap.GlobalMaps(ipv4, ipv6)

		// We treat per-cluster CT Maps as global maps. When we don't enable
		// cluster-aware addressing, perClusterCTMapsRetriever is nil (default).
		if gc.perClusterCTMapsRetriever != nil {
			maps = append(maps, gc.perClusterCTMapsRetriever()...)
		}
	} else {
		maps = ctmap.LocalMaps(e, ipv4, ipv6)
	}
	for _, m := range maps {
		path, err := ctmap.OpenCTMap(m)
		if err != nil {
			success = false
			msg := "Skipping CT garbage collection"
			scopedLog := gc.logger.WithError(err).WithField(logfields.Path, path)
			if os.IsNotExist(err) {
				scopedLog.Debug(msg)
			} else {
				scopedLog.Warn(msg)
			}
			if e != nil {
				e.LogStatus(endpoint.BPF, endpoint.Warning, fmt.Sprintf("%s: %s", msg, err))
			}
			continue
		}
		defer m.Close()

		deleted, err := ctmap.GC(m, filter)
		if err != nil {
			gc.logger.WithError(err).Error("failed to perform CT garbage collection")
			success = false
		}

		if deleted > 0 {
			ratio := float64(deleted) / float64(m.MaxEntries())
			if ratio > maxDeleteRatio {
				maxDeleteRatio = ratio
			}
			gc.logger.WithFields(logrus.Fields{
				logfields.Path: path,
				"count":        deleted,
			}).Debug("Deleted filtered entries from map")
		}
	}

	if e == nil && triggeredBySignal {
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
				gc.logger.WithFields(logrus.Fields{
					"ingressDeleted": stats.IngressDeleted,
					"egressDeleted":  stats.EgressDeleted,
					"ingressAlive":   stats.IngressAlive,
					"egressAlive":    stats.EgressAlive,
					"ctMapIPVersion": vsn,
					"duration":       time.Since(startTime),
				}).Info("Deleted orphan SNAT entries from map")
			}
		}
	}

	return
}

type fakeCTMapGC struct{}

func NewFake() Enabler { return fakeCTMapGC{} }

func (fakeCTMapGC) Enable() {}
