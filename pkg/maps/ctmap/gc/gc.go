// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gc

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	stdtime "time"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/stream"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointstate"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/promise"
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

type AdditionalCTMapsFunc func() []ctmap.MapPair

type AdditionalCTMapsOut struct {
	cell.Out

	AdditionalCTMaps AdditionalCTMapsFunc `group:"ct-additional-maps"`
}

type parameters struct {
	cell.In

	Lifecycle               cell.Lifecycle
	JobGroup                job.Group
	Logger                  *slog.Logger
	Config                  config
	DB                      *statedb.DB
	NodeAddrs               statedb.Table[tables.NodeAddress]
	DaemonConfig            *option.DaemonConfig
	EndpointRestorerPromise promise.Promise[endpointstate.Restorer]
	EndpointManager         EndpointManager
	NodeAddressing          types.NodeAddressing
	SignalManager           SignalHandler
	CTMaps                  ctmap.CTMaps

	// AdditionalCTMaps contains optional additional CT maps that should be garbage collected.
	// Provide a AdditionalCTMapsOut struct to inject them.
	AdditionalCTMaps []AdditionalCTMapsFunc `group:"ct-additional-maps"`
}

type config struct {
	ConntrackGCInterval    time.Duration
	ConntrackGCMaxInterval time.Duration
}

func (r config) Flags(flags *pflag.FlagSet) {
	flags.Duration("conntrack-gc-interval", r.ConntrackGCInterval, "Overwrite the connection-tracking garbage collection interval")
	flags.Duration("conntrack-gc-max-interval", r.ConntrackGCMaxInterval, "Set the maximum interval for the connection-tracking garbage collection")
}

type GC struct {
	logger *slog.Logger
	config config

	ipv4 bool
	ipv6 bool

	db        *statedb.DB
	nodeAddrs statedb.Table[tables.NodeAddress]

	endpointsManager EndpointManager
	signalHandler    SignalHandler

	additionalCTMapsFns []AdditionalCTMapsFunc
	controllerManager   *controller.Manager

	ctMaps ctmap.CTMaps

	observable4 stream.Observable[ctmap.GCEvent]
	next4       func(ctmap.GCEvent)
	complete4   func(error)

	observable6 stream.Observable[ctmap.GCEvent]
	next6       func(ctmap.GCEvent)
	complete6   func(error)
}

func newGC(params parameters) *GC {
	gc := &GC{
		logger: params.Logger,
		config: params.Config,

		ipv4: params.DaemonConfig.EnableIPv4,
		ipv6: params.DaemonConfig.EnableIPv6,

		db:        params.DB,
		nodeAddrs: params.NodeAddrs,

		endpointsManager: params.EndpointManager,
		signalHandler:    params.SignalManager,
		ctMaps:           params.CTMaps,

		controllerManager: controller.NewManager(),

		additionalCTMapsFns: slices.DeleteFunc(
			params.AdditionalCTMaps,
			func(mapsFunc AdditionalCTMapsFunc) bool {
				return mapsFunc == nil
			},
		),
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

	enableGCFunc := func(ctx context.Context, _ cell.Health) error {
		params.Logger.Info("Starting connection tracking garbage collector")

		restorer, err := params.EndpointRestorerPromise.Await(ctx)
		if err != nil {
			return fmt.Errorf("failed to wait for endpoint restorer: %w", err)
		}

		if err := restorer.WaitForEndpointRestore(ctx); err != nil {
			return fmt.Errorf("failed to wait for endpoint restoration: %w", err)
		}

		gc.Enable()

		return nil
	}

	params.JobGroup.Add(
		job.Observer("nat-map-next4", func(ctx context.Context, event ctmap.GCEvent) error { ctmap.NatMapNext4(event); return nil }, gc.Observe4()),
		job.Observer("nat-map-next6", func(ctx context.Context, event ctmap.GCEvent) error { ctmap.NatMapNext6(event); return nil }, gc.Observe6()),
		job.OneShot("enable-gc", enableGCFunc))

	return gc
}

// A full GC pass is when we perform GC on any and all
// enabled IP families.
// Partial passes can happen as a result of datapath
// signals on particular families (i.e. ct or nat).
func (gc *GC) isFullGC(ipv4, ipv6 bool) bool {
	return ipv4 == gc.ipv4 && ipv6 == gc.ipv6
}

// Enable enables the periodic execution of the connection tracking garbage collection.
func (gc *GC) Enable() {
	gc.enableWithConfig(gc.runGC, true,
		gc.config.ConntrackGCInterval, gc.config.ConntrackGCMaxInterval,
		gcIntervalRounding, minGCInterval)
}

func (gc *GC) enableWithConfig(
	runGC func(ipv4, ipv6, triggeredBySignal bool, filter ctmap.GCFilter) (maxDeleteRatio float64, success bool),
	runMapPressureDaemon bool,
	conntrackGCInterval, conntrackGCMaxInterval, gcIntervalRounding, minGCInterval time.Duration,
) {
	var (
		initialScan         = true
		initialScanComplete = make(chan struct{})
	)

	go func() {
		ipv4 := gc.ipv4
		ipv6 := gc.ipv6
		triggeredBySignal := false
		var gcPrev time.Time
		var forceFullGCTTL time.Time
		var cachedGCInterval time.Duration
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

				emitEntryCB = func(srcIP, dstIP ctmap.NetAddr, srcPort, dstPort uint16, nextHdr, flags uint8, entry *ctmap.CtEntry) {
					// FQDN related connections can only be outbound
					if flags != ctmap.TUPLE_F_OUT {
						return
					}

					// Only consider IP addresses in default network
					if srcIP.NetID != 0 || dstIP.NetID != 0 {
						return
					}

					if ep, exists := epsMap[srcIP.Addr]; exists {
						ep.MarkDNSCTEntry(dstIP.Addr, aliveTime)
					}
				}

				gcFilter = ctmap.GCFilter{
					RemoveExpired: true,
					EmitCTEntryCB: emitEntryCB,
				}

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
				gc.logger.Info("Starting GC of connection tracking", logfields.First, initialScan)
				maxDeleteRatio, success = runGC(ipv4, ipv6, triggeredBySignal, gcFilter)
			}

			interval := getIntervalWithConfig(gc.logger, gcInterval, cachedGCInterval, maxDeleteRatio,
				conntrackGCInterval, conntrackGCMaxInterval, gcIntervalRounding, minGCInterval)
			if success && gc.isFullGC(ipv4, ipv6) {
				// Mark the CT GC as over in each EP DNSZombies instance, if we did a *full* GC run
				nextGCTime := time.Now().Add(interval)
				for _, e := range eps {
					e.MarkCTGCTime(gcStart, nextGCTime)
				}

				forceFullGCTTL = time.Now().Add(interval)
				// full pass so we reset our cached GC interval.
				cachedGCInterval = interval
			} else if !initialScan {
				// If we did not succeed, or it wasn't a full pass then we take the
				// minimum of the new interval and any remaining time on the last interval
				// clock - effectively running out the clock of the previous interval.
				// This is because in a partial GC pass one of the IP families has not been
				// tended to, so to avoid potentially starving GC on one of the IP families
				// we do this to ensure it is eventually run.
				forceInterval := max(0, time.Until(forceFullGCTTL))
				if forceInterval < interval {
					interval = forceInterval
				} else {
					// partial pass, but the new interval is less than any leftover ttl so
					// we cache this as well.
					cachedGCInterval = interval
				}
			}

			if initialScan {
				close(initialScanComplete)
				initialScan = false
				gc.logger.Info("initial gc of ct and nat maps completed",
					logfields.Duration, time.Since(gcStart),
				)
			} else {
				gc.logger.Debug("CT GC Run completed",
					logfields.Success, success,
					logfields.Duration, time.Since(gcStart),
					logfields.NextRunIn, interval)
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

	if runMapPressureDaemon {
		// Wait until after initial scan is complete prior to starting ctmap metrics controller.
		go func() {
			<-initialScanComplete
			gc.logger.Info("Initial scan of connection tracking completed, starting ctmap pressure metrics controller")
			// Not supporting BPF map pressure for per-cluster CT maps as of yet.
			gc.calculateCTMapPressure()
		}()
	}
}

func (gc *GC) Run(filter ctmap.GCFilter) (int, error) {
	totalDeleted := 0
	for _, m := range gc.ctMaps.ActiveMaps() {
		deleted, err := m.GC(filter, gc.next4, gc.next6)
		if err != nil {
			gc.logger.Error("failed to run GC on map",
				logfields.BPFMapName, m.Name(),
				logfields.Error, err,
			)
		}

		totalDeleted += deleted
	}

	return totalDeleted, nil
}

func (gc *GC) Observe4() stream.Observable[ctmap.GCEvent] {
	return gc.observable4
}

func (gc *GC) Observe6() stream.Observable[ctmap.GCEvent] {
	return gc.observable6
}

type gcMap struct {
	m                 *ctmap.Map
	openCloseRequired bool
}

// runGC run CT's garbage collector for the global map.
//
// If `isIPv6` is set specifies that is the IPv6 map. `filter` represents the
// filter type to be used while looping all CT entries.
func (gc *GC) runGC(ipv4, ipv6, triggeredBySignal bool, filter ctmap.GCFilter) (maxDeleteRatio float64, success bool) {
	success = true

	// maps defines the maps that need garbage collection.
	// The value defines whether the maps need to be opened and closed.
	maps := []*gcMap{}

	for _, m := range gc.ctMaps.ActiveMaps() {
		maps = append(maps, &gcMap{m: m, openCloseRequired: false})
	}

	// Inject additional maps (e.g. per cluster ID maps)
	for _, getMapPairs := range gc.additionalCTMapsFns {
		for _, mapPair := range getMapPairs() {
			maps = append(maps,
				&gcMap{m: mapPair.TCP, openCloseRequired: true},
				&gcMap{m: mapPair.Any, openCloseRequired: true})
		}
	}

	for _, gcMap := range maps {
		m := gcMap.m
		if gcMap.openCloseRequired {
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
		}

		deleted, err := m.GC(filter, gc.next4, gc.next6)
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
				logfields.Path, m.Name(),
				logfields.Count, deleted,
			)
		}
	}

	if triggeredBySignal {
		// This works under the assumption that [maps] contains consecutive pairs
		// of CT maps, respectively of TCP and ANY type, which is enforced for
		// additional maps injected above
		for i := 0; i+1 < len(maps); i += 2 {
			startTime := time.Now()
			ctMapTCP, ctMapAny := maps[i], maps[i+1]
			stats := ctmap.PurgeOrphanNATEntries(ctMapTCP.m, ctMapAny.m)
			if stats != nil && (stats.EgressDeleted != 0 || stats.IngressDeleted != 0) {
				gc.logger.Info(
					"Deleted orphan SNAT entries from map",
					logfields.IngressDeleted, stats.IngressDeleted,
					logfields.EgressDeleted, stats.EgressDeleted,
					logfields.IngressAlive, stats.IngressAlive,
					logfields.EgressAlive, stats.EgressAlive,
					logfields.Family, stats.Family,
					logfields.ClusterID, cmp.Or(stats.ClusterID, option.Config.ClusterID),
					logfields.Duration, time.Since(startTime),
				)
			}
		}
	}

	return
}

const ctmapPressureInterval = 30 * time.Second

// calculateCTMapPressure is a controller that calculates the BPF CT map
// pressure and pubishes it as part of the BPF map pressure metric.
func (gc *GC) calculateCTMapPressure() {
	ctx, cancel := context.WithCancelCause(context.Background())
	gc.controllerManager.UpdateController("ct-map-pressure", controller.ControllerParams{
		Group: controller.Group{
			Name: "ct-map-pressure",
		},
		DoFunc: func(context.Context) error {
			var errs error
			for _, m := range gc.ctMaps.ActiveMaps() {
				ctx, cancelCtx := context.WithTimeout(ctx, ctmapPressureInterval)
				defer cancelCtx()
				count, err := m.Count(ctx)
				if errors.Is(err, ebpf.ErrNotSupported) {
					// We don't have batch ops, so cancel context to kill this
					// controller.
					cancel(err)
					return err
				}
				if err != nil {
					errs = errors.Join(errs, fmt.Errorf("failed to dump CT map %v: %w", m.Name(), err))
				}
				m.UpdatePressureMetricWithSize(int32(count))
			}
			return errs
		},
		RunInterval: 30 * time.Second,
		Context:     ctx,
	})
}

// getIntervalWithConfig returns the interval adjusted based on the deletion ratio of the
// last run.
//   - actualPrevInterval 	= actual time elapsed since last GC.
//   - expectedPrevInterval 	= Is the last computed interval, which we expected to
//     wait *unless* a signal caused early pass. If this is set to zero then we use gc starting interval.
func getIntervalWithConfig(logger *slog.Logger, actualPrevInterval, expectedPrevInterval time.Duration, maxDeleteRatio float64,
	conntrackGCInterval, conntrackGCMaxInterval, gcIntervalRounding, minGCInterval time.Duration,
) time.Duration {
	if val := conntrackGCInterval; val != time.Duration(0) {
		return val
	}

	adjustedDeleteRatio := maxDeleteRatio
	if expectedPrevInterval == time.Duration(0) {
		expectedPrevInterval = defaults.ConntrackGCStartingInterval
	} else if actualPrevInterval < expectedPrevInterval && actualPrevInterval > 0 {
		adjustedDeleteRatio *= float64(expectedPrevInterval) / float64(actualPrevInterval)
	}

	newInterval := calculateIntervalWithConfig(expectedPrevInterval, adjustedDeleteRatio, gcIntervalRounding, minGCInterval)
	if val := conntrackGCMaxInterval; val != time.Duration(0) && newInterval > val {
		newInterval = val
	}

	if newInterval != expectedPrevInterval {
		logger.Info(
			"Conntrack garbage collector interval recalculated",
			logfields.ExpectedPrevInterval, expectedPrevInterval,
			logfields.ActualPrevInterval, actualPrevInterval,
			logfields.NewInterval, newInterval,
			logfields.DeleteRatio, maxDeleteRatio,
			logfields.AdjustedDeleteRatio, adjustedDeleteRatio,
		)
	}

	metrics.ConntrackInterval.WithLabelValues("global").Set(newInterval.Seconds())

	return newInterval
}

const (
	minGCInterval      = defaults.ConntrackGCMinInterval
	gcIntervalRounding = time.Second
)

func calculateIntervalWithConfig(prevInterval time.Duration, maxDeleteRatio float64, gcIntervalRounding, minGCInterval time.Duration) time.Duration {
	if maxDeleteRatio == 0.0 {
		return prevInterval
	}

	switch {
	case maxDeleteRatio > 0.25:
		if maxDeleteRatio > 0.9 {
			maxDeleteRatio = 0.9
		}
		// 25%..90% => 1.3x..10x shorter
		return max(time.Duration(float64(prevInterval)*(1.0-maxDeleteRatio)).Round(gcIntervalRounding), minGCInterval)
	case maxDeleteRatio < 0.05:
		// When less than 5% of entries were deleted, increase the
		// interval. Use a simple 1.5x multiplier to start growing slowly
		// as a new node may not be seeing workloads yet and thus the
		// scan will return a low deletion ratio at first.
		return min(time.Duration(float64(prevInterval)*1.5).Round(gcIntervalRounding), defaults.ConntrackGCMaxLRUInterval)
	}

	return prevInterval
}
