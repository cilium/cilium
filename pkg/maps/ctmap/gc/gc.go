// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gc

import (
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/inctimer"
	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/option"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "ct-gc")

// EndpointManager is any type which returns the list of Endpoints which are
// globally exposed on the current node.
type EndpointManager interface {
	GetEndpoints() []*endpoint.Endpoint
}

// Enable enables the connection tracking garbage collection.
// The restored endpoints and local node addresses are used to avoid GCing
// connections that may still be in use: connections of active endpoints and,
// in case the host firewall is enabled, connections of the local host.
func Enable(ipv4, ipv6 bool, restoredEndpoints []*endpoint.Endpoint, mgr EndpointManager,
	nodeAddressing types.NodeAddressing) {
	var (
		initialScan         = true
		initialScanComplete = make(chan struct{})
	)

	go func() {
		ipv4Orig := ipv4
		ipv6Orig := ipv6
		triggeredBySignal := false
		ctTimer, ctTimerDone := inctimer.New()
		defer ctTimerDone()
		for {
			var (
				maxDeleteRatio float64

				// epsMap contains an IP -> EP mapping. It is used by EmitCTEntryCB to
				// avoid doing mgr.LookupIP, which is more expensive.
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
			)

			eps := mgr.GetEndpoints()
			for _, e := range eps {
				epsMap[e.IPv4Address()] = e
				epsMap[e.IPv6Address()] = e
			}

			if len(eps) > 0 || initialScan {
				gcFilter := createGCFilter(initialScan, restoredEndpoints, emitEntryCB, nodeAddressing)
				maxDeleteRatio = runGC(nil, ipv4, ipv6, triggeredBySignal, gcFilter)
			}
			for _, e := range eps {
				if !e.ConntrackLocal() {
					// Skip because GC was handled above.
					continue
				}
				runGC(e, ipv4, ipv6, triggeredBySignal, &ctmap.GCFilter{RemoveExpired: true, EmitCTEntryCB: emitEntryCB})
			}

			// Mark the CT GC as over in each EP DNSZombies instance
			for _, e := range eps {
				e.MarkCTGCTime(gcStart)
			}

			if initialScan {
				close(initialScanComplete)
				initialScan = false
			}

			triggeredBySignal = false
			unmuteSignals()
			select {
			case x := <-wakeup:
				// mute before draining so that no more wakeups are queued just
				// after we have drained
				muteSignals()
				triggeredBySignal = true
				ipv4 = false
				ipv6 = false
				if x == SignalProtoV4 {
					ipv4 = true
				} else if x == SignalProtoV6 {
					ipv6 = true
				}
				// Drain current queue since we just woke up anyway.
				for len(wakeup) > 0 {
					x := <-wakeup
					if x == SignalProtoV4 {
						ipv4 = true
					} else if x == SignalProtoV6 {
						ipv6 = true
					}
				}
			case <-ctTimer.After(ctmap.GetInterval(maxDeleteRatio)):
				muteSignals()
				ipv4 = ipv4Orig
				ipv6 = ipv6Orig
			}
		}
	}()

	select {
	case <-initialScanComplete:
		log.Info("Initial scan of connection tracking completed")
	case <-time.After(30 * time.Second):
		log.Fatal("Timeout while waiting for initial conntrack scan")
	}
}

// runGC run CT's garbage collector for the given endpoint. `isLocal` refers if
// the CT map is set to local. If `isIPv6` is set specifies that is the IPv6
// map. `filter` represents the filter type to be used while looping all CT
// entries.
//
// The provided endpoint is optional; if it is provided, then its map will be
// garbage collected and any failures will be logged to the endpoint log.
// Otherwise it will garbage-collect the global map and use the global log.
func runGC(e *endpoint.Endpoint, ipv4, ipv6, triggeredBySignal bool, filter *ctmap.GCFilter) (maxDeleteRatio float64) {
	var maps []*ctmap.Map

	if e == nil {
		maps = ctmap.GlobalMaps(ipv4, ipv6)

		// We treat per-cluster CT Maps as global map. When we don't enable
		// cluster-aware addressing, ctmap.PerClusterCTMaps is nil (this is
		// the default).
		if ctmap.PerClusterCTMaps != nil {
			perClusterMaps, err := ctmap.PerClusterCTMaps.GetAllClusterCTMaps()
			if err != nil {
				log.Error("Failed to get per-cluster CT maps. Continue without them.")
			} else {
				maps = append(maps, perClusterMaps...)
			}
		}
	} else {
		maps = ctmap.LocalMaps(e, ipv4, ipv6)
	}
	for _, m := range maps {
		path, err := m.Path()
		if err == nil {
			err = m.Open()
		}
		if err != nil {
			msg := "Skipping CT garbage collection"
			scopedLog := log.WithError(err).WithField(logfields.Path, path)
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

		deleted := ctmap.GC(m, filter)

		if deleted > 0 {
			ratio := float64(deleted) / float64(m.MapInfo.MaxEntries)
			if ratio > maxDeleteRatio {
				maxDeleteRatio = ratio
			}
			log.WithFields(logrus.Fields{
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
			ctMapTCP, ctMapAny := ctmap.FilterMapsByProto(maps, vsn)
			stats := ctmap.PurgeOrphanNATEntries(ctMapTCP, ctMapAny)
			if stats != nil && (stats.EgressDeleted != 0 || stats.IngressDeleted != 0) {
				log.WithFields(logrus.Fields{
					"ingressDeleted": stats.IngressDeleted,
					"egressDeleted":  stats.EgressDeleted,
					"ingressAlive":   stats.IngressAlive,
					"egressAlive":    stats.EgressAlive,
					"ctMapIPVersion": vsn,
				}).Info("Deleted orphan SNAT entries from map")
			}
		}
	}

	return
}

func createGCFilter(initialScan bool, restoredEndpoints []*endpoint.Endpoint,
	emitEntryCB ctmap.EmitCTEntryCBFunc, nodeAddressing types.NodeAddressing) *ctmap.GCFilter {
	filter := &ctmap.GCFilter{
		RemoveExpired: true,
		EmitCTEntryCB: emitEntryCB,
	}

	// On the initial scan, scrub all IPs from the conntrack table which do
	// not belong to IPs of any endpoint that has been restored. No new
	// endpoints can appear yet so we can assume that any other entry not
	// belonging to a restored endpoint has become stale.
	if initialScan {
		filter.ValidIPs = map[netip.Addr]struct{}{}
		for _, ep := range restoredEndpoints {
			if ep.IsHost() {
				continue
			}
			if ep.IPv6.IsValid() {
				filter.ValidIPs[ep.IPv6] = struct{}{}
			}
			if ep.IPv4.IsValid() {
				filter.ValidIPs[ep.IPv4] = struct{}{}
			}
		}

		// Once the host firewall is enabled, we will start tracking (and
		// potentially enforcing policies) on all connections to and from the
		// host IP addresses. Thus, we also need to avoid GCing the host IPs.
		if option.Config.EnableHostFirewall {
			addrs, err := nodeAddressing.IPv4().LocalAddresses()
			if err != nil {
				log.WithError(err).Warning("Unable to list local IPv4 addresses")
			}
			addrsV6, err := nodeAddressing.IPv6().LocalAddresses()
			if err != nil {
				log.WithError(err).Warning("Unable to list local IPv6 addresses")
			}
			addrs = append(addrs, addrsV6...)

			for _, ip := range addrs {
				if option.Config.IsExcludedLocalAddress(ip) {
					continue
				}
				filter.ValidIPs[iputil.MustAddrFromIP(ip)] = struct{}{}
			}
		}
	}

	return filter
}
