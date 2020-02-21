// Copyright 2016-2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gc

import (
	"fmt"
	"net"
	"os"
	"time"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/signal"
	"github.com/sirupsen/logrus"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "ct-gc")

// EndpointManager is any type which returns the list of Endpoints which are
// globally exposed on the current node.
type EndpointManager interface {
	GetEndpoints() []*endpoint.Endpoint
}

// Enable enables the connection tracking garbage collection.
func Enable(ipv4, ipv6 bool, restoredEndpoints []*endpoint.Endpoint, mgr EndpointManager) {
	var (
		initialScan         = true
		initialScanComplete = make(chan struct{})
		mapType             bpf.MapType
	)

	go func() {
		var wakeup = make(chan signal.SignalData)
		ipv4Orig := ipv4
		ipv6Orig := ipv6
		for {
			var (
				maxDeleteRatio float64

				// epsMap contains an IP -> EP mapping. It is used by EmitCTEntryCB to
				// avoid doing mgr.LookupIP, which is more expensive.
				epsMap = make(map[string]*endpoint.Endpoint)

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

				emitEntryCB = func(srcIP, dstIP net.IP, srcPort, dstPort uint16, nextHdr, flags uint8, entry *ctmap.CtEntry) {
					// FQDN related connections can only be outbound
					if flags != ctmap.TUPLE_F_OUT {
						return
					}
					if ep, exists := epsMap[srcIP.String()]; exists {
						ep.MarkDNSCTEntry(dstIP, gcStart)
					}
				}
			)

			eps := mgr.GetEndpoints()
			for _, e := range eps {
				epsMap[e.GetIPv4Address()] = e
				epsMap[e.GetIPv6Address()] = e
			}

			if len(eps) > 0 || initialScan {
				mapType, maxDeleteRatio = runGC(nil, ipv4, ipv6, createGCFilter(initialScan, restoredEndpoints, emitEntryCB))
			}
			for _, e := range eps {
				if !e.ConntrackLocal() {
					// Skip because GC was handled above.
					continue
				}
				runGC(e, ipv4, ipv6, &ctmap.GCFilter{RemoveExpired: true, EmitCTEntryCB: emitEntryCB})
			}

			// Mark the CT GC as over in each EP DNSZombies instance
			for _, e := range eps {
				e.MarkCTGCTime(gcStart)
			}

			if initialScan {
				close(initialScanComplete)
				initialScan = false

				signal.RegisterChannel(signal.SignalNatFillUp, wakeup)
				signal.SetupSignalListener()
				signal.MuteChannel(signal.SignalNatFillUp)
			}

			signal.UnmuteChannel(signal.SignalNatFillUp)
			select {
			case x := <-wakeup:
				ipv4 = false
				ipv6 = false
				if x == signal.SignalNatV4 {
					ipv4 = true
				} else if x == signal.SignalNatV6 {
					ipv6 = true
				}
				// Drain current queue since we just woke up anyway.
				for len(wakeup) > 0 {
					x := <-wakeup
					if x == signal.SignalNatV4 {
						ipv4 = true
					} else if x == signal.SignalNatV6 {
						ipv6 = true
					}
				}
			case <-time.After(ctmap.GetInterval(mapType, maxDeleteRatio)):
				ipv4 = ipv4Orig
				ipv6 = ipv6Orig
			}
			signal.MuteChannel(signal.SignalNatFillUp)
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
func runGC(e *endpoint.Endpoint, ipv4, ipv6 bool, filter *ctmap.GCFilter) (mapType bpf.MapType, maxDeleteRatio float64) {
	var maps []*ctmap.Map

	// We don't need to check for LRU hashmap support to run the garbage collector.
	if e == nil {
		maps = ctmap.GlobalMaps(ipv4, ipv6, true)
	} else {
		maps = ctmap.LocalMaps(e, ipv4, ipv6, true)
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

		mapType = m.MapInfo.MapType

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

	return
}

func createGCFilter(initialScan bool, restoredEndpoints []*endpoint.Endpoint, emitEntryCB ctmap.EmitCTEntryCBFunc) *ctmap.GCFilter {
	filter := &ctmap.GCFilter{
		RemoveExpired: true,
		EmitCTEntryCB: emitEntryCB,
	}

	// On the initial scan, scrub all IPs from the conntrack table which do
	// not belong to IPs of any endpoint that has been restored. No new
	// endpoints can appear yet so we can assume that any other entry not
	// belonging to a restored endpoint has become stale.
	if initialScan {
		filter.ValidIPs = map[string]struct{}{}
		for _, ep := range restoredEndpoints {
			filter.ValidIPs[ep.IPv6.String()] = struct{}{}
			filter.ValidIPs[ep.IPv4.String()] = struct{}{}
		}
	}

	return filter
}
