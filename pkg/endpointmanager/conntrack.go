// Copyright 2016-2018 Authors of Cilium
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

package endpointmanager

import (
	"fmt"
	"os"
	"time"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"

	"github.com/sirupsen/logrus"
)

const (
	// MinGcInterval is the minimum garbage collection interval.
	MinGcInterval int = 5
)

// runGC run CT's garbage collector for the given endpoint. `isLocal` refers if
// the CT map is set to local. If `isIPv6` is set specifies that is the IPv6
// map. `filter` represents the filter type to be used while looping all CT
// entries.
//
// The provided endpoint is optional; if it is provided, then its map will be
// garbage collected and any failures will be logged to the endpoint log.
// Otherwise it will garbage-collect the global map and use the global log.
func runGC(e *endpoint.Endpoint, ipv4, ipv6 bool, filter *ctmap.GCFilter) {
	var maps []*ctmap.Map

	if e == nil {
		maps = ctmap.GlobalMaps(ipv4, ipv6)
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
				scopedLog.Info(msg)
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
			log.WithFields(logrus.Fields{
				logfields.Path: path,
				"count":        deleted,
			}).Debug("Deleted filtered entries from map")
		}
	}
}

func createGCFilter(initialScan bool, restoredEndpoints []*endpoint.Endpoint) *ctmap.GCFilter {
	filter := &ctmap.GCFilter{
		RemoveExpired: true,
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

// EnableConntrackGC enables the connection tracking garbage collection.
func EnableConntrackGC(ipv4, ipv6 bool, gcinterval int, restoredEndpoints []*endpoint.Endpoint) {
	initialScan := true
	initialScanComplete := make(chan struct{})

	go func() {
		if gcinterval < MinGcInterval {
			gcinterval = MinGcInterval
			log.Warnf("Setting conntrack garbage collector interval to its minimum value(%d seconds)", gcinterval)
		}
		sleepTime := time.Duration(gcinterval) * time.Second
		for {
			eps := GetEndpoints()
			if len(eps) > 0 || initialScan {
				runGC(nil, ipv4, ipv6, createGCFilter(initialScan, restoredEndpoints))
			}
			for _, e := range eps {
				if !e.ConntrackLocal() {
					// Skip because GC was handled above.
					continue
				}
				runGC(e, ipv4, ipv6, &ctmap.GCFilter{RemoveExpired: true})
			}

			if initialScan {
				close(initialScanComplete)
				initialScan = false
			}

			time.Sleep(sleepTime)
		}
	}()

	select {
	case <-initialScanComplete:
		log.Info("Initial scan of connection tracking completed")
	case <-time.After(30 * time.Second):
		log.Fatal("Timeout while waiting for initial conntrack scan")
	}
}
