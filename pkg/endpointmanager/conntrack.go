// Copyright 2016-2017 Authors of Cilium
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
	"time"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"

	"github.com/sirupsen/logrus"
)

const (
	// GcInterval is the garbage collection interval.
	GcInterval int = 60
)

// runGC run CT's garbage collector for the given endpoint. `isLocal` refers if
// the CT map is set to local. If `isIPv6` is set specifies that is the IPv6
// map. `filter` represents the filter type to be used while looping all CT
// entries.
//
// The provided endpoint is optional; if it is provided, then its map will be
// garbage collected and any failures will be logged to the endpoint log.
// Otherwise it will garbage-collect the global map and use the global log.
func runGC(e *endpoint.Endpoint, isIPv6 bool, filter *ctmap.GCFilter) {
	var file string
	var mapType string

	// Even if the pointer points to nil, passing it directly to a function
	// that receives an interface doesn't pass the nil through, so to avoid
	// a segfault we check the pointer and directly pass nil here.
	if e == nil {
		mapType, file = ctmap.GetMapTypeAndPath(nil, isIPv6)
	} else {
		mapType, file = ctmap.GetMapTypeAndPath(e, isIPv6)
	}
	m, err := bpf.OpenMap(file)
	if err != nil {
		log.WithError(err).WithField(logfields.Path, file).Warn("Unable to open map")
		if e != nil {
			e.LogStatus(endpoint.BPF, endpoint.Warning, fmt.Sprintf("Unable to open CT map %s: %s", file, err))
		}
		return
	}
	defer m.Close()

	deleted := ctmap.GC(m, mapType, filter)

	if deleted > 0 {
		log.WithFields(logrus.Fields{
			logfields.Path:  file,
			"ctFilter.type": filter.TypeString(),
			"count":         deleted,
		}).Debug("Deleted filtered entries from map")
	}
}

func createGCFilter(ipv6, initialScan bool, restoredEndpoints []*endpoint.Endpoint) *ctmap.GCFilter {
	filter := ctmap.NewGCFilterBy(ctmap.GCFilterByTime)

	// On the initial scan, scrub all IPs from the conntrack table which do
	// not belong to IPs of any endpoint that has been restored. No new
	// endpoints can appear yet so we can assume that any other entry not
	// belonging to a restored endpoint has become stale.
	if initialScan {
		filter.ValidIPs = map[string]struct{}{}
		for _, ep := range restoredEndpoints {
			if ipv6 {
				filter.ValidIPs[ep.IPv6.String()] = struct{}{}
			} else {
				filter.ValidIPs[ep.IPv4.String()] = struct{}{}
			}
		}
	}

	return filter
}

// EnableConntrackGC enables the connection tracking garbage collection.
func EnableConntrackGC(ipv4, ipv6 bool, gcinterval int, restoredEndpoints []*endpoint.Endpoint) {
	initialScan := true
	initialScanComplete := make(chan struct{})

	go func() {
		sleepTime := time.Duration(GcInterval) * time.Second
		for {
			eps := GetEndpoints()
			if len(eps) > 0 || initialScan {
				if ipv6 {
					runGC(nil, true, createGCFilter(true, initialScan, restoredEndpoints))
				}

				if ipv4 {
					runGC(nil, false, createGCFilter(false, initialScan, restoredEndpoints))
				}
			}
			for _, e := range eps {
				if !e.ConntrackLocal() {
					// Skip because GC was handled above.
					continue
				}
				if ipv6 {
					runGC(e, true, ctmap.NewGCFilterBy(ctmap.GCFilterByTime))
				}
				if ipv4 {
					runGC(e, false, ctmap.NewGCFilterBy(ctmap.GCFilterByTime))
				}
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
