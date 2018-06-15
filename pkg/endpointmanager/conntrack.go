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
	"strconv"
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

// RunGC run CT's garbage collector for the given endpoint. `isLocal` refers if
// the CT map is set to local. If `isIPv6` is set specifies that is the IPv6
// map. `filter` represents the filter type to be used while looping all CT
// entries.
//
// The provided endpoint is optional; if it is provided, then its map will be
// garbage collected and any failures will be logged to the endpoint log.
// Otherwise it will garbage-collect the global map and use the global log.
func RunGC(e *endpoint.Endpoint, isIPv6 bool, filter *ctmap.GCFilter) {
	var file string
	var mapType string

	// Choose whether to garbage collect the local or global conntrack map
	if e != nil {
		if isIPv6 {
			mapType = ctmap.MapName6
		} else {
			mapType = ctmap.MapName4
		}
		file = bpf.MapPath(mapType + strconv.Itoa(int(e.ID)))
	} else {
		if isIPv6 {
			mapType = ctmap.MapName6Global
		} else {
			mapType = ctmap.MapName4Global
		}
		file = bpf.MapPath(mapType)
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

// EnableConntrackGC enables the connection tracking garbage collection.
func EnableConntrackGC(ipv4, ipv6 bool) {
	go func() {
		sleepTime := time.Duration(GcInterval) * time.Second
		for {
			eps := GetEndpoints()
			if len(eps) > 0 {
				if ipv6 {
					RunGC(nil, true, ctmap.NewGCFilterBy(ctmap.GCFilterByTime))
				}
				if ipv4 {
					RunGC(nil, false, ctmap.NewGCFilterBy(ctmap.GCFilterByTime))
				}
			}
			for _, e := range eps {
				if !e.ConntrackLocal() {
					// Skip because GC was handled above.
					continue
				}
				if ipv6 {
					RunGC(e, true, ctmap.NewGCFilterBy(ctmap.GCFilterByTime))
				}
				if ipv4 {
					RunGC(e, false, ctmap.NewGCFilterBy(ctmap.GCFilterByTime))
				}
			}
			time.Sleep(sleepTime)
		}
	}()
}
