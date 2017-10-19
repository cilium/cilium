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
	"net"
	"strconv"
	"time"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"

	log "github.com/sirupsen/logrus"
)

const (
	// GcInterval is the garbage collection interval.
	GcInterval int = 10
)

// RunGC run CT's garbage collector for the given endpoint. `isLocal` refers if
// the CT map is set to local. If `isIPv6` is set specifies that is the IPv6
// map. `filter` represents the filter type to be used while looping all CT
// entries.
func RunGC(e *endpoint.Endpoint, isLocal, isIPv6 bool, filter *ctmap.GCFilter) {
	var file string
	var mapType string
	// TODO: We need to optimize this a bit in future, so we traverse
	// the global table less often.

	// Use local or global conntrack maps depending on configuration settings.
	if isLocal {
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
		e.LogStatus(endpoint.BPF, endpoint.Warning, fmt.Sprintf("Unable to open CT map %s: %s", file, err))
		return
	}
	defer m.Close()

	// If LRUHashtable, no need to garbage collect as LRUHashtable cleans itself up.
	if m.MapInfo.MapType == bpf.MapTypeLRUHash {
		return
	}

	deleted := ctmap.GC(m, mapType, filter)

	if deleted > 0 {
		log.WithFields(log.Fields{
			logfields.Path:  file,
			"ctFilter.type": filter.TypeString(),
			"count":         deleted,
		}).Debug("Deleted filtered entries from map")
	}
}

// EnableConntrackGC enables the connection tracking garbage collection.
func EnableConntrackGC(ipv4, ipv6 bool) {
	go func() {
		seenGlobal := false
		sleepTime := time.Duration(GcInterval) * time.Second
		for {
			Mutex.RLock()

			for k := range Endpoints {
				e := Endpoints[k]
				e.Mutex.RLock()

				if e.Consumable == nil {
					e.Mutex.RUnlock()
					continue
				}

				// Only process global CT once per round.
				// We don't really care about which EP
				// triggers the traversal as long as we do
				// traverse it eventually. Update/delete
				// combo only serialized done from here,
				// so no extra mutex for global CT needed
				// right now. We still need to traverse
				// other EPs since some may not be part
				// of the global CT, but have a local one.
				isLocal := e.Opts.IsEnabled(endpoint.OptionConntrackLocal)
				if isLocal == false {
					if seenGlobal == true {
						e.Mutex.RUnlock()
						continue
					}
					seenGlobal = true
				}

				e.Mutex.RUnlock()
				// We can unlock the endpoint mutex sense
				// in runGC it will be locked as needed.
				if ipv6 {
					RunGC(e, isLocal, true, ctmap.NewGCFilterBy(ctmap.GCFilterByTime))
				}
				if ipv4 {
					RunGC(e, isLocal, false, ctmap.NewGCFilterBy(ctmap.GCFilterByTime))
				}
			}

			Mutex.RUnlock()
			time.Sleep(sleepTime)
			seenGlobal = false
		}
	}()
}

// RmCTEntriesOf cleans the connection tracking table of the given endpoint `e`
// by removing the CT's entries that have the src_sec_id equal to any of keys
// in the ids' map.
func RmCTEntriesOf(ipv4Enabled bool, e *endpoint.Endpoint, ids map[uint32]bool) {
	var eIPv4, eIPv6 net.IP

	e.Mutex.RLock()
	isLocal := e.Opts.IsEnabled(endpoint.OptionConntrackLocal)
	eIPv6 = e.IPv6.IP()
	if ipv4Enabled {
		eIPv4 = e.IPv4.IP()
	}
	// We can unlock the endpoint mutex since
	// in runGC it will be locked as needed.
	e.Mutex.RUnlock()

	gcFilter := ctmap.NewGCFilterBy(ctmap.GCFilterByID)
	gcFilter.IDsToRm = ids

	gcFilter.IP = eIPv6
	RunGC(e, isLocal, true, gcFilter)

	if ipv4Enabled {
		gcFilter.IP = eIPv4
		RunGC(e, isLocal, false, gcFilter)
	}
}
