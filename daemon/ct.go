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

package main

import (
	"fmt"
	"strconv"
	"time"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/maps/ctmap"
)

const (
	// GcInterval is the garbage collection interval.
	GcInterval int = 10
)

func runGC(e *endpoint.Endpoint, isIPv6 bool) {
	var file string
	var mapType string
	// TODO: We need to optimize this a bit in future, so we traverse
	// the global table less often.

	// Use local or global conntrack maps depending on configuration settings.
	if e.Opts.IsEnabled(endpoint.OptionConntrackLocal) {
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
	defer m.Close()

	if err != nil {
		log.Warningf("Unable to open map %s: %s", file, err)
		e.LogStatus(endpoint.BPF, endpoint.Warning, fmt.Sprintf("Unable to open CT map %s: %s", file, err))
	}

	// If LRUHashtable, no need to garbage collect as LRUHashtable cleans itself up.
	if m.MapInfo.MapType == bpf.MapTypeLRUHash {
		return
	}

	deleted := ctmap.GC(m, uint16(GcInterval), mapType)

	if deleted > 0 {
		log.Debugf("Deleted %d entries from map %s", deleted, file)
	}
}

// EnableConntrackGC enables the connection tracking garbage collection.
func (d *Daemon) EnableConntrackGC() {
	go func() {
		for {
			sleepTime := time.Duration(GcInterval) * time.Second

			d.endpointsMU.RLock()

			for k := range d.endpoints {
				e := d.endpoints[k]
				e.Mutex.RLock()
				if e.Consumable == nil {
					e.Mutex.RUnlock()
					continue
				}
				e.Mutex.RUnlock()
				// We can unlock the endpoint mutex sense
				// in runGC it will be locked as needed.
				runGC(e, true)
				if !d.conf.IPv4Disabled {
					runGC(e, false)
				}
			}

			d.endpointsMU.RUnlock()
			time.Sleep(sleepTime)
		}
	}()
}
