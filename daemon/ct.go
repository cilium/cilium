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
	"os"
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

func runGC(e *endpoint.Endpoint, nameLocal string, nameGlobal string, ctType ctmap.CtType) {
	var file string

	// TODO: We need to optimize this a bit in future, so we traverse
	// the global table less often.

	if (e.Opts.IsEnabled(endpoint.OptionConntrackLocal)) {
		file = bpf.MapPath(nameLocal + strconv.Itoa(int(e.ID)))
	} else {
		file = bpf.MapPath(nameGlobal)
	}
	fd, err := bpf.ObjGet(file)
	if err != nil {
		log.Warningf("Unable to open CT map %s: %s\n", file, err)
		e.LogStatus(endpoint.BPF, endpoint.Warning, fmt.Sprintf("Unable to open CT map %s: %s", file, err))
		return
	}

	info, err := bpf.GetMapInfo(os.Getpid(), fd)
	if err != nil {
		log.Warningf("Unable to open CT map's fdinfo %s: %s\n", file, err)
	}

	if info.MapType == bpf.MapTypeLRUHash {
		return
	}

	f := os.NewFile(uintptr(fd), file)
	m := ctmap.CtMap{Fd: fd, Type: ctType}

	deleted := m.GC(uint16(GcInterval))
	if deleted > 0 {
		log.Debugf("Deleted %d entries from map %s", deleted, file)
	}

	f.Close()
}

// EnableConntrackGC enables the connection tracking garbage collection.
func (d *Daemon) EnableConntrackGC() {
	go func() {
		for {
			sleepTime := time.Duration(GcInterval) * time.Second

			d.endpointsMU.Lock()

			for k := range d.endpoints {
				e := d.endpoints[k]
				if e.Consumable == nil {
					continue
				}

                                runGC(e, ctmap.MapName6, ctmap.MapName6Global, ctmap.CtTypeIPv6)
				if !d.conf.IPv4Disabled {
                                	runGC(e, ctmap.MapName4, ctmap.MapName4Global, ctmap.CtTypeIPv4)
				}
			}

			d.endpointsMU.Unlock()
			time.Sleep(sleepTime)
		}
	}()
}
