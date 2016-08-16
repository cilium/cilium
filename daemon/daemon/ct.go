//
// Copyright 2016 Authors of Cilium
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
//
package daemon

import (
	"os"
	"strconv"
	"time"

	"github.com/cilium/cilium/bpf/ctmap"
	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/common/bpf"
	"github.com/cilium/cilium/common/types"
)

const (
	GcInterval int = 10
)

func runGC(e *types.Endpoint, prefix string, ctType ctmap.CtType) {
	file := prefix + strconv.Itoa(int(e.ID))
	fd, err := bpf.ObjGet(file)
	if err != nil {
		log.Warningf("Unable to open CT map %s: %s\n", file, err)
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

func (d *Daemon) EnableConntrackGC() {
	go func() {
		for {
			sleepTime := time.Duration(GcInterval) * time.Second

			d.endpointsMU.Lock()

			for k, _ := range d.endpoints {
				e := d.endpoints[k]
				if e.Consumable == nil {
					continue
				}

				runGC(e, common.BPFMapCT6, ctmap.CtTypeIPv6)
				runGC(e, common.BPFMapCT4, ctmap.CtTypeIPv4)
			}

			d.endpointsMU.Unlock()
			time.Sleep(sleepTime)
		}
	}()
}
