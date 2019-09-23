// Copyright 2019 Authors of Cilium
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

package events

import (
	"runtime"
	"sync"
	"unsafe"

	oldBPF "github.com/cilium/cilium/pkg/bpf"

	"github.com/cilium/ebpf"
)

const (
	eventsMapName = "cilium_events"
)

var (
	// eventsMapTemplate corresponds to EVENTS_MAP in "bpf/lib/events.h".
	eventsMapTemplate *ebpf.MapABI
	initABIOnce       sync.Once
)

func OpenMap() (*ebpf.Map, error) {
	initABIOnce.Do(func() {
		eventsMapTemplate = &ebpf.MapABI{
			Type:      ebpf.PerfEventArray,
			KeySize:   uint32(unsafe.Sizeof(uint32(0))),
			ValueSize: uint32(unsafe.Sizeof(uint32(0))),
			// TODO: Remove runtime.NumCPU() dependency
			// https://github.com/cilium/ebpf/pull/7#discussion_r329560441
			MaxEntries: uint32(runtime.NumCPU()),
		}
	})
	path := oldBPF.MapPath(eventsMapName)
	return ebpf.LoadPinnedMapExplicit(path, eventsMapTemplate)
}
