// Copyright 2016-2019 Authors of Cilium
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

package bpf

import (
	"sync/atomic"

	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "bpf")

	preAllocateMapSetting uint32 = BPF_F_NO_PREALLOC
)

const (
	// BPF map type constants. Must match enum bpf_map_type from linux/bpf.h
	BPF_MAP_TYPE_UNSPEC              = 0
	BPF_MAP_TYPE_HASH                = 1
	BPF_MAP_TYPE_ARRAY               = 2
	BPF_MAP_TYPE_PROG_ARRAY          = 3
	BPF_MAP_TYPE_PERF_EVENT_ARRAY    = 4
	BPF_MAP_TYPE_PERCPU_HASH         = 5
	BPF_MAP_TYPE_PERCPU_ARRAY        = 6
	BPF_MAP_TYPE_STACK_TRACE         = 7
	BPF_MAP_TYPE_CGROUP_ARRAY        = 8
	BPF_MAP_TYPE_LRU_HASH            = 9
	BPF_MAP_TYPE_LRU_PERCPU_HASH     = 10
	BPF_MAP_TYPE_LPM_TRIE            = 11
	BPF_MAP_TYPE_ARRAY_OF_MAPS       = 12
	BPF_MAP_TYPE_HASH_OF_MAPS        = 13
	BPF_MAP_TYPE_DEVMAP              = 14
	BPF_MAP_TYPE_SOCKMAP             = 15
	BPF_MAP_TYPE_CPUMAP              = 16
	BPF_MAP_TYPE_XSKMAP              = 17
	BPF_MAP_TYPE_SOCKHASH            = 18
	BPF_MAP_TYPE_CGROUP_STORAGE      = 19
	BPF_MAP_TYPE_REUSEPORT_SOCKARRAY = 20

	// BPF syscall command constants. Must match enum bpf_cmd from linux/bpf.h
	BPF_MAP_CREATE          = 0
	BPF_MAP_LOOKUP_ELEM     = 1
	BPF_MAP_UPDATE_ELEM     = 2
	BPF_MAP_DELETE_ELEM     = 3
	BPF_MAP_GET_NEXT_KEY    = 4
	BPF_PROG_LOAD           = 5
	BPF_OBJ_PIN             = 6
	BPF_OBJ_GET             = 7
	BPF_PROG_ATTACH         = 8
	BPF_PROG_DETACH         = 9
	BPF_PROG_TEST_RUN       = 10
	BPF_PROG_GET_NEXT_ID    = 11
	BPF_MAP_GET_NEXT_ID     = 12
	BPF_PROG_GET_FD_BY_ID   = 13
	BPF_MAP_GET_FD_BY_ID    = 14
	BPF_OBJ_GET_INFO_BY_FD  = 15
	BPF_PROG_QUERY          = 16
	BPF_RAW_TRACEPOINT_OPEN = 17
	BPF_BTF_LOAD            = 18
	BPF_BTF_GET_FD_BY_ID    = 19
	BPF_TASK_FD_QUERY       = 20

	// Flags for BPF_MAP_UPDATE_ELEM. Must match values from linux/bpf.h
	BPF_ANY     = 0
	BPF_NOEXIST = 1
	BPF_EXIST   = 2

	// Flags for BPF_MAP_CREATE. Must match values from linux/bpf.h
	BPF_F_NO_PREALLOC   = 1 << 0
	BPF_F_NO_COMMON_LRU = 1 << 1
	BPF_F_NUMA_NODE     = 1 << 2

	// Flags for BPF_PROG_QUERY
	BPF_F_QUERY_EFFECTVE = 1 << 0

	// Flags for accessing BPF object
	BPF_F_RDONLY = 1 << 3
	BPF_F_WRONLY = 1 << 4

	// Flag for stack_map, store build_id+offset instead of pointer
	BPF_F_STACK_BUILD_ID = 1 << 5
)

// EnableMapPreAllocation enables BPF map pre-allocation on map types that
// support it.
func EnableMapPreAllocation() {
	atomic.StoreUint32(&preAllocateMapSetting, 0)
}

// GetPreAllocateMapFlags returns the map flags for map which use conditional
// pre-allocation.
func GetPreAllocateMapFlags(t MapType) uint32 {
	switch {
	case !t.allowsPreallocation():
		return BPF_F_NO_PREALLOC
	case t.requiresPreallocation():
		return 0
	}
	return atomic.LoadUint32(&preAllocateMapSetting)
}
