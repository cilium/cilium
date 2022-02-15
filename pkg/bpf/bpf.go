// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

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

	// BPF syscall attach types
	BPF_CGROUP_INET_INGRESS      = 0
	BPF_CGROUP_INET_EGRESS       = 1
	BPF_CGROUP_INET_SOCK_CREATE  = 2
	BPF_CGROUP_SOCK_OPS          = 3
	BPF_SK_SKB_STREAM_PARSER     = 4
	BPF_SK_SKB_STREAM_VERDICT    = 5
	BPF_CGROUP_DEVICE            = 6
	BPF_SK_MSG_VERDICT           = 7
	BPF_CGROUP_INET4_BIND        = 8
	BPF_CGROUP_INET6_BIND        = 9
	BPF_CGROUP_INET4_CONNECT     = 10
	BPF_CGROUP_INET6_CONNECT     = 11
	BPF_CGROUP_INET4_POST_BIND   = 12
	BPF_CGROUP_INET6_POST_BIND   = 13
	BPF_CGROUP_UDP4_SENDMSG      = 14
	BPF_CGROUP_UDP6_SENDMSG      = 15
	BPF_LIRC_MODE2               = 16
	BPF_FLOW_DISSECTOR           = 17
	BPF_CGROUP_SYSCTL            = 18
	BPF_CGROUP_UDP4_RECVMSG      = 19
	BPF_CGROUP_UDP6_RECVMSG      = 20
	BPF_CGROUP_INET4_GETPEERNAME = 29
	BPF_CGROUP_INET6_GETPEERNAME = 30
	BPF_CGROUP_INET4_GETSOCKNAME = 31
	BPF_CGROUP_INET6_GETSOCKNAME = 32

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
// support it. This does not take effect on existing map although some map
// types could be recreated later when objCheck() runs.
func EnableMapPreAllocation() {
	atomic.StoreUint32(&preAllocateMapSetting, 0)
}

// DisableMapPreAllocation disables BPF map pre-allocation as a default
// setting. Some map types enforces pre-alloc strategy so this does not
// take effect in that case. Also note that this does not take effect on
// existing map although could be recreated later when objCheck() runs.
func DisableMapPreAllocation() {
	atomic.StoreUint32(&preAllocateMapSetting, 1)
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
