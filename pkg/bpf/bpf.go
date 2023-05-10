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
	// Flags for BPF_MAP_CREATE. Must match values from linux/bpf.h
	BPF_F_NO_PREALLOC = 1 << 0
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
