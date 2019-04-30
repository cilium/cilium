// Copyright 2017 Authors of Cilium
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

// +build linux

package bpf

import (
	"fmt"
	"unsafe"

	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/spanstat"

	"golang.org/x/sys/unix"
)

// attrProg holds values from the upstream struct union for BPF_*_GET_*_ID.
// From: https://github.com/torvalds/linux/blob/v4.19-rc2/include/uapi/linux/bpf.h#L358
type attrProg struct {
	progID    uint32 // union: start_id, prog_id, or map_id
	nextID    uint32
	openFlags uint32
}

// ProgInfo holds values from the upstream struct bpf_prog_info.
// From: https://github.com/torvalds/linux/blob/v4.19-rc2/include/uapi/linux/bpf.h#L2427
type ProgInfo struct {
	ProgType        uint32
	ID              uint32
	Tag             uint8
	JitedProgLen    uint32
	XlatedProgLen   uint32
	JitedProgInsns  uint64
	XlatedProgInsns uint64
	LoadTime        uint64 // ns since boottime
	CreatedByUID    uint32
	NRMapIDs        uint32
	MapIDs          []uint32
	Name            string
	IfIndex         uint32
	NetnsDev        uint64
	NetnsIno        uint64
	NrJitedKsyms    uint32
	NrJitedFuncLens uint32
	JitedKsyms      uint64
	JitedFuncLens   uint64
}

// attrObjInfo holds values from the upstream struct union for BPF_OBJ_GET_INFO_BY_FD.
// From: https://github.com/torvalds/linux/blob/v4.19-rc2/include/uapi/linux/bpf.h#L369
type attrObjInfo struct {
	bpfFD   uint32
	infoLen uint32
	info    uint64
}

// GetProgNextID takes a current program ID and returns the next program ID.
func GetProgNextID(current uint32) (uint32, error) {
	attr := attrProg{
		progID: current,
	}

	var duration *spanstat.SpanStat
	if option.Config.MetricsConfig.BPFSyscallDurationEnabled {
		duration = spanstat.Start()
	}
	ret, _, err := unix.Syscall(unix.SYS_BPF, BPF_PROG_GET_NEXT_ID, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if option.Config.MetricsConfig.BPFSyscallDurationEnabled {
		metrics.BPFSyscallDuration.WithLabelValues(metricOpProgGetNextID, metrics.Errno2Outcome(err)).Observe(duration.End(err == 0).Total().Seconds())
	}
	if ret != 0 || err != 0 {
		return 0, fmt.Errorf("Unable to get next id: %v", err)
	}

	return attr.nextID, nil
}

// GetProgFDByID returns the file descriptor for the program id.
func GetProgFDByID(id uint32) (int, error) {
	attr := attrProg{
		progID: uint32(uintptr(id)),
	}

	fd, _, err := unix.Syscall(unix.SYS_BPF, BPF_PROG_GET_FD_BY_ID, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if fd < 0 || err != 0 {
		return int(fd), fmt.Errorf("Unable to get fd for program id %d: %v", id, err)
	}

	return int(fd), nil
}

// GetProgInfoByFD gets the bpf program info from its file descriptor.
func GetProgInfoByFD(fd int) (ProgInfo, error) {
	info := ProgInfo{}
	attrInfo := attrObjInfo{
		bpfFD:   uint32(fd),
		infoLen: uint32(unsafe.Sizeof(info)),
		info:    uint64(uintptr(unsafe.Pointer(&info))),
	}
	// This struct must be in sync with union bpf_attr's anonymous struct
	attr := struct {
		info attrObjInfo
	}{
		info: attrInfo,
	}

	var duration *spanstat.SpanStat
	if option.Config.MetricsConfig.BPFSyscallDurationEnabled {
		duration = spanstat.Start()
	}
	ret, _, err := unix.Syscall(unix.SYS_BPF, BPF_OBJ_GET_INFO_BY_FD, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr))
	if option.Config.MetricsConfig.BPFSyscallDurationEnabled {
		metrics.BPFSyscallDuration.WithLabelValues(metricOpObjGetInfoByFD, metrics.Errno2Outcome(err)).Observe(duration.End(err == 0).Total().Seconds())
	}
	if ret != 0 || err != 0 {
		return ProgInfo{}, fmt.Errorf("Unable to get object info: %v", err)
	}

	return info, nil
}
