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

package bpf

// ProgType is an enumeration for valid BPF program types
type ProgType int

// This enumeration must be in sync with enum bpf_prog_type in <linux/bpf.h>
const (
	ProgTypeUnspec ProgType = iota
	ProgTypeSocketFilter
	ProgTypeKprobe
	ProgTypeSchedCls
	ProgTypeSchedAct
	ProgTypeTracepoint
	ProgTypeXdp
	ProgTypePerfEvent
	ProgTypeCgroupSkb
	ProgTypeCgroupSock
	ProgTypeLwtIn
	ProgTypeLwtOut
	ProgTypeLwtXmit
	ProgTypeSockOps
	ProgTypeSkSkb
	ProgTypeCgroupDevice
	ProgTypeSkMsg
	ProgTypeRawTracepoint
	ProgTypeCgroupSockAddr
	ProgTypeLwtSeg6Local
	ProgTypeLircMode2
	ProgTypeSkReusePort
)

func (t ProgType) String() string {
	switch t {
	case ProgTypeSocketFilter:
		return "Socket filter"
	case ProgTypeKprobe:
		return "Kprobe"
	case ProgTypeSchedCls:
		return "Sched CLS"
	case ProgTypeSchedAct:
		return "Sched ACT"
	case ProgTypeTracepoint:
		return "Tracepoint"
	case ProgTypeXdp:
		return "XDP"
	case ProgTypePerfEvent:
		return "Perf event"
	case ProgTypeCgroupSkb:
		return "Cgroup skb"
	case ProgTypeCgroupSock:
		return "Cgroup sock"
	case ProgTypeLwtIn:
		return "LWT in"
	case ProgTypeLwtOut:
		return "LWT out"
	case ProgTypeLwtXmit:
		return "LWT xmit"
	case ProgTypeSockOps:
		return "Sock ops"
	case ProgTypeSkSkb:
		return "Socket skb"
	case ProgTypeCgroupDevice:
		return "Cgroup device"
	case ProgTypeSkMsg:
		return "Socket msg"
	case ProgTypeRawTracepoint:
		return "Raw tracepoint"
	case ProgTypeCgroupSockAddr:
		return "Cgroup sockaddr"
	case ProgTypeLwtSeg6Local:
		return "LWT seg6local"
	case ProgTypeLircMode2:
		return "LIRC"
	case ProgTypeSkReusePort:
		return "Socket SO_REUSEPORT"
	}

	return "Unknown"
}
