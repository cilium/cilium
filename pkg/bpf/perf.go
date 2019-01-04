// Copyright 2016-2018 Authors of Cilium
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

const (
	EventsMapName = "cilium_events"

	PERF_TYPE_HARDWARE   = 0
	PERF_TYPE_SOFTWARE   = 1
	PERF_TYPE_TRACEPOINT = 2
	PERF_TYPE_HW_CACHE   = 3
	PERF_TYPE_RAW        = 4
	PERF_TYPE_BREAKPOINT = 5

	PERF_SAMPLE_IP           = 1 << 0
	PERF_SAMPLE_TID          = 1 << 1
	PERF_SAMPLE_TIME         = 1 << 2
	PERF_SAMPLE_ADDR         = 1 << 3
	PERF_SAMPLE_READ         = 1 << 4
	PERF_SAMPLE_CALLCHAIN    = 1 << 5
	PERF_SAMPLE_ID           = 1 << 6
	PERF_SAMPLE_CPU          = 1 << 7
	PERF_SAMPLE_PERIOD       = 1 << 8
	PERF_SAMPLE_STREAM_ID    = 1 << 9
	PERF_SAMPLE_RAW          = 1 << 10
	PERF_SAMPLE_BRANCH_STACK = 1 << 11
	PERF_SAMPLE_REGS_USER    = 1 << 12
	PERF_SAMPLE_STACK_USER   = 1 << 13
	PERF_SAMPLE_WEIGHT       = 1 << 14
	PERF_SAMPLE_DATA_SRC     = 1 << 15
	PERF_SAMPLE_IDENTIFIER   = 1 << 16
	PERF_SAMPLE_TRANSACTION  = 1 << 17
	PERF_SAMPLE_REGS_INTR    = 1 << 18

	PERF_COUNT_SW_BPF_OUTPUT = 10
)
