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

package monitor

// Must be synchronized with <bpf/lib/common.h>
const (
	// 0-128 are reserved for BPF datapath events
	MessageTypeUnspec = iota
	MessageTypeDrop
	MessageTypeDebug
	MessageTypeCapture
	MessageTypeTrace

	// 129-255 are reserved for agent level events

	// MessageTypeAccessLog contains a pkg/proxy/accesslog.LogRecord
	MessageTypeAccessLog = 129

	// MessageTypeAgent is an agent notification carrying a AgentNotify
	MessageTypeAgent = 130
)
