// Copyright 2020 Authors of Cilium
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

package consumer

// MonitorConsumer is a consumer of decoded monitor events
type MonitorConsumer interface {
	// NotifyAgentEvent informs the consumer about a new monitor event
	// sent from cilium-agent. The concrete type of the message parameter
	// depends on the value of typ:
	//  - MessageTypeAccessLog:		accesslog.LogRecord
	//  - MessageTypeAgent:			api.AgentNotify
	NotifyAgentEvent(typ int, message interface{})

	// NotifyPerfEvent informs the consumer about an datapath event obtained
	// via perf events ring buffer.
	// Data contains the raw binary encoded perf payload. The underlying type
	// depends on the value of typ:
	// 	- MessageTypeDrop:			monitor.DropNotify
	// 	- MessageTypeDebug:			monitor.DebugMsg
	// 	- MessageTypeCapture:		monitor.DebugCapture
	// 	- MessageTypeTrace:			monitor.TraceNotify
	// 	- MessageTypePolicyVerdict:	monitor.PolicyVerdictNotify
	NotifyPerfEvent(data []byte, cpu int)

	// NotifyPerfEventLost informs the consumer that a number of events have
	// been lost due to the perf event ring buffer not being read.
	NotifyPerfEventLost(numLostEvents uint64, cpu int)
}
