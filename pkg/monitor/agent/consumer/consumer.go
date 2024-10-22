// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

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
