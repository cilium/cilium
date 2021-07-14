// SPDX-License-Identifier: Apache-2.0
// Copyright 2018 Authors of Cilium

package option

var (
	endpointMutableOptionLibrary = OptionLibrary{
		ConntrackAccounting: &specConntrackAccounting,
		ConntrackLocal:      &specConntrackLocal,
		Conntrack:           &specConntrack,
		Debug:               &specDebug,
		DebugLB:             &specDebugLB,
		DebugPolicy:         &specDebugPolicy,
		DropNotify:          &specDropNotify,
		TraceNotify:         &specTraceNotify,
		PolicyVerdictNotify: &specPolicyVerdictNotify,
		PolicyAuditMode:     &specPolicyAuditMode,
		MonitorAggregation:  &specMonitorAggregation,
		NAT46:               &specNAT46,
	}
)

func GetEndpointMutableOptionLibrary() OptionLibrary {
	opt := OptionLibrary{}
	for k, v := range endpointMutableOptionLibrary {
		opt[k] = v
	}
	return opt
}
