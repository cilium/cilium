// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package option

var (
	endpointMutableOptionLibrary = OptionLibrary{
		ConntrackAccounting:  &specConntrackAccounting,
		ConntrackLocal:       &specConntrackLocal,
		Debug:                &specDebug,
		DebugLB:              &specDebugLB,
		DebugPolicy:          &specDebugPolicy,
		DropNotify:           &specDropNotify,
		TraceNotify:          &specTraceNotify,
		PolicyVerdictNotify:  &specPolicyVerdictNotify,
		PolicyAuditMode:      &specPolicyAuditMode,
		MonitorAggregation:   &specMonitorAggregation,
		SourceIPVerification: &specSourceIPVerification,
	}
)

func GetEndpointMutableOptionLibrary() OptionLibrary {
	opt := OptionLibrary{}
	for k, v := range endpointMutableOptionLibrary {
		opt[k] = v
	}
	return opt
}
