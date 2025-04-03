// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package option

import "maps"

var (
	endpointMutableOptionLibrary = OptionLibrary{
		ConntrackAccounting:  &specConntrackAccounting,
		PolicyAccounting:     &specPolicyAccounting,
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
	return maps.Clone(endpointMutableOptionLibrary)
}
