// SPDX-License-Identifier: Apache-2.0
// Copyright 2016-2018 Authors of Cilium

package option

var (
	specPolicyTracing = Option{
		Description: "Enable tracing when resolving policy (Debug)",
	}

	// DaemonOptionLibrary is the daemon's option library that should be
	// used for read-only.
	DaemonOptionLibrary = OptionLibrary{
		PolicyTracing: &specPolicyTracing,
	}

	DaemonMutableOptionLibrary = OptionLibrary{
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

func init() {
	for k, v := range DaemonMutableOptionLibrary {
		DaemonOptionLibrary[k] = v
	}
}

// ParseDaemonOption parses a string as daemon option
func ParseDaemonOption(opt string) (string, OptionSetting, error) {
	return ParseOption(opt, &DaemonOptionLibrary)
}
