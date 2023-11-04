// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package option

const (
	PolicyTracing        = "PolicyTracing"
	ConntrackAccounting  = "ConntrackAccounting"
	ConntrackLocal       = "ConntrackLocal"
	Debug                = "Debug"
	DebugLB              = "DebugLB"
	DebugPolicy          = "DebugPolicy"
	DropNotify           = "DropNotification"
	TraceNotify          = "TraceNotification"
	TraceSockNotify      = "TraceSockNotification"
	PolicyVerdictNotify  = "PolicyVerdictNotification"
	PolicyAuditMode      = "PolicyAuditMode"
	PolicyAccounting     = "PolicyAccounting"
	MonitorAggregation   = "MonitorAggregationLevel"
	SourceIPVerification = "SourceIPVerification"
	AlwaysEnforce        = "always"
	NeverEnforce         = "never"
	DefaultEnforcement   = "default"
)

var (
	specConntrackAccounting = Option{
		Define:      "CONNTRACK_ACCOUNTING",
		Description: "Enable per flow (conntrack) statistics",
		Requires:    nil,
	}

	specConntrackLocal = Option{
		Define:      "CONNTRACK_LOCAL",
		Description: "Use endpoint dedicated tracking table instead of global one",
		Requires:    nil,
	}

	specDebug = Option{
		Define:      "DEBUG",
		Description: "Enable debugging trace statements",
	}

	specDebugLB = Option{
		Define:      "LB_DEBUG",
		Description: "Enable debugging trace statements for load balancer",
	}

	specDebugPolicy = Option{
		Define:      "POLICY_DEBUG",
		Description: "Enable debugging trace statements for policy enforcement",
	}

	specDropNotify = Option{
		Define:      "DROP_NOTIFY",
		Description: "Enable drop notifications",
	}

	specTraceNotify = Option{
		Define:      "TRACE_NOTIFY",
		Description: "Enable trace notifications",
	}

	specPolicyAccounting = Option{
		Define:      "POLICY_ACCOUNTING",
		Description: "Enable policy accounting ",
	}

	specPolicyVerdictNotify = Option{
		Define:      "POLICY_VERDICT_NOTIFY",
		Description: "Enable policy verdict notifications",
	}

	specPolicyAuditMode = Option{
		Define:      "POLICY_AUDIT_MODE",
		Description: "Enable audit mode for policies",
	}

	specMonitorAggregation = Option{
		Define:      "MONITOR_AGGREGATION",
		Description: "Set the level of aggregation for monitor events in the datapath",
		Verify:      VerifyMonitorAggregationLevel,
		Parse:       ParseMonitorAggregationLevel,
		Format:      FormatMonitorAggregationLevel,
	}

	specSourceIPVerification = Option{
		Define:      "ENABLE_SIP_VERIFICATION",
		Description: "Enable the check of the source IP on pod egress",
	}
)
