// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package option

const (
	PolicyTracing        = "PolicyTracing"
	Debug                = "Debug"
	DebugLB              = "DebugLB"
	DebugPolicy          = "DebugPolicy"
	DebugTagged          = "DebugTagged"
	DropNotify           = "DropNotification"
	TraceNotify          = "TraceNotification"
	TraceSockNotify      = "TraceSockNotification"
	PolicyVerdictNotify  = "PolicyVerdictNotification"
	PolicyAuditMode      = "PolicyAuditMode"
	MonitorAggregation   = "MonitorAggregationLevel"
	SourceIPVerification = "SourceIPVerification"
	AlwaysEnforce        = "always"
	NeverEnforce         = "never"
	DefaultEnforcement   = "default"
)

var (
	specDebug = Option{
		Define:      "DEBUG",
		Description: "Enable debugging trace statements",
	}

	specDebugLB = Option{
		Description: "Enable debugging trace statements for load balancer",
	}

	specDebugPolicy = Option{
		Define:      "POLICY_DEBUG",
		Description: "Enable debugging trace statements for policy enforcement",
	}

	specDebugTagged = Option{
		Define:      "DEBUG_TAGGED",
		Description: "Enable debugging trace statements for tagged packets",
	}

	specDropNotify = Option{
		Define:      "DROP_NOTIFY",
		Description: "Enable drop notifications",
	}

	specTraceNotify = Option{
		Define:      "TRACE_NOTIFY",
		Description: "Enable trace notifications",
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
