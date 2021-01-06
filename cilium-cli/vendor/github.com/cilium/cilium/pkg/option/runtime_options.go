// Copyright 2018-2019 Authors of Cilium
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

package option

import (
	"errors"

	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
)

const (
	PolicyTracing       = "PolicyTracing"
	ConntrackAccounting = "ConntrackAccounting"
	ConntrackLocal      = "ConntrackLocal"
	Conntrack           = "Conntrack"
	Debug               = "Debug"
	DebugLB             = "DebugLB"
	DebugPolicy         = "DebugPolicy"
	DropNotify          = "DropNotification"
	TraceNotify         = "TraceNotification"
	PolicyVerdictNotify = "PolicyVerdictNotification"
	PolicyAuditMode     = "PolicyAuditMode"
	MonitorAggregation  = "MonitorAggregationLevel"
	NAT46               = "NAT46"
	AlwaysEnforce       = "always"
	NeverEnforce        = "never"
	DefaultEnforcement  = "default"
)

var (
	ErrNAT46ReqIPv4 = errors.New("NAT46 requires IPv4 to be enabled")
	ErrNAT46ReqIPv6 = errors.New("NAT46 requires IPv6 to be enabled")
	ErrNAT46ReqVeth = errors.New("NAT46 not supported in ipvlan datapath mode")
)

var (
	specConntrackAccounting = Option{
		Define:      "CONNTRACK_ACCOUNTING",
		Description: "Enable per flow (conntrack) statistics",
		Requires:    []string{Conntrack},
	}

	specConntrackLocal = Option{
		Define:      "CONNTRACK_LOCAL",
		Description: "Use endpoint dedicated tracking table instead of global one",
		Requires:    []string{Conntrack},
	}

	specConntrack = Option{
		Define:      "CONNTRACK",
		Description: "Enable stateful connection tracking",
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

	specNAT46 = Option{
		Define:      "ENABLE_NAT46",
		Description: "Enable automatic NAT46 translation",
		Requires:    []string{Conntrack},
		Verify: func(key string, val string) error {
			opt, err := NormalizeBool(val)
			if err != nil {
				return err
			}
			if opt == OptionEnabled {
				if !Config.EnableIPv4 {
					return ErrNAT46ReqIPv4
				}
				if !Config.EnableIPv6 {
					return ErrNAT46ReqIPv6
				}
				if Config.DatapathMode == datapathOption.DatapathModeIpvlan {
					return ErrNAT46ReqVeth
				}
			}
			return nil
		},
	}
)
