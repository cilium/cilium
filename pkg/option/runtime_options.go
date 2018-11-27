// Copyright 2018 Authors of Cilium
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
)

const (
	PolicyTracing       = "PolicyTracing"
	ConntrackAccounting = "ConntrackAccounting"
	ConntrackLocal      = "ConntrackLocal"
	Conntrack           = "Conntrack"
	Debug               = "Debug"
	DebugLB             = "DebugLB"
	DropNotify          = "DropNotification"
	TraceNotify         = "TraceNotification"
	MonitorAggregation  = "MonitorAggregationLevel"
	NAT46               = "NAT46"
	IngressPolicy       = "IngressPolicy"
	EgressPolicy        = "EgressPolicy"
	AlwaysEnforce       = "always"
	NeverEnforce        = "never"
	DefaultEnforcement  = "default"

	// HTTP403Message specifies the response body for 403 responses, defaults to "Access denied"
	HTTP403Message = "http-403-msg"
	// HTTPRequestTimeout specifies the time in seconds after which forwarded requests time out
	HTTPRequestTimeout = "http-request-timeout"
	// HTTPIdleTimeout spcifies the time in seconds if http stream being idle after which the
	// request times out
	HTTPIdleTimeout = "http-idle-timeout"
	// HTTPMaxGRPCTimeout specifies the maximum time in seconds that limits the values of
	// "grpc-timeout" headers being honored.
	HTTPMaxGRPCTimeout = "http-max-grpc-timeout"
	// HTTPRetryCount specifies the number of retries performed after a forwarded request fails
	HTTPRetryCount = "http-retry-count"
	// HTTPRetryTimeout is the time in seconds before an uncompleted request is retried.
	HTTPRetryTimeout = "http-retry-timeout"
	// ProxyConnectTimeout specifies the time in seconds after which a TCP connection attempt
	// is considered timed out
	ProxyConnectTimeout = "proxy-connect-timeout"
)

var (
	ErrNAT46ReqIPv4 = errors.New("NAT46 requires IPv4 to be enabled")
	IPv4Disabled    = false
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

	specDropNotify = Option{
		Define:      "DROP_NOTIFY",
		Description: "Enable drop notifications",
	}

	specTraceNotify = Option{
		Define:      "TRACE_NOTIFY",
		Description: "Enable trace notifications",
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
			if IPv4Disabled {
				return ErrNAT46ReqIPv4
			}
			return nil
		},
	}

	IngressSpecPolicy = Option{
		Define:      "POLICY_INGRESS",
		Description: "Enable ingress policy enforcement",
	}

	EgressSpecPolicy = Option{
		Define:      "POLICY_EGRESS",
		Description: "Enable egress policy enforcement",
	}
)
