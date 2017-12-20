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

package config

import (
	"github.com/cilium/cilium/pkg/option"
)

const (
	OptionAllowToHost         = "AllowToHost"
	OptionAllowToWorld        = "AllowToWorld"
	OptionConntrackAccounting = "ConntrackAccounting"
	OptionConntrackLocal      = "ConntrackLocal"
	OptionConntrack           = "Conntrack"
	OptionDebug               = "Debug"
	OptionDropNotify          = "DropNotification"
	OptionTraceNotify         = "TraceNotification"
	OptionNAT46               = "NAT46"
	OptionIngressPolicy       = "IngressPolicy"
	OptionEgressPolicy        = "EgressPolicy"
	OptionPolicyTracing       = "PolicyTracing"
	AlwaysEnforce             = "always"
	NeverEnforce              = "never"
	DefaultEnforcement        = "default"
)

// Available tunnel modes
const (
	TunnelModeVxlan  = "vxlan"
	TunnelModeGeneve = "geneve"
)

var (
	OptionSpecAllowToHost = option.Option{
		Define:      "ALLOW_TO_HOST",
		Immutable:   true,
		Description: "Allow all traffic to local host",
	}

	OptionSpecAllowToWorld = option.Option{
		Define:      "ALLOW_TO_WORLD",
		Immutable:   true,
		Description: "Allow all traffic to outside world",
	}

	OptionSpecConntrackAccounting = option.Option{
		Define:      "CONNTRACK_ACCOUNTING",
		Description: "Enable per flow (conntrack) statistics",
		Requires:    []string{OptionConntrack},
	}

	OptionSpecConntrackLocal = option.Option{
		Define:      "CONNTRACK_LOCAL",
		Description: "Use endpoint dedicated tracking table instead of global one",
		Requires:    []string{OptionConntrack},
	}

	OptionSpecConntrack = option.Option{
		Define:      "CONNTRACK",
		Description: "Enable stateful connection tracking",
	}

	OptionSpecDebug = option.Option{
		Define:      "DEBUG",
		Description: "Enable debugging trace statements",
	}

	OptionSpecDropNotify = option.Option{
		Define:      "DROP_NOTIFY",
		Description: "Enable drop notifications",
	}

	OptionSpecTraceNotify = option.Option{
		Define:      "TRACE_NOTIFY",
		Description: "Enable trace notifications",
	}

	OptionSpecNAT46 = option.Option{
		Define:      "ENABLE_NAT46",
		Description: "Enable automatic NAT46 translation",
		Requires:    []string{OptionConntrack},
	}

	OptionIngressSpecPolicy = option.Option{
		Define:      "POLICY_INGRESS",
		Description: "Enable ingress policy enforcement",
	}

	OptionEgressSpecPolicy = option.Option{
		Define:      "POLICY_EGRESS",
		Description: "Enable egress policy enforcement",
	}

	OptionSpecPolicyTracing = option.Option{
		Description: "Enable tracing when resolving policy (Debug)",
	}
)
