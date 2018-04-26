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

package endpoint

import (
	"fmt"

	"github.com/cilium/cilium/pkg/option"
)

const (
	OptionConntrackAccounting = "ConntrackAccounting"
	OptionConntrackLocal      = "ConntrackLocal"
	OptionConntrack           = "Conntrack"
	OptionDebug               = "Debug"
	OptionDebugLB             = "DebugLB"
	OptionDropNotify          = "DropNotification"
	OptionTraceNotify         = "TraceNotification"
	OptionNAT46               = "NAT46"
	OptionIngressPolicy       = "IngressPolicy"
	OptionEgressPolicy        = "EgressPolicy"
	AlwaysEnforce             = "always"
	NeverEnforce              = "never"
	DefaultEnforcement        = "default"
)

var (
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

	OptionSpecDebugLB = option.Option{
		Define:      "LB_DEBUG",
		Description: "Enable debugging trace statements for load balancer",
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
		Verify: func(key string, val bool) error {
			if !IPv4Enabled {
				return fmt.Errorf("NAT46 requires IPv4 to be enabled")
			}
			return nil
		},
	}

	OptionIngressSpecPolicy = option.Option{
		Define:      "POLICY_INGRESS",
		Description: "Enable ingress policy enforcement",
	}

	OptionEgressSpecPolicy = option.Option{
		Define:      "POLICY_EGRESS",
		Description: "Enable egress policy enforcement",
	}

	EndpointMutableOptionLibrary = option.OptionLibrary{
		OptionConntrackAccounting: &OptionSpecConntrackAccounting,
		OptionConntrackLocal:      &OptionSpecConntrackLocal,
		OptionConntrack:           &OptionSpecConntrack,
		OptionDebug:               &OptionSpecDebug,
		OptionDebugLB:             &OptionSpecDebugLB,
		OptionDropNotify:          &OptionSpecDropNotify,
		OptionTraceNotify:         &OptionSpecTraceNotify,
		OptionNAT46:               &OptionSpecNAT46,
		OptionIngressPolicy:       &OptionIngressSpecPolicy,
		OptionEgressPolicy:        &OptionEgressSpecPolicy,
	}

	EndpointOptionLibrary = option.OptionLibrary{}
)

func (e *Endpoint) SetDefaultOpts(opts *option.BoolOptions) {
	if e.Opts == nil {
		e.Opts = option.NewBoolOptions(&EndpointOptionLibrary)
	}
	if e.Opts.Library == nil {
		e.Opts.Library = &EndpointOptionLibrary
	}

	if opts != nil {
		for k := range EndpointMutableOptionLibrary {
			e.Opts.Set(k, opts.IsEnabled(k))
		}
	}
}

// applyOptsLocked applies the given options to the endpoint's options and
// returns true if there were any options changed.
func (e *Endpoint) applyOptsLocked(opts map[string]string) bool {
	return e.Opts.Apply(opts, optionChanged, e) > 0
}

// optionChanged is a callback used with pkg/option to apply the options to an
// endpoint.  Not used for anything at the moment.
func optionChanged(key string, value bool, data interface{}) {
}
