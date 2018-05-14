// Copyright 2016-2017 Authors of Cilium
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

package options

import (
	"github.com/cilium/cilium/pkg/option"
)

const (
	PolicyTracing = "PolicyTracing"
)

var (
	SpecPolicyTracing = option.Option{
		Description: "Enable tracing when resolving policy (Debug)",
	}

	Library = option.OptionLibrary{
		PolicyTracing: &SpecPolicyTracing,
	}

	DaemonMutableOptionLibrary = option.OptionLibrary{
		option.ConntrackAccounting: &option.SpecConntrackAccounting,
		option.ConntrackLocal:      &option.SpecConntrackLocal,
		option.Conntrack:           &option.SpecConntrack,
		option.Debug:               &option.SpecDebug,
		option.DebugLB:             &option.SpecDebugLB,
		option.DropNotify:          &option.SpecDropNotify,
		option.TraceNotify:         &option.SpecTraceNotify,
		option.NAT46:               &option.SpecNAT46,
	}
)

// Parse a string as daemon option
func Parse(opt string) (string, bool, error) {
	return option.ParseOption(opt, &Library)
}

func init() {
	for k, v := range DaemonMutableOptionLibrary {
		Library[k] = v
	}
}
