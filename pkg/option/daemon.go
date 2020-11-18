// Copyright 2016-2018 Authors of Cilium
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
