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

var (
	// EndpointMutableOptionLibrary is the list of all mutable endpoint
	// options
	EndpointMutableOptionLibrary = option.OptionLibrary{
		OptionConntrackAccounting: &OptionSpecConntrackAccounting,
		OptionConntrackLocal:      &OptionSpecConntrackLocal,
		OptionConntrack:           &OptionSpecConntrack,
		OptionDebug:               &OptionSpecDebug,
		OptionDropNotify:          &OptionSpecDropNotify,
		OptionTraceNotify:         &OptionSpecTraceNotify,
		OptionNAT46:               &OptionSpecNAT46,
		OptionIngressPolicy:       &OptionIngressSpecPolicy,
		OptionEgressPolicy:        &OptionEgressSpecPolicy,
	}

	// EndpointOptionLibrary is the list of all mutable and non-mutable
	// endpoint options
	EndpointOptionLibrary = option.OptionLibrary{
		OptionAllowToHost:  &OptionSpecAllowToHost,
		OptionAllowToWorld: &OptionSpecAllowToWorld,
	}
)

func init() {
	for k, v := range EndpointMutableOptionLibrary {
		EndpointOptionLibrary[k] = v
	}
}
