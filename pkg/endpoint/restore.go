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
	"github.com/cilium/cilium/pkg/option"
)

// deprecatedOptions represents the 'Opts' field in the Endpoint structure from
// Cilium 1.1 or earlier.
type deprecatedOptions struct {
	Opts map[string]bool `json:"map"`
}

// convertOptions handles backwards compatibility for the 'Opts' field.
//
// In Cilium 1.2, the ep.Opts became ep.Options and its internal storage type
// was converted from map[string]bool to map[string]int. To allow downgrade, we
// must populate the older Opts field based on the newer Options field.
//
// Consider deprecating in the Cilium 1.5 cycle or later.
func convertOptions(opts option.OptionMap) map[string]bool {
	result := make(map[string]bool, len(opts))
	for k, v := range opts {
		switch v {
		case option.OptionDisabled:
			result[k] = false
		case option.OptionEnabled:
			result[k] = true
		}
	}
	return result
}

// transformEndpointForDowngrade modifies the specified endpoint to populate
// deprecated fields so that when the endpoint is serialized, an older version
// of Cilium will understand the format. This allows safe downgrade from this
// version to an older version.
func transformEndpointForDowngrade(ep *Endpoint) {
	ep.DeprecatedOpts.Opts = convertOptions(ep.Options.Opts)
}
