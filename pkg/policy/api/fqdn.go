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

package api

type FQDNSelector struct {
	MatchName string `json:"matchName,omitempty"`
}

// GetAsEndpointSelectors returns a FQDNSelector as a single EntityNone
// EndpointSelector slice.
// Note that toFQDNs behaves differently than most other rules. The presence of
// any toFQDNs rules means the endpoint must enforce policy, but the IPs are later
// added as toCIDRSet entries and processed as such.
func (s *FQDNSelector) GetAsEndpointSelectors() EndpointSelectorSlice {
	return []EndpointSelector{endpointSelectorNone}
}

// FQDNSelectorSlice is a wrapper type for []FQDNSelector to make is simpler to
// bind methods.
type FQDNSelectorSlice []FQDNSelector

// GetAsEndpointSelectors will return a single EntityNone if any
// toFQDNs rules exist, and a nil slice otherwise.
func (s FQDNSelectorSlice) GetAsEndpointSelectors() EndpointSelectorSlice {
	for _, rule := range s {
		return rule.GetAsEndpointSelectors()
	}
	return nil
}
