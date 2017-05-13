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

package api

import (
	"github.com/cilium/cilium/pkg/labels"
)

// EndpointSelector is a list of labels selecting an endpoint
// TODO: Use k8s podSelector
type EndpointSelector labels.LabelArray

// ParseEndpointSelector parses a list of labels in the format of
// strings and returns an EndpointSelector
func ParseEndpointSelector(list ...string) EndpointSelector {
	array := make([]*labels.Label, len(list))
	for i := range list {
		array[i] = labels.ParseLabel(list[i])
	}
	return array
}
