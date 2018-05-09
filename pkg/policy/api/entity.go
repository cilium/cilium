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

package api

import (
	"github.com/cilium/cilium/pkg/labels"
)

// Entity specifies the class of receiver/sender endpoints that do not have
// individual identities.  Entities are used to describe "outside of cluster",
// "host", etc.
type Entity string

const (
	// EntityAll is an entity that represents all traffic
	EntityAll Entity = "all"

	// EntityWorld is an entity that represents traffic external to
	// endpoint's cluster
	EntityWorld Entity = "world"

	// EntityCluster is an entity that represents traffic within the
	// endpoint's cluster, to endpoints not managed by cilium
	EntityCluster Entity = "cluster"

	// EntityHost is an entity that represents traffic within endpoint host
	EntityHost Entity = "host"

	// EntityInit is an entity that represents an initializing endpoint
	EntityInit Entity = "init"
)

// EntitySelectorMapping maps special entity names that come in policies to
// selectors
var EntitySelectorMapping = map[Entity]EndpointSelector{
	EntityAll: WildcardEndpointSelector,
	EntityWorld: NewESFromLabels(&labels.Label{
		Key:    labels.IDNameWorld,
		Value:  "",
		Source: labels.LabelSourceReserved,
	}),
	EntityCluster: NewESFromLabels(&labels.Label{
		Key:    labels.IDNameCluster,
		Value:  "",
		Source: labels.LabelSourceReserved,
	}),
	EntityHost: NewESFromLabels(&labels.Label{
		Key:    labels.IDNameHost,
		Value:  "",
		Source: labels.LabelSourceReserved,
	}),
	EntityInit: NewESFromLabels(&labels.Label{
		Key:    labels.IDNameInit,
		Value:  "",
		Source: labels.LabelSourceReserved,
	}),
}

// EntitySlice is a slice of entities
type EntitySlice []Entity

// Matches returns true if the entity matches the labels
func (e Entity) Matches(ctx labels.LabelArray) bool {
	if selector, ok := EntitySelectorMapping[e]; ok {
		return selector.Matches(ctx)
	}

	return false
}

// Matches returns true if any of the entities in the slice match the labels
func (s EntitySlice) Matches(ctx labels.LabelArray) bool {
	for _, entity := range s {
		if entity.Matches(ctx) {
			return true
		}
	}

	return false
}

// GetAsEndpointSelectors returns the provided entity slice as a slice of
// endpoint selectors
func (s EntitySlice) GetAsEndpointSelectors() EndpointSelectorSlice {
	slice := EndpointSelectorSlice{}
	for _, e := range s {
		if selector, ok := EntitySelectorMapping[e]; ok {
			slice = append(slice, selector)
		}
	}

	return slice
}
