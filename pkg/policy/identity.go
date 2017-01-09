//
// Copyright 2016 Authors of Cilium
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
//
package policy

import (
	"strconv"
	"time"

	"github.com/cilium/cilium/pkg/labels"
)

const (
	secLabelTimeout = time.Duration(120 * time.Second)

	// All IDs lesser than this value are reserved
	MinimalNumericIdentity = NumericIdentity(256)
)

// Represents an identity of an entity to which consumer policy can be
// applied to
type NumericIdentity uint32

func (id NumericIdentity) StringID() string {
	return strconv.FormatUint(uint64(id), 10)
}

func (id NumericIdentity) String() string {
	if v, exists := ReservedIdentityNames[id]; exists {
		return v
	}

	return id.StringID()
}

// Normalize ID for use in BPF program
func (id NumericIdentity) Uint32() uint32 {
	return uint32(id)
}

// Identity is the representation of the security context for a particular set of
// labels.
type Identity struct {
	// Identity's ID.
	ID NumericIdentity `json:"id"`
	// Endpoints that have this Identity where their value is the last time they were seen.
	Labels labels.Labels `json:"labels"`
	// Set of labels that belong to this Identity.
	Endpoints map[string]time.Time `json:"containers"`
}

func (s *Identity) DeepCopy() *Identity {
	cpy := &Identity{
		ID:        s.ID,
		Labels:    s.Labels.DeepCopy(),
		Endpoints: make(map[string]time.Time, len(s.Endpoints)),
	}
	for k, v := range s.Endpoints {
		cpy.Endpoints[k] = v
	}
	return cpy
}

func NewIdentity() *Identity {
	return &Identity{
		Endpoints: make(map[string]time.Time),
		Labels:    make(map[string]*labels.Label),
	}
}

func (s *Identity) AddOrUpdateContainer(contID string) {
	s.Endpoints[contID] = time.Now()
}

func (s *Identity) DelContainer(contID string) {
	delete(s.Endpoints, contID)
}

func (s *Identity) RefCount() int {
	refCount := 0
	for _, t := range s.Endpoints {
		if t.Add(secLabelTimeout).After(time.Now()) {
			refCount++
		}
	}
	return refCount
}

const (
	ID_UNKNOWN NumericIdentity = iota
	ID_HOST
	ID_WORLD
)

var (
	ReservedIdentities = map[string]NumericIdentity{
		labels.ID_NAME_HOST:  ID_HOST,
		labels.ID_NAME_WORLD: ID_WORLD,
	}
	ReservedIdentityNames = map[NumericIdentity]string{
		ID_HOST:  labels.ID_NAME_HOST,
		ID_WORLD: labels.ID_NAME_WORLD,
	}
)

func GetReservedID(name string) NumericIdentity {
	if v, ok := ReservedIdentities[name]; ok {
		return v
	}
	return ID_UNKNOWN
}
