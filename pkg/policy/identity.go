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

package policy

import (
	"strconv"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/labels"
)

const (
	secLabelTimeout = time.Duration(120 * time.Second)

	// MinimalNumericIdentity represents the minimal numeric identity not
	// used for reserved purposes.
	MinimalNumericIdentity = NumericIdentity(256)

	// InvalidIdentity is the identity assigned if the identity is invalid
	// or not determined yet
	InvalidIdentity = NumericIdentity(0)
)

// NumericIdentity represents an identity of an entity to which consumer policy
// can be applied to.
type NumericIdentity uint32

func ParseNumericIdentity(id string) (NumericIdentity, error) {
	nid, err := strconv.ParseUint(id, 0, 32)
	if err != nil {
		return NumericIdentity(0), err
	}
	return NumericIdentity(nid), nil
}

func (id NumericIdentity) StringID() string {
	return strconv.FormatUint(uint64(id), 10)
}

func (id NumericIdentity) String() string {
	if v, exists := ReservedIdentityNames[id]; exists {
		return v
	}

	return id.StringID()
}

// Uint32 normalizes the ID for use in BPF program.
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

func NewIdentityFromModel(base *models.Identity) *Identity {
	if base == nil {
		return nil
	}

	id := &Identity{
		ID:        NumericIdentity(base.ID),
		Labels:    make(labels.Labels),
		Endpoints: make(map[string]time.Time),
	}
	for _, v := range base.Labels {
		lbl := labels.ParseLabel(v)
		id.Labels[lbl.Key] = lbl
	}

	return id
}

func (id *Identity) GetModel() *models.Identity {
	if id == nil {
		return nil
	}

	ret := &models.Identity{
		ID:     int64(id.ID),
		Labels: []string{},
	}

	for _, v := range id.Labels {
		ret.Labels = append(ret.Labels, v.String())
	}

	return ret
}

func (id *Identity) DeepCopy() *Identity {
	cpy := &Identity{
		ID:        id.ID,
		Labels:    id.Labels.DeepCopy(),
		Endpoints: make(map[string]time.Time, len(id.Endpoints)),
	}
	for k, v := range id.Endpoints {
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

// AssociateEndpoint associates the endpoint with identity.
func (id *Identity) AssociateEndpoint(epID string) {
	id.Endpoints[epID] = time.Now()
}

// DisassociateEndpoint disassociates the endpoint endpoint with identity and
// return true if successful.
func (id *Identity) DisassociateEndpoint(epID string) bool {
	if _, ok := id.Endpoints[epID]; ok {
		delete(id.Endpoints, epID)
		return true
	}

	return false
}

func (id *Identity) RefCount() int {
	refCount := 0
	for _, t := range id.Endpoints {
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
		labels.IDNameHost:  ID_HOST,
		labels.IDNameWorld: ID_WORLD,
	}
	ReservedIdentityNames = map[NumericIdentity]string{
		ID_HOST:  labels.IDNameHost,
		ID_WORLD: labels.IDNameWorld,
	}
)

func GetReservedID(name string) NumericIdentity {
	if v, ok := ReservedIdentities[name]; ok {
		return v
	}
	return ID_UNKNOWN
}
