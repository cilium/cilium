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
	secLabelTimeout = 120 * time.Second

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

type RuleContexts map[RuleContext]bool

// RuleContext represents a L3-dependent L4 rule
// Don't use pointers here since this structure is used as key on maps.
type RuleContext struct {
	// SecID is the security ID for the numeric identity
	SecID NumericIdentity
	// Port is the destination port in the policy in network byte order
	Port uint16
	// Proto is the protocol ID used
	Proto uint8
	// L7RedirectPort is the L7 redirect port in the policy in network byte order
	L7RedirectPort uint16
	// IsRedirect is set in case the rule is a redirect
	IsRedirect bool
}

// Identity is the representation of the security context for a particular set of
// labels.
type Identity struct {
	// Identity's ID.
	ID NumericIdentity `json:"id"`
	// Set of labels that belong to this Identity.
	Labels labels.Labels `json:"labels"`
	// SHA256 of labels.
	LabelsSHA256 string `json:"labelsSHA256"`
	// Endpoints that have this Identity where their value is the last time they were seen.
	// Also, If an identity is no longer used (i.e. all endpoints have disassociated from it) we can recycle the identity.
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

// GetLabelsSHA256 returns the SHA256 of the labels associated with the
// identity. The SHA is calculated if not already cached.
func (id *Identity) GetLabelsSHA256() string {
	if id.LabelsSHA256 == "" {
		id.LabelsSHA256 = id.Labels.SHA256Sum()
	}

	return id.LabelsSHA256
}

// StringID returns the identity identifier as string
func (id *Identity) StringID() string {
	return id.ID.StringID()
}

func (id *Identity) GetModel() *models.Identity {
	if id == nil {
		return nil
	}

	ret := &models.Identity{
		ID:           int64(id.ID),
		Labels:       []string{},
		LabelsSHA256: "",
	}

	for _, v := range id.Labels {
		ret.Labels = append(ret.Labels, v.String())
	}
	ret.LabelsSHA256 = id.LabelsSHA256
	return ret
}

func NewIdentity() *Identity {
	return &Identity{
		Endpoints: make(map[string]time.Time),
		Labels:    make(map[string]*labels.Label),
	}
}

// AssociateEndpoint associates the endpoint with identity.
func (id *Identity) AssociateEndpoint(epID string) {
	id.Endpoints[epID] = time.Now().UTC()
}

// DisassociateEndpoint disassociates the endpoint endpoint with identity and
// returns true if successful.
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
		if t.Add(secLabelTimeout).After(time.Now().UTC()) {
			refCount++
		}
	}
	return refCount
}

const (
	// IdentityUnknown represents an unknown identity
	IdentityUnknown NumericIdentity = iota

	// ReservedIdentityHost represents the local host
	ReservedIdentityHost

	// ReservedIdentityWorld represents any endpoint outside of the cluster
	ReservedIdentityWorld

	// ReservedIdentityCluster represents any endpoint inside the cluster
	// that does not have a more specific identity
	ReservedIdentityCluster
)

var (
	ReservedIdentities = map[string]NumericIdentity{
		labels.IDNameHost:    ReservedIdentityHost,
		labels.IDNameWorld:   ReservedIdentityWorld,
		labels.IDNameCluster: ReservedIdentityCluster,
	}
	ReservedIdentityNames = map[NumericIdentity]string{
		ReservedIdentityHost:    labels.IDNameHost,
		ReservedIdentityWorld:   labels.IDNameWorld,
		ReservedIdentityCluster: labels.IDNameCluster,
	}
)

func GetReservedID(name string) NumericIdentity {
	if v, ok := ReservedIdentities[name]; ok {
		return v
	}
	return IdentityUnknown
}
