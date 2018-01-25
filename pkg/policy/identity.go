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

package policy

import (
	"strconv"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/u8proto"
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

// SecurityIDContexts maps a security identity to a L4RuleContexts
type SecurityIDContexts map[NumericIdentity]L4RuleContexts

// DeepCopy returns a deep copy of SecurityIDContexts
func (sc SecurityIDContexts) DeepCopy() SecurityIDContexts {
	cpy := make(SecurityIDContexts)
	for k, v := range sc {
		cpy[k] = v.DeepCopy()
	}
	return cpy
}

// SecurityIDContexts returns a new L4RuleContexts created.
func NewSecurityIDContexts() SecurityIDContexts {
	return SecurityIDContexts(make(map[NumericIdentity]L4RuleContexts))
}

// L4RuleContexts maps a rule context to a L7RuleContext.
type L4RuleContexts map[L4RuleContext]L7RuleContext

// NewL4RuleContexts returns a new L4RuleContexts.
func NewL4RuleContexts() L4RuleContexts {
	return L4RuleContexts(make(map[L4RuleContext]L7RuleContext))
}

// DeepCopy returns a deep copy of L4RuleContexts
func (rc L4RuleContexts) DeepCopy() L4RuleContexts {
	cpy := make(L4RuleContexts)
	for k, v := range rc {
		cpy[k] = v
	}
	return cpy
}

// IsL3Only returns false if the given L4RuleContexts contains any entry. If it
// does not contain any entry it is considered an L3 only rule.
func (rc L4RuleContexts) IsL3Only() bool {
	return rc != nil && len(rc) == 0
}

// L4RuleContext represents a L4 rule
// Don't use pointers here since this structure is used as key on maps.
type L4RuleContext struct {
	// Port is the destination port in the policy in network byte order
	Port uint16
	// Proto is the protocol ID used
	Proto uint8
}

// L7RuleContext represents a L7 rule
type L7RuleContext struct {
	// RedirectPort is the L7 redirect port in the policy in network byte order
	RedirectPort uint16
	// L4Installed specifies if the L4 rule is installed in the L4 BPF map
	L4Installed bool
}

// IsRedirect checks if the L7RuleContext is a redirect to the proxy.
func (rc L7RuleContext) IsRedirect() bool {
	return rc.RedirectPort != 0
}

// PortProto returns the port proto tuple in a human readable format. i.e.
// with its port in host byte order.
func (rc L4RuleContext) PortProto() string {
	proto := u8proto.U8proto(rc.Proto).String()
	port := strconv.Itoa(int(byteorder.NetworkToHost(uint16(rc.Port)).(uint16)))
	return port + "/" + proto
}

// ParseL4Filter parses a L4Filter and returns a L4RuleContext and a
// L7RuleContext with L4Installed set as false.
func ParseL4Filter(filter L4Filter) (L4RuleContext, L7RuleContext) {
	return L4RuleContext{
			Port:  byteorder.HostToNetwork(uint16(filter.Port)).(uint16),
			Proto: uint8(filter.U8Proto),
		}, L7RuleContext{
			RedirectPort: byteorder.HostToNetwork(uint16(filter.L7RedirectPort)).(uint16),
		}
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

	// ReservedIdentityHealth represents the local cilium-health endpoint
	ReservedIdentityHealth
)

var (
	ReservedIdentities = map[string]NumericIdentity{
		labels.IDNameHost:    ReservedIdentityHost,
		labels.IDNameWorld:   ReservedIdentityWorld,
		labels.IDNameHealth:  ReservedIdentityHealth,
		labels.IDNameCluster: ReservedIdentityCluster,
	}
	ReservedIdentityNames = map[NumericIdentity]string{
		ReservedIdentityHost:    labels.IDNameHost,
		ReservedIdentityWorld:   labels.IDNameWorld,
		ReservedIdentityHealth:  labels.IDNameHealth,
		ReservedIdentityCluster: labels.IDNameCluster,
	}
)

func GetReservedID(name string) NumericIdentity {
	if v, ok := ReservedIdentities[name]; ok {
		return v
	}
	return IdentityUnknown
}
