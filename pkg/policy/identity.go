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
	"path"
	"strconv"
	"sync"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/kvstore/allocator"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/u8proto"

	"github.com/sirupsen/logrus"
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

var (
	// IdentitiesPath is the to where identities are stored
	IdentitiesPath = path.Join(kvstore.BaseKeyPrefix, "state", "identities", "v1")
)

// NumericIdentity is the numeric representation of a security identity / a
// security policy.
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
}

func NewIdentityFromModel(base *models.Identity) *Identity {
	if base == nil {
		return nil
	}

	id := &Identity{
		ID:     NumericIdentity(base.ID),
		Labels: make(labels.Labels),
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
	ret.LabelsSHA256 = id.GetLabelsSHA256()
	return ret
}

// NewIdentity creates a new identity
func NewIdentity(id NumericIdentity, lbls labels.Labels) *Identity {
	return &Identity{ID: id, Labels: lbls}
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

// globalIdentity is the structure used to store an identity in the kvstore
type globalIdentity struct {
	labels.Labels
}

// GetKey() encodes a globalIdentity as string
func (gi globalIdentity) GetKey() string {
	return kvstore.Encode(gi.SortedList())
}

// PutKey() decides a globalIdentity from its string representation
func (gi globalIdentity) PutKey(v string) (allocator.AllocatorKey, error) {
	b, err := kvstore.Decode(v)
	if err != nil {
		return nil, err
	}

	return globalIdentity{labels.NewLabelsFromSortedList(string(b))}, nil
}

var (
	setupOnce         sync.Once
	identityAllocator *allocator.Allocator
)

// IdentityAllocatorOwner is the interface the owner of an identity allocator
// must implement
type IdentityAllocatorOwner interface {
	// TriggerPolicyUpdates will be called whenever a policy recalculation
	// must be triggered
	TriggerPolicyUpdates(force bool) *sync.WaitGroup

	// GetSuffix must return the node specific suffix to use
	GetNodeSuffix() string
}

// InitIdentityAllocator creates the the identity allocator. Only the first
// invocation of this function will have an effect.
func InitIdentityAllocator(owner IdentityAllocatorOwner) {
	setupOnce.Do(func() {
		minID := allocator.ID(MinimalNumericIdentity)
		maxID := allocator.ID(^uint16(0))
		a, err := allocator.NewAllocator(IdentitiesPath, globalIdentity{},
			allocator.WithMax(maxID), allocator.WithMin(minID),
			allocator.WithSuffix(owner.GetNodeSuffix()))
		if err != nil {
			log.WithError(err).Fatal("Unable to initialize identity allocator")
		}

		identityAllocator = a

		go identityWatcher(owner)
	})
}

// AllocateIdentity allocates an identity described by the specified labels. If
// an identity for the specified set of labels already exist, the identity is
// re-used and reference counting is performed, otherwise a new identity is
// allocated via the kvstore.
func AllocateIdentity(lbls labels.Labels) (*Identity, bool, error) {
	log.WithFields(logrus.Fields{
		logfields.IdentityLabels: lbls.String(),
	}).Debug("Resolving identity")

	id, isNew, err := identityAllocator.Allocate(globalIdentity{lbls})
	if err != nil {
		return nil, false, err
	}

	log.WithFields(logrus.Fields{
		logfields.Identity:       id,
		logfields.IdentityLabels: lbls.String(),
		"isNew":                  isNew,
	}).Debug("Resolved identity")

	return NewIdentity(NumericIdentity(id), lbls), isNew, nil
}

// LookupIdentity looks up the identity by its labels but does not create it.
// This function will first search through the local cache and fall back to
// querying the kvstore.
func LookupIdentity(lbls labels.Labels) *Identity {
	if identityAllocator == nil {
		return nil
	}

	id, err := identityAllocator.Get(globalIdentity{lbls})
	if err != nil {
		return nil
	}

	if id == allocator.NoID {
		return nil
	}

	return NewIdentity(NumericIdentity(id), lbls)
}

// LookupIdentityByID returns the identity by ID. This function will first
// search through the local cache and fall back to querying the kvstore.
func LookupIdentityByID(id NumericIdentity) *Identity {
	if identityAllocator == nil {
		return nil
	}

	allocatorKey, err := identityAllocator.GetByID(allocator.ID(id))
	if err != nil {
		return nil
	}

	if gi, ok := allocatorKey.(globalIdentity); ok {
		return NewIdentity(id, gi.Labels)
	}

	return nil
}

// Release is the reverse operation of AllocateIdentity() and releases the
// identity again. This function may result in kvstore operations.
func (id *Identity) Release() error {
	return identityAllocator.Release(globalIdentity{id.Labels})
}

// IdentityCache is a cache of identity to labels mapping
type IdentityCache map[NumericIdentity]labels.LabelArray

// GetIdentityCache returns a cache of all known identities
func GetIdentityCache() IdentityCache {
	cache := IdentityCache{}

	identityAllocator.ForeachCache(func(id allocator.ID, val allocator.AllocatorKey) {
		gi := val.(globalIdentity)
		cache[NumericIdentity(id)] = gi.LabelArray()
	})

	return cache
}

// GetIdentities returns all known identities
func GetIdentities() []*models.Identity {
	identities := []*models.Identity{}

	identityAllocator.ForeachCache(func(id allocator.ID, val allocator.AllocatorKey) {
		if gi, ok := val.(globalIdentity); ok {
			identity := NewIdentity(NumericIdentity(id), gi.Labels)
			identities = append(identities, identity.GetModel())
		}

	})

	return identities
}

func identityWatcher(owner IdentityAllocatorOwner) {
	for {
		event := <-identityAllocator.Events

		switch event.Typ {
		case kvstore.EventTypeCreate, kvstore.EventTypeDelete:
			owner.TriggerPolicyUpdates(true)

		case kvstore.EventTypeModify:
			// Ignore modify events
		}
	}
}
