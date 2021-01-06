// Copyright 2018-2019 Authors of Cilium
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

package identity

import (
	"fmt"
	"net"
	"sync"

	"github.com/cilium/cilium/pkg/labels"
)

// Identity is the representation of the security context for a particular set of
// labels.
type Identity struct {
	// Identity's ID.
	ID NumericIdentity `json:"id"`
	// Set of labels that belong to this Identity.
	Labels labels.Labels `json:"labels"`

	// onceLabelSHA256 makes sure LabelsSHA256 is only set once
	onceLabelSHA256 sync.Once
	// SHA256 of labels.
	LabelsSHA256 string `json:"labelsSHA256"`

	// LabelArray contains the same labels as Labels in a form of a list, used
	// for faster lookup.
	LabelArray labels.LabelArray `json:"-"`

	// CIDRLabel is the primary identity label when the identity represents
	// a CIDR. The Labels field will consist of all matching prefixes, e.g.
	// 10.0.0.0/8
	// 10.0.0.0/7
	// 10.0.0.0/6
	// [...]
	// reserved:world
	//
	// The CIDRLabel field will only contain 10.0.0.0/8
	CIDRLabel labels.Labels `json:"-"`

	// ReferenceCount counts the number of references pointing to this
	// identity. This field is used by the owning cache of the identity.
	ReferenceCount int `json:"-"`
}

// IPIdentityPair is a pairing of an IP and the security identity to which that
// IP corresponds. May include an optional Mask which, if present, denotes that
// the IP represents a CIDR with the specified Mask.
//
// WARNING - STABLE API
// This structure is written as JSON to the key-value store. Do NOT modify this
// structure in ways which are not JSON forward compatible.
type IPIdentityPair struct {
	IP           net.IP          `json:"IP"`
	Mask         net.IPMask      `json:"Mask"`
	HostIP       net.IP          `json:"HostIP"`
	ID           NumericIdentity `json:"ID"`
	Key          uint8           `json:"Key"`
	Metadata     string          `json:"Metadata"`
	K8sNamespace string          `json:"K8sNamespace,omitempty"`
	K8sPodName   string          `json:"K8sPodName,omitempty"`
	NamedPorts   []NamedPort     `json:"NamedPorts,omitempty"`
}

// NamedPort is a mapping from a port name to a port number and protocol.
//
// WARNING - STABLE API
// This structure is written as JSON to the key-value store. Do NOT modify this
// structure in ways which are not JSON forward compatible.
type NamedPort struct {
	Name     string `json:"Name"`
	Port     uint16 `json:"Port"`
	Protocol string `json:"Protocol"`
}

// Sanitize takes a partially initialized Identity (for example, deserialized
// from json) and reconstitutes the full object from what has been restored.
func (id *Identity) Sanitize() {
	if id.Labels != nil {
		id.LabelArray = id.Labels.LabelArray()
	}
}

// GetLabelsSHA256 returns the SHA256 of the labels associated with the
// identity. The SHA is calculated if not already cached.
func (id *Identity) GetLabelsSHA256() string {
	id.onceLabelSHA256.Do(func() {
		if id.LabelsSHA256 == "" {
			id.LabelsSHA256 = id.Labels.SHA256Sum()
		}
	})

	return id.LabelsSHA256
}

// StringID returns the identity identifier as string
func (id *Identity) StringID() string {
	return id.ID.StringID()
}

// StringID returns the identity identifier as string
func (id *Identity) String() string {
	return id.ID.StringID()
}

// IsReserved returns whether the identity represents a reserved identity
// (true), or not (false).
func (id *Identity) IsReserved() bool {
	return LookupReservedIdentity(id.ID) != nil
}

// IsFixed returns whether the identity represents a fixed identity
// (true), or not (false).
func (id *Identity) IsFixed() bool {
	return LookupReservedIdentity(id.ID) != nil &&
		(id.ID == ReservedIdentityHost || id.ID == ReservedIdentityHealth ||
			IsUserReservedIdentity(id.ID))
}

// IsWellKnown returns whether the identity represents a well known identity
// (true), or not (false).
func (id *Identity) IsWellKnown() bool {
	return WellKnown.lookupByNumericIdentity(id.ID) != nil
}

// NewIdentityFromLabelArray creates a new identity
func NewIdentityFromLabelArray(id NumericIdentity, lblArray labels.LabelArray) *Identity {
	var lbls labels.Labels

	if lblArray != nil {
		lbls = lblArray.Labels()
	}
	return &Identity{ID: id, Labels: lbls, LabelArray: lblArray}
}

// NewIdentity creates a new identity
func NewIdentity(id NumericIdentity, lbls labels.Labels) *Identity {
	var lblArray labels.LabelArray

	if lbls != nil {
		lblArray = lbls.LabelArray()
	}
	return &Identity{ID: id, Labels: lbls, LabelArray: lblArray}
}

// IsHost determines whether the IP in the pair represents a host (true) or a
// CIDR prefix (false)
func (pair *IPIdentityPair) IsHost() bool {
	return pair.Mask == nil
}

// PrefixString returns the IPIdentityPair's IP as either a host IP in the
// format w.x.y.z if 'host' is true, or as a prefix in the format the w.x.y.z/N
// if 'host' is false.
func (pair *IPIdentityPair) PrefixString() string {
	var suffix string
	if !pair.IsHost() {
		var ones int
		if pair.Mask == nil {
			if pair.IP.To4() != nil {
				ones = net.IPv4len
			} else {
				ones = net.IPv6len
			}
		} else {
			ones, _ = pair.Mask.Size()
		}
		suffix = fmt.Sprintf("/%d", ones)
	}
	return fmt.Sprintf("%s%s", pair.IP.String(), suffix)
}

// RequiresGlobalIdentity returns true if the label combination requires a
// global identity
func RequiresGlobalIdentity(lbls labels.Labels) bool {
	needsGlobal := true

	for _, label := range lbls {
		switch label.Source {
		case labels.LabelSourceCIDR, labels.LabelSourceReserved:
			needsGlobal = false
		default:
			return true
		}
	}

	return needsGlobal
}

// AddUserDefinedNumericIdentitySet adds all key-value pairs from the given map
// to the map of user defined numeric identities and reserved identities.
// The key-value pairs should map a numeric identity to a valid label.
// Is not safe for concurrent use.
func AddUserDefinedNumericIdentitySet(m map[string]string) error {
	// Validate first
	for k := range m {
		ni, err := ParseNumericIdentity(k)
		if err != nil {
			return err
		}
		if !IsUserReservedIdentity(ni) {
			return ErrNotUserIdentity
		}
	}
	for k, lbl := range m {
		ni, _ := ParseNumericIdentity(k)
		AddUserDefinedNumericIdentity(ni, lbl)
		AddReservedIdentity(ni, lbl)
	}
	return nil
}

// LookupReservedIdentityByLabels looks up a reserved identity by its labels and
// returns it if found. Returns nil if not found.
func LookupReservedIdentityByLabels(lbls labels.Labels) *Identity {
	if identity := WellKnown.LookupByLabels(lbls); identity != nil {
		return identity
	}

	for _, lbl := range lbls {
		switch {
		// If the set of labels contain a fixed identity then and exists in
		// the map of reserved IDs then return the identity of that reserved ID.
		case lbl.Key == labels.LabelKeyFixedIdentity:
			id := GetReservedID(lbl.Value)
			if id != IdentityUnknown && IsUserReservedIdentity(id) {
				return LookupReservedIdentity(id)
			}
			// If a fixed identity was not found then we return nil to avoid
			// falling to a reserved identity.
			return nil

		case lbl.Source == labels.LabelSourceReserved:
			// If it contains the reserved, local host identity, return it with
			// the new list of labels. This is to ensure the local node retains
			// this identity regardless of label changes.
			id := GetReservedID(lbl.Key)
			if id == ReservedIdentityHost {
				identity := NewIdentity(ReservedIdentityHost, lbls)
				// Pre-calculate the SHA256 hash.
				identity.GetLabelsSHA256()
				return identity
			}

			// If it doesn't contain a fixed-identity then make sure the set of
			// labels only contains a single label and that label is of the
			// reserved type. This is to prevent users from adding
			// cilium-reserved labels into the workloads.
			if len(lbls) != 1 {
				return nil
			}
			if id != IdentityUnknown && !IsUserReservedIdentity(id) {
				return LookupReservedIdentity(id)
			}
		}
	}
	return nil
}

// IdentityAllocationIsLocal returns true if a call to AllocateIdentity with
// the given labels would not require accessing the KV store to allocate the
// identity.
// Currently, this function returns true only if the labels are those of a
// reserved identity, i.e. if the slice contains a single reserved
// "reserved:*" label.
func IdentityAllocationIsLocal(lbls labels.Labels) bool {
	// If there is only one label with the "reserved" source and a well-known
	// key, the well-known identity for it can be allocated locally.
	return LookupReservedIdentityByLabels(lbls) != nil
}
