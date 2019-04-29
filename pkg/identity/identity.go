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

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/labels"
)

// Identity is the representation of the security context for a particular set of
// labels.
type Identity struct {
	// Identity's ID.
	ID NumericIdentity `json:"id"`
	// Set of labels that belong to this Identity.
	Labels labels.Labels `json:"labels"`
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
	// reserverd:world
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
	IP       net.IP          `json:"IP"`
	Mask     net.IPMask      `json:"Mask"`
	HostIP   net.IP          `json:"HostIP"`
	ID       NumericIdentity `json:"ID"`
	Key      uint8           `json:"Key"`
	Metadata string          `json:"Metadata"`
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
	id.Sanitize()

	return id
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
	if id.LabelsSHA256 == "" {
		id.LabelsSHA256 = id.Labels.SHA256Sum()
	}

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

// IsReserved returns whether the identity represents a reserved identity
// (true), or not (false).
func (id *Identity) IsReserved() bool {
	return LookupReservedIdentity(id.ID) != nil
}

// IsFixed returns whether the identity represents a fixed identity
// (true), or not (false).
func (id *Identity) IsFixed() bool {
	return LookupReservedIdentity(id.ID) != nil && IsUserReservedIdentity(id.ID)
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
	for _, label := range lbls {
		switch label.Source {
		case labels.LabelSourceCIDR, labels.LabelSourceReserved:
		default:
			return true
		}
	}

	return false
}
