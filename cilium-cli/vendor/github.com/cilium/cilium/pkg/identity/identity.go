// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identity

import (
	"net"
	"strconv"

	"github.com/cilium/cilium/pkg/labels"
)

const (
	NodeLocalIdentityType    = "node_local"
	ReservedIdentityType     = "reserved"
	ClusterLocalIdentityType = "cluster_local"
	WellKnownIdentityType    = "well_known"
)

// Identity is the representation of the security context for a particular set of
// labels.
type Identity struct {
	// Identity's ID.
	ID NumericIdentity `json:"id"`
	// Set of labels that belong to this Identity.
	Labels labels.Labels `json:"labels"`

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

// IsWellKnownIdentity returns true if the identity represents a well-known
// identity, false otherwise.
func IsWellKnownIdentity(id NumericIdentity) bool {
	return WellKnown.lookupByNumericIdentity(id) != nil
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
	ipstr := pair.IP.String()

	if pair.IsHost() {
		return ipstr
	}

	ones, _ := pair.Mask.Size()
	return ipstr + "/" + strconv.Itoa(ones)
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
		var createID bool
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
			id := GetReservedID(lbl.Key)
			switch {
			case id == ReservedIdentityKubeAPIServer && lbls.Has(labels.LabelHost[labels.IDNameHost]):
				// Due to Golang map iteration order (random) we might get the
				// ID returned as kube-apiserver. If there's a local host
				// label, then we know this is local host reserved ID, so
				// change it as such. All local host traffic should always be
				// considered host (and not kube-apiserver).
				//
				// The kube-apiserver label can be a part of a few identities:
				//   * host
				//   * kube-apiserver reserved identity (contains remote-node
				//     label)
				//   * (maybe) CIDR
				id = ReservedIdentityHost
				fallthrough
			case id == ReservedIdentityKubeAPIServer && lbls.Has(labels.LabelRemoteNode[labels.IDNameRemoteNode]):
				createID = true

			case id == ReservedIdentityRemoteNode && lbls.Has(labels.LabelKubeAPIServer[labels.IDNameKubeAPIServer]):
				// Due to Golang map iteration order (random) we might get the
				// ID returned as remote-node. If there's a kube-apiserver
				// label, then we know this is kube-apiserver reserved ID, so
				// change it as such. Only traffic to non-kube-apiserver nodes
				// should be considered as remote-node.
				id = ReservedIdentityKubeAPIServer
				fallthrough
			case id == ReservedIdentityHost || id == ReservedIdentityRemoteNode:
				// If it contains the reserved, local host or remote node
				// identity, return it with the new list of labels. This is to
				// ensure that the local node  or remote node retain their
				// identity regardless of label changes.
				createID = true
			}

			if createID {
				return NewIdentity(id, lbls)
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
