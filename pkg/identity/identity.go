// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identity

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"

	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
)

const (
	NodeLocalIdentityType    = "node_local"
	ReservedIdentityType     = "reserved"
	ClusterLocalIdentityType = "cluster_local"
	WellKnownIdentityType    = "well_known"
	RemoteNodeIdentityType   = "remote_node"
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

type IdentityMap map[NumericIdentity]labels.LabelArray

// GetKeyName returns the kvstore key to be used for the IPIdentityPair
func (pair *IPIdentityPair) GetKeyName() string { return pair.PrefixString() }

// Marshal returns the IPIdentityPair object as JSON byte slice
func (pair *IPIdentityPair) Marshal() ([]byte, error) { return json.Marshal(pair) }

// Unmarshal parses the JSON byte slice and updates the IPIdentityPair receiver
func (pair *IPIdentityPair) Unmarshal(key string, data []byte) error {
	newPair := IPIdentityPair{}
	if err := json.Unmarshal(data, &newPair); err != nil {
		return err
	}

	if got := newPair.GetKeyName(); got != key {
		return fmt.Errorf("IP address does not match key: expected %s, got %s", key, got)
	}

	*pair = newPair
	return nil
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
	return ScopeForLabels(lbls) == IdentityScopeGlobal
}

// ScopeForLabels returns the identity scope to be used for the label set.
// If all labels are either CIDR or reserved, then returns the CIDR scope.
// Note: This assumes the caller has already called LookupReservedIdentityByLabels;
// it does not handle that case.
func ScopeForLabels(lbls labels.Labels) NumericIdentity {
	scope := IdentityScopeGlobal

	// If this is a remote node, return the remote node scope.
	// Note that this is not reachable when policy-cidr-selects-nodes is false or
	// when enable-node-selector-labels is false, since
	// callers will already have gotten a value from LookupReservedIdentityByLabels.
	if lbls.Has(labels.LabelRemoteNode[labels.IDNameRemoteNode]) {
		return IdentityScopeRemoteNode
	}

	for _, label := range lbls {
		switch label.Source {
		case labels.LabelSourceCIDR, labels.LabelSourceFQDN, labels.LabelSourceReserved:
			scope = IdentityScopeLocal
		default:
			return IdentityScopeGlobal
		}
	}

	return scope
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

	// Check if a fixed identity exists.
	if lbl, exists := lbls[labels.LabelKeyFixedIdentity]; exists {
		// If the set of labels contain a fixed identity then and exists in
		// the map of reserved IDs then return the identity of that reserved ID.
		id := GetReservedID(lbl.Value)
		if id != IdentityUnknown && IsUserReservedIdentity(id) {
			return LookupReservedIdentity(id)
		}
		// If a fixed identity was not found then we return nil to avoid
		// falling to a reserved identity.
		return nil
	}

	// If there is no reserved label, return nil.
	if !lbls.IsReserved() {
		return nil
	}

	var nid NumericIdentity
	if lbls.Has(labels.LabelHost[labels.IDNameHost]) {
		nid = ReservedIdentityHost
	} else if lbls.Has(labels.LabelRemoteNode[labels.IDNameRemoteNode]) {
		// If selecting remote-nodes via CIDR policies is allowed, then
		// they no longer have a reserved identity.
		if option.Config.PolicyCIDRMatchesNodes() {
			return nil
		}
		// If selecting remote-nodes via node labels is allowed, then
		// they no longer have a reserved identity and are using
		// IdentityScopeRemoteNode.
		if option.Config.PerNodeLabelsEnabled() {
			return nil
		}
		nid = ReservedIdentityRemoteNode
		if lbls.Has(labels.LabelKubeAPIServer[labels.IDNameKubeAPIServer]) {
			// If there's a kube-apiserver label, then we know this is
			// kube-apiserver reserved ID, so change it as such.
			// Only traffic from non-kube-apiserver nodes should be
			// considered as remote-node.
			nid = ReservedIdentityKubeAPIServer
		}
	}

	if nid != IdentityUnknown {
		return NewIdentity(nid, lbls)
	}

	// We have handled all the cases where multiple labels can be present.
	// So, we make sure the set of labels only contains a single label and
	// that label is of the reserved type. This is to prevent users from
	// adding cilium-reserved labels into the workloads.
	if len(lbls) != 1 {
		return nil
	}

	nid = GetReservedID(lbls.ToSlice()[0].Key)
	if nid != IdentityUnknown && !IsUserReservedIdentity(nid) {
		return LookupReservedIdentity(nid)
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
