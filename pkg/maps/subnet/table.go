// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package subnet

import (
	"encoding"
	"fmt"
	"iter"
	"net/netip"

	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/types"
)

const TableName = "subnet-identities"

var (
	SubnetPrimaryIndex = statedb.Index[SubnetTableEntry, netip.Prefix]{
		Name: "key",
		FromObject: func(t SubnetTableEntry) index.KeySet {
			return index.NewKeySet(index.NetIPPrefix(t.Key))
		},
		FromKey:    index.NetIPPrefix,
		FromString: index.NetIPPrefixString,
		Unique:     true,
	}
)

type SubnetTableEntry struct {
	Key netip.Prefix

	// Identity is the uint64 identifier associated with this subnet.
	Value uint32

	// Status represents the reconciliation status of the subnet entry.
	Status reconciler.Status
}

func NewSubnetEntry(key netip.Prefix, value uint32) SubnetTableEntry {
	return SubnetTableEntry{
		Key:    key,
		Value:  value,
		Status: reconciler.StatusPending(),
	}
}

// TableHeader returns the header for the table representation of SubnetEntry.
func (s SubnetTableEntry) TableHeader() []string {
	return []string{"Prefix", "Identity"}
}

// TableRow returns the row representation of SubnetEntry.
func (s SubnetTableEntry) TableRow() []string {
	return []string{s.Key.String(), fmt.Sprintf("%d", s.Value)}
}

// clone returns a shallow copy of the SubnetTableEntry.
func (s SubnetTableEntry) clone() SubnetTableEntry {
	return SubnetTableEntry{
		Key:    s.Key,
		Value:  s.Value,
		Status: s.Status,
	}
}

// setStatus sets the reconciliation status and returns the updated entry.
func (s SubnetTableEntry) setStatus(status reconciler.Status) SubnetTableEntry {
	s.Status = status
	return s
}

// getStatus returns the current reconciliation status.
func (s SubnetTableEntry) getStatus() reconciler.Status {
	return s.Status
}

// SubnetLPMIndex is the secondary index for SubnetEntry
// Primary index is exact prefix index and secondary is LPM.
var SubnetLPMIndex = statedb.NetIPPrefixIndex[SubnetTableEntry]{
	Name: "prefix",
	FromObject: func(s SubnetTableEntry) iter.Seq[netip.Prefix] {
		return statedb.Just(s.Key)
	},
	Unique: true,
}

// newSubnetEntryTable creates and registers the subnet entry table in stateDB.
func newSubnetEntryTable(db *statedb.DB) (statedb.RWTable[SubnetTableEntry], error) {
	return statedb.NewTable(
		db,
		TableName,
		SubnetPrimaryIndex,
		SubnetLPMIndex,
	)
}

// BinaryKey returns the binary representation of the subnet prefix for the eBPF map key.
func (s SubnetTableEntry) BinaryKey() encoding.BinaryMarshaler {
	var ip types.IPv6
	var family uint8

	// Convert netip.Prefix to SubnetMapKey
	addr := s.Key.Addr()

	// Copy the IP address bytes into the IPv6 array
	if addr.Is4() {
		// For IPv4, copy to the last 4 bytes (IPv4-mapped IPv6 format)
		ipv4 := addr.As4()
		copy(ip[:], ipv4[:])
		family = bpf.EndpointKeyIPv4
	} else {
		// For IPv6, copy all 16 bytes
		ipv6 := addr.As16()
		copy(ip[:], ipv6[:])
		family = bpf.EndpointKeyIPv6
	}

	k := SubnetMapKey{
		Prefixlen: getStaticPrefixBits() + uint32(s.Key.Bits()),
		Family:    family,
		IP:        ip,
	}
	return bpf.StructBinaryMarshaler{Target: &k}
}

// BinaryValue returns the binary representation of the identity for the eBPF map value.
func (s SubnetTableEntry) BinaryValue() encoding.BinaryMarshaler {
	v := SubnetMapValue{
		Identity: s.Value,
	}
	return bpf.StructBinaryMarshaler{Target: &v}
}
