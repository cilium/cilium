// Copyright 2016-2020 Authors of Cilium
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

package policymap

import (
	"bytes"
	"fmt"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/u8proto"
)

const (
	// PolicyCallMapName is the name of the map to do tail calls into policy
	// enforcement programs.
	PolicyCallMapName = "cilium_policy_call"

	// MapName is the prefix for endpoint-specific policy maps which map
	// identity+ports+direction to whether the policy allows communication
	// with that identity on that port for that direction.
	MapName = PolicyCallMapName + "_"

	// PolicyCallMaxEntries is the upper limit of entries in the program
	// array for the tail calls to jump into the endpoint specific policy
	// programs. This number *MUST* be identical to the maximum endpoint ID.
	PolicyCallMaxEntries = ^uint16(0)

	// AllPorts is used to ignore the L4 ports in PolicyMap lookups; all ports
	// are allowed. In the datapath, this is represented with the value 0 in the
	// port field of map elements.
	AllPorts = uint16(0)
)

var (
	// MaxEntries is the upper limit of entries in the per endpoint policy
	// table
	MaxEntries = 16384
)

type PolicyMap struct {
	*bpf.Map
}

func (pe *PolicyEntry) String() string {
	return fmt.Sprintf("%d %d %d", pe.ProxyPort, pe.Packets, pe.Bytes)
}

// PolicyKey represents a key in the BPF policy map for an endpoint. It must
// match the layout of policy_key in bpf/lib/common.h.
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type PolicyKey struct {
	Identity         uint32 `align:"sec_label"`
	DestPort         uint16 `align:"dport"` // In network byte-order
	Nexthdr          uint8  `align:"protocol"`
	TrafficDirection uint8  `align:"egress"`
}

// PolicyEntry represents an entry in the BPF policy map for an endpoint. It must
// match the layout of policy_entry in bpf/lib/common.h.
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type PolicyEntry struct {
	ProxyPort uint16 `align:"proxy_port"` // In network byte-order
	Pad0      uint16 `align:"pad0"`
	Pad1      uint16 `align:"pad1"`
	Pad2      uint16 `align:"pad2"`
	Packets   uint64 `align:"packets"`
	Bytes     uint64 `align:"bytes"`
}

func (pe *PolicyEntry) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(pe) }
func (pe *PolicyEntry) NewValue() bpf.MapValue      { return &PolicyEntry{} }

func (pe *PolicyEntry) Add(oPe PolicyEntry) {
	pe.Packets += oPe.Packets
	pe.Bytes += oPe.Bytes
}

type PolicyEntryDump struct {
	PolicyEntry
	Key PolicyKey
}

// PolicyEntriesDump is a wrapper for a slice of PolicyEntryDump
type PolicyEntriesDump []PolicyEntryDump

// Less returns true if the element in index `i` has the value of
// TrafficDirection lower than `j`'s TrafficDirection or if the element in index
// `i` has the value of TrafficDirection lower and equal than `j`'s
// TrafficDirection and the identity of element `i` is lower than the Identity
// of element j.
func (p PolicyEntriesDump) Less(i, j int) bool {
	if p[i].Key.TrafficDirection < p[j].Key.TrafficDirection {
		return true
	}
	return p[i].Key.TrafficDirection <= p[j].Key.TrafficDirection &&
		p[i].Key.Identity < p[j].Key.Identity
}

func (key *PolicyKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(key) }
func (key *PolicyKey) NewValue() bpf.MapValue    { return &PolicyEntry{} }

func (key *PolicyKey) String() string {

	trafficDirectionString := (trafficdirection.TrafficDirection)(key.TrafficDirection).String()
	if key.DestPort != 0 {
		return fmt.Sprintf("%s: %d %d/%d", trafficDirectionString, key.Identity, byteorder.NetworkToHost(key.DestPort), key.Nexthdr)
	}
	return fmt.Sprintf("%s: %d", trafficDirectionString, key.Identity)
}

// ToHost returns a copy of key with fields converted from network byte-order
// to host-byte-order if necessary.
func (key *PolicyKey) ToHost() PolicyKey {
	if key == nil {
		return PolicyKey{}
	}

	n := *key
	n.DestPort = byteorder.NetworkToHost(n.DestPort).(uint16)
	return n
}

// ToNetwork returns a copy of key with fields converted from host byte-order
// to network-byte-order if necessary.
func (key *PolicyKey) ToNetwork() PolicyKey {
	if key == nil {
		return PolicyKey{}
	}

	n := *key
	n.DestPort = byteorder.HostToNetwork(n.DestPort).(uint16)
	return n
}

// newKey returns a PolicyKey representing the specified parameters in network
// byte-order.
func newKey(id uint32, dport uint16, proto u8proto.U8proto, trafficDirection trafficdirection.TrafficDirection) PolicyKey {
	return PolicyKey{
		Identity:         id,
		DestPort:         byteorder.HostToNetwork(dport).(uint16),
		Nexthdr:          uint8(proto),
		TrafficDirection: trafficDirection.Uint8(),
	}
}

// newEntry returns a PolicyEntry representing the specified parameters in
// network byte-order.
func newEntry(proxyPort uint16) PolicyEntry {
	return PolicyEntry{
		ProxyPort: byteorder.HostToNetwork(proxyPort).(uint16),
	}
}

// AllowKey pushes an entry into the PolicyMap for the given PolicyKey k.
// Returns an error if the update of the PolicyMap fails.
func (pm *PolicyMap) AllowKey(k PolicyKey, proxyPort uint16) error {
	return pm.Allow(k.Identity, k.DestPort, u8proto.U8proto(k.Nexthdr), trafficdirection.TrafficDirection(k.TrafficDirection), proxyPort)
}

// Allow pushes an entry into the PolicyMap to allow traffic in the given
// `trafficDirection` for identity `id` with destination port `dport` over
// protocol `proto`. It is assumed that `dport` and `proxyPort` are in host byte-order.
func (pm *PolicyMap) Allow(id uint32, dport uint16, proto u8proto.U8proto, trafficDirection trafficdirection.TrafficDirection, proxyPort uint16) error {
	key := newKey(id, dport, proto, trafficDirection)
	entry := newEntry(proxyPort)
	return pm.Update(&key, &entry)
}

// Exists determines whether PolicyMap currently contains an entry that
// allows traffic in `trafficDirection` for identity `id` with destination port
// `dport`over protocol `proto`. It is assumed that `dport` is in host byte-order.
func (pm *PolicyMap) Exists(id uint32, dport uint16, proto u8proto.U8proto, trafficDirection trafficdirection.TrafficDirection) bool {
	key := newKey(id, dport, proto, trafficDirection)
	_, err := pm.Lookup(&key)
	return err == nil
}

// DeleteKey deletes the key-value pair from the given PolicyMap with PolicyKey
// k. Returns an error if deletion from the PolicyMap fails.
func (pm *PolicyMap) DeleteKey(key PolicyKey) error {
	k := key.ToNetwork()
	return pm.Map.Delete(&k)
}

// Delete removes an entry from the PolicyMap for identity `id`
// sending traffic in direction `trafficDirection` with destination port `dport`
// over protocol `proto`. It is assumed that `dport` is in host byte-order.
// Returns an error if the deletion did not succeed.
func (pm *PolicyMap) Delete(id uint32, dport uint16, proto u8proto.U8proto, trafficDirection trafficdirection.TrafficDirection) error {
	k := newKey(id, dport, proto, trafficDirection)
	return pm.Map.Delete(&k)
}

// DeleteEntry removes an entry from the PolicyMap. It can be used in
// conjunction with DumpToSlice() to inspect and delete map entries.
func (pm *PolicyMap) DeleteEntry(entry *PolicyEntryDump) error {
	return pm.Map.Delete(&entry.Key)
}

// String returns a human-readable string representing the policy map.
func (pm *PolicyMap) String() string {
	path, err := pm.Path()
	if err != nil {
		return err.Error()
	}
	return path
}

func (pm *PolicyMap) Dump() (string, error) {
	var buffer bytes.Buffer
	entries, err := pm.DumpToSlice()
	if err != nil {
		return "", err
	}
	for _, entry := range entries {
		buffer.WriteString(fmt.Sprintf("%20s: %s\n",
			entry.Key.String(), entry.PolicyEntry.String()))
	}
	return buffer.String(), nil
}

func (pm *PolicyMap) DumpToSlice() (PolicyEntriesDump, error) {
	entries := PolicyEntriesDump{}

	cb := func(key bpf.MapKey, value bpf.MapValue) {
		eDump := PolicyEntryDump{
			Key:         *key.DeepCopyMapKey().(*PolicyKey),
			PolicyEntry: *value.DeepCopyMapValue().(*PolicyEntry),
		}
		entries = append(entries, eDump)
	}
	err := pm.DumpWithCallback(cb)

	return entries, err
}

func newMap(path string) *PolicyMap {
	mapType := bpf.MapType(bpf.BPF_MAP_TYPE_HASH)
	flags := bpf.GetPreAllocateMapFlags(mapType)
	return &PolicyMap{
		Map: bpf.NewMap(
			path,
			mapType,
			&PolicyKey{},
			int(unsafe.Sizeof(PolicyKey{})),
			&PolicyEntry{},
			int(unsafe.Sizeof(PolicyEntry{})),
			MaxEntries,
			flags, 0,
			bpf.ConvertKeyValue,
		),
	}
}

// OpenOrCreate opens (or creates) a policy map at the specified path, which
// is used to govern which peer identities can communicate with the endpoint
// protected by this map.
func OpenOrCreate(path string) (*PolicyMap, bool, error) {
	m := newMap(path)
	isNewMap, err := m.OpenOrCreate()
	return m, isNewMap, err
}

// Open opens the policymap at the specified path.
func Open(path string) (*PolicyMap, error) {
	m := newMap(path)
	if err := m.Open(); err != nil {
		return nil, err
	}
	return m, nil
}

// InitMapInfo updates the map info defaults for policy maps.
func InitMapInfo(maxEntries int) {
	MaxEntries = maxEntries
}
