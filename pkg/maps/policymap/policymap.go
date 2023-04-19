// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"fmt"
	"strconv"
	"strings"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/u8proto"
)

const (
	// PolicyCallMapName is the name of the map to do tail calls into policy
	// enforcement programs.
	PolicyCallMapName = "cilium_call_policy"

	// PolicyEgressCallMapName is the name of the map to do tail calls into egress policy
	// enforcement programs.
	PolicyEgressCallMapName = "cilium_egresscall_policy"

	// MapName is the prefix for endpoint-specific policy maps which map
	// identity+ports+direction to whether the policy allows communication
	// with that identity on that port for that direction.
	MapName = "cilium_policy_"

	// PolicyCallMaxEntries is the upper limit of entries in the program
	// array for the tail calls to jump into the endpoint specific policy
	// programs. This number *MUST* be identical to the maximum endpoint ID.
	PolicyCallMaxEntries = ^uint16(0)

	// AllPorts is used to ignore the L4 ports in PolicyMap lookups; all ports
	// are allowed. In the datapath, this is represented with the value 0 in the
	// port field of map elements.
	AllPorts = uint16(0)

	// PressureMetricThreshold sets the threshold over which map pressure will
	// be reported for the policy map.
	PressureMetricThreshold = 0.1
)

type policyFlag uint8

const (
	policyFlagDeny = 1 << iota
)

// PolicyEntryFlags is a new type used to define the flags used in the policy
// entry.
type PolicyEntryFlags uint8

// UInt8 returns the UInt8 representation of the PolicyEntryFlags.
func (pef PolicyEntryFlags) UInt8() uint8 {
	return uint8(pef)
}

func (pef PolicyEntryFlags) is(pf policyFlag) bool {
	return uint8(pef)&uint8(pf) != 0
}

func (pef PolicyEntryFlags) IsDeny() bool {
	return pef.is(policyFlagDeny)
}

// String returns the string implementation of PolicyEntryFlags.
func (pef PolicyEntryFlags) String() string {
	if pef.IsDeny() {
		return "Deny"
	}
	return "Allow"
}

var (
	// MaxEntries is the upper limit of entries in the per endpoint policy
	// table ie the maximum number of peer identities that the endpoint could
	// send/receive traffic to/from.. It is set by InitMapInfo(), but unit
	// tests use the initial value below.
	// The default value of this upper limit is 16384.
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

// SizeofPolicyKey is the size of type PolicyKey.
const SizeofPolicyKey = int(unsafe.Sizeof(PolicyKey{}))

// PolicyEntry represents an entry in the BPF policy map for an endpoint. It must
// match the layout of policy_entry in bpf/lib/common.h.
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type PolicyEntry struct {
	ProxyPort uint16 `align:"proxy_port"` // In network byte-order
	Flags     uint8  `align:"deny"`
	AuthType  uint8  `align:"auth_type"`
	Pad1      uint16 `align:"pad1"`
	Pad2      uint16 `align:"pad2"`
	Packets   uint64 `align:"packets"`
	Bytes     uint64 `align:"bytes"`
}

// ToHost returns a copy of entry with fields converted from network byte-order
// to host-byte-order if necessary.
func (pe *PolicyEntry) ToHost() PolicyEntry {
	if pe == nil {
		return PolicyEntry{}
	}

	n := *pe
	n.ProxyPort = byteorder.NetworkToHost16(n.ProxyPort)
	return n
}

func (pe *PolicyEntry) SetFlags(flags uint8) {
	pe.Flags = flags
}

func (pe *PolicyEntry) GetFlags() uint8 {
	return pe.Flags
}

type PolicyEntryFlagParam struct {
	IsDeny bool
}

// NewPolicyEntryFlag returns a PolicyEntryFlags from the PolicyEntryFlagParam.
func NewPolicyEntryFlag(p *PolicyEntryFlagParam) PolicyEntryFlags {
	var flags PolicyEntryFlags

	if p.IsDeny {
		flags |= policyFlagDeny
	}

	return flags
}

// SizeofPolicyEntry is the size of type PolicyEntry.
const SizeofPolicyEntry = int(unsafe.Sizeof(PolicyEntry{}))

// CallKey is the index into the prog array map.
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type CallKey struct {
	index uint32
}

// CallValue is the program ID in the prog array map.
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type CallValue struct {
	progID uint32
}

// GetKeyPtr returns the unsafe pointer to the BPF key
func (k *CallKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

// GetValuePtr returns the unsafe pointer to the BPF value
func (v *CallValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

// String converts the key into a human readable string format.
func (k *CallKey) String() string { return strconv.FormatUint(uint64(k.index), 10) }

// String converts the value into a human readable string format.
func (v *CallValue) String() string { return strconv.FormatUint(uint64(v.progID), 10) }

// NewValue returns a new empty instance of the structure representing the BPF
// map value.
func (k CallKey) NewValue() bpf.MapValue { return &CallValue{} }

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

// String returns a string representation of PolicyEntriesDump
func (p PolicyEntriesDump) String() string {
	var sb strings.Builder
	for _, entry := range p {
		sb.WriteString(fmt.Sprintf("%20s: %s\n",
			entry.Key.String(), entry.PolicyEntry.String()))
	}
	return sb.String()
}

// Less is a function used to sort PolicyEntriesDump by Policy Type
// (Deny / Allow), TrafficDirection (Ingress / Egress) and Identity
// (ascending order).
func (p PolicyEntriesDump) Less(i, j int) bool {
	iDeny := PolicyEntryFlags(p[i].PolicyEntry.GetFlags()).IsDeny()
	jDeny := PolicyEntryFlags(p[j].PolicyEntry.GetFlags()).IsDeny()
	switch {
	case iDeny && !jDeny:
		return true
	case !iDeny && jDeny:
		return false
	}
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
		return fmt.Sprintf("%s: %d %d/%d", trafficDirectionString, key.Identity, byteorder.NetworkToHost16(key.DestPort), key.Nexthdr)
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
	n.DestPort = byteorder.NetworkToHost16(n.DestPort)
	return n
}

// ToNetwork returns a copy of key with fields converted from host byte-order
// to network-byte-order if necessary.
func (key *PolicyKey) ToNetwork() PolicyKey {
	if key == nil {
		return PolicyKey{}
	}

	n := *key
	n.DestPort = byteorder.HostToNetwork16(n.DestPort)
	return n
}

// newKey returns a PolicyKey representing the specified parameters in network
// byte-order.
func newKey(id uint32, dport uint16, proto u8proto.U8proto, trafficDirection trafficdirection.TrafficDirection) PolicyKey {
	return PolicyKey{
		Identity:         id,
		DestPort:         byteorder.HostToNetwork16(dport),
		Nexthdr:          uint8(proto),
		TrafficDirection: trafficDirection.Uint8(),
	}
}

// newEntry returns a PolicyEntry representing the specified parameters in
// network byte-order.
func newEntry(authType uint8, proxyPort uint16, flags PolicyEntryFlags) PolicyEntry {
	return PolicyEntry{
		ProxyPort: byteorder.HostToNetwork16(proxyPort),
		Flags:     flags.UInt8(),
		AuthType:  authType,
	}
}

// AllowKey pushes an entry into the PolicyMap for the given PolicyKey k.
// Returns an error if the update of the PolicyMap fails.
func (pm *PolicyMap) AllowKey(k PolicyKey, authType uint8, proxyPort uint16) error {
	return pm.Allow(k.Identity, k.DestPort, u8proto.U8proto(k.Nexthdr), trafficdirection.TrafficDirection(k.TrafficDirection), authType, proxyPort)
}

// Allow pushes an entry into the PolicyMap to allow traffic in the given
// `trafficDirection` for identity `id` with destination port `dport` over
// protocol `proto`. It is assumed that `dport` and `proxyPort` are in host byte-order.
func (pm *PolicyMap) Allow(id uint32, dport uint16, proto u8proto.U8proto, trafficDirection trafficdirection.TrafficDirection, authType uint8, proxyPort uint16) error {
	key := newKey(id, dport, proto, trafficDirection)
	pef := NewPolicyEntryFlag(&PolicyEntryFlagParam{})
	entry := newEntry(authType, proxyPort, pef)
	return pm.Update(&key, &entry)
}

// DenyKey pushes an entry into the PolicyMap for the given PolicyKey k.
// Returns an error if the update of the PolicyMap fails.
func (pm *PolicyMap) DenyKey(k PolicyKey) error {
	return pm.Deny(k.Identity, k.DestPort, u8proto.U8proto(k.Nexthdr), trafficdirection.TrafficDirection(k.TrafficDirection))
}

// Deny pushes an entry into the PolicyMap to deny traffic in the given
// `trafficDirection` for identity `id` with destination port `dport` over
// protocol `proto`. It is assumed that `dport` is in host byte-order.
func (pm *PolicyMap) Deny(id uint32, dport uint16, proto u8proto.U8proto, trafficDirection trafficdirection.TrafficDirection) error {
	key := newKey(id, dport, proto, trafficDirection)
	pef := NewPolicyEntryFlag(&PolicyEntryFlagParam{IsDeny: true})
	entry := newEntry(0, 0, pef)
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
	entries, err := pm.DumpToSlice()
	if err != nil {
		return "", err
	}
	return entries.String(), nil
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
	mapType := bpf.MapTypeHash
	flags := bpf.GetPreAllocateMapFlags(mapType)
	return &PolicyMap{
		Map: bpf.NewMap(
			path,
			mapType,
			&PolicyKey{},
			SizeofPolicyKey,
			&PolicyEntry{},
			SizeofPolicyEntry,
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
	// Open the map without triggring a warning if the map type, key, or value have changed.
	isNewMap, err := m.OpenOrCreateWithoutWarning()
	return m, isNewMap, err
}

// Create creates a policy map at the specified path.
func Create(path string) (bool, error) {
	m := newMap(path)
	return m.Create()
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

// InitCallMap creates the policy call maps in the kernel.
func InitCallMaps(haveEgressCallMap bool) error {
	policyCallMap := bpf.NewMap(PolicyCallMapName,
		bpf.MapTypeProgArray,
		&CallKey{},
		int(unsafe.Sizeof(CallKey{})),
		&CallValue{},
		int(unsafe.Sizeof(CallValue{})),
		int(PolicyCallMaxEntries),
		0,
		0,
		bpf.ConvertKeyValue,
	)
	_, err := policyCallMap.Create()

	if err == nil && haveEgressCallMap {
		policyEgressCallMap := bpf.NewMap(PolicyEgressCallMapName,
			bpf.MapTypeProgArray,
			&CallKey{},
			int(unsafe.Sizeof(CallKey{})),
			&CallValue{},
			int(unsafe.Sizeof(CallValue{})),
			int(PolicyCallMaxEntries),
			0,
			0,
			bpf.ConvertKeyValue,
		)

		_, err = policyEgressCallMap.Create()
	}
	return err
}
