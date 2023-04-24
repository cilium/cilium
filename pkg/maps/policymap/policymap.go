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

// policyEntryFlags is a new type used to define the flags used in the policy
// entry.
type policyEntryFlags uint8

const (
	policyFlagDeny policyEntryFlags = 1 << iota
)

func (pef policyEntryFlags) is(pf policyEntryFlags) bool {
	return pef&pf == pf
}

// String returns the string implementation of policyEntryFlags.
func (pef policyEntryFlags) String() string {
	if pef.is(policyFlagDeny) {
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

func (pe PolicyEntry) IsDeny() bool {
	return pe.Flags.is(policyFlagDeny)
}

func (pe *PolicyEntry) String() string {
	return fmt.Sprintf("%d %d %d", pe.GetProxyPort(), pe.Packets, pe.Bytes)
}

// PolicyKey represents a key in the BPF policy map for an endpoint. It must
// match the layout of policy_key in bpf/lib/common.h.
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type PolicyKey struct {
	Identity         uint32 `align:"sec_label"`
	DestPortNetwork  uint16 `align:"dport"` // In network byte-order
	Nexthdr          uint8  `align:"protocol"`
	TrafficDirection uint8  `align:"egress"`
}

// GetDestPort returns the DestPortNetwork in host byte order
func (k *PolicyKey) GetDestPort() uint16 {
	return byteorder.NetworkToHost16(k.DestPortNetwork)
}

// SizeofPolicyKey is the size of type PolicyKey.
const SizeofPolicyKey = int(unsafe.Sizeof(PolicyKey{}))

// PolicyEntry represents an entry in the BPF policy map for an endpoint. It must
// match the layout of policy_entry in bpf/lib/common.h.
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type PolicyEntry struct {
	ProxyPortNetwork uint16           `align:"proxy_port"` // In network byte-order
	Flags            policyEntryFlags `align:"deny"`
	AuthType         uint8            `align:"auth_type"`
	Pad1             uint16           `align:"pad1"`
	Pad2             uint16           `align:"pad2"`
	Packets          uint64           `align:"packets"`
	Bytes            uint64           `align:"bytes"`
}

// GetProxyPort returns the ProxyPortNetwork in host byte order
func (pe *PolicyEntry) GetProxyPort() uint16 {
	return byteorder.NetworkToHost16(pe.ProxyPortNetwork)
}

type policyEntryFlagParams struct {
	IsDeny bool
}

// getPolicyEntryFlags returns a policyEntryFlags from the policyEntryFlagParams.
func getPolicyEntryFlags(p policyEntryFlagParams) policyEntryFlags {
	var flags policyEntryFlags

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
	iDeny := p[i].PolicyEntry.IsDeny()
	jDeny := p[j].PolicyEntry.IsDeny()
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
	dport := key.GetDestPort()
	protoStr := u8proto.U8proto(key.Nexthdr).String()

	if dport != 0 {
		return fmt.Sprintf("%s: %d %d/%s", trafficDirectionString, key.Identity, dport, protoStr)
	}
	return fmt.Sprintf("%s: %d %s", trafficDirectionString, key.Identity, protoStr)
}

// NewKey returns a PolicyKey representing the specified parameters in network
// byte-order.
func NewKey(id uint32, dport uint16, proto uint8, trafficDirection uint8) PolicyKey {
	return PolicyKey{
		Identity:         id,
		DestPortNetwork:  byteorder.HostToNetwork16(dport),
		Nexthdr:          proto,
		TrafficDirection: trafficDirection,
	}
}

// newKey returns a PolicyKey representing the specified parameters in network
// byte-order.
func newKey(id uint32, dport uint16, proto u8proto.U8proto, trafficDirection trafficdirection.TrafficDirection) PolicyKey {
	return NewKey(id, dport, uint8(proto), trafficDirection.Uint8())
}

// newEntry returns a PolicyEntry representing the specified parameters in
// network byte-order.
func newEntry(authType uint8, proxyPort uint16, flags policyEntryFlags) PolicyEntry {
	return PolicyEntry{
		ProxyPortNetwork: byteorder.HostToNetwork16(proxyPort),
		Flags:            flags,
		AuthType:         authType,
	}
}

// AllowKey pushes an entry into the PolicyMap for the given PolicyKey k.
// Returns an error if the update of the PolicyMap fails.
func (pm *PolicyMap) AllowKey(key PolicyKey, authType uint8, proxyPort uint16) error {
	pef := getPolicyEntryFlags(policyEntryFlagParams{})
	entry := newEntry(authType, proxyPort, pef)
	return pm.Update(&key, &entry)
}

// Allow pushes an entry into the PolicyMap to allow traffic in the given
// `trafficDirection` for identity `id` with destination port `dport` over
// protocol `proto`. It is assumed that `dport` and `proxyPort` are in host byte-order.
func (pm *PolicyMap) Allow(id uint32, dport uint16, proto u8proto.U8proto, trafficDirection trafficdirection.TrafficDirection, authType uint8, proxyPort uint16) error {
	key := newKey(id, dport, proto, trafficDirection)
	return pm.AllowKey(key, authType, proxyPort)
}

// DenyKey pushes an entry into the PolicyMap for the given PolicyKey k.
// Returns an error if the update of the PolicyMap fails.
func (pm *PolicyMap) DenyKey(key PolicyKey) error {
	pef := getPolicyEntryFlags(policyEntryFlagParams{
		IsDeny: true,
	})
	entry := newEntry(0, 0, pef)
	return pm.Update(&key, &entry)
}

// Deny pushes an entry into the PolicyMap to deny traffic in the given
// `trafficDirection` for identity `id` with destination port `dport` over
// protocol `proto`. It is assumed that `dport` is in host byte-order.
func (pm *PolicyMap) Deny(id uint32, dport uint16, proto u8proto.U8proto, trafficDirection trafficdirection.TrafficDirection) error {
	key := newKey(id, dport, proto, trafficDirection)
	return pm.DenyKey(key)
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
	return pm.Map.Delete(&key)
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
	isNewMap, err := m.OpenOrCreate()
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
