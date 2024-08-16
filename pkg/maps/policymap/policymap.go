// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"fmt"
	"math/bits"
	"strconv"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"

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

	// SinglePortMask represents the mask argument required to lookup or
	// insert a single port key into the bpf map.
	SinglePortMask = 0xffff
)

// policyEntryFlags is a new type used to define the flags used in the policy
// entry.
type policyEntryFlags uint8

const (
	policyFlagDeny policyEntryFlags = 1 << iota
	policyFlagWildcardNexthdr
	policyFlagWildcardDestPort
)

func (pef policyEntryFlags) is(pf policyEntryFlags) bool {
	return pef&pf == pf
}

// String returns the string implementation of policyEntryFlags.
func (pef policyEntryFlags) String() string {
	var str []string

	if pef.is(policyFlagDeny) {
		str = append(str, "Deny")
	} else {
		str = append(str, "Allow")
	}
	if pef.is(policyFlagWildcardNexthdr) {
		str = append(str, "WildcardProtocol")
	}
	if pef.is(policyFlagWildcardDestPort) {
		str = append(str, "WildcardPort")
	}

	return strings.Join(str, ", ")
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

func (pe *PolicyEntry) New() bpf.MapValue { return &PolicyEntry{} }

// PolicyKey represents a key in the BPF policy map for an endpoint. It must
// match the layout of policy_key in bpf/lib/common.h.
type PolicyKey struct {
	Prefixlen        uint32 `align:"lpm_key"`
	Identity         uint32 `align:"sec_label"`
	TrafficDirection uint8  `align:"egress"`
	Nexthdr          uint8  `align:"protocol"`
	DestPortNetwork  uint16 `align:"dport"` // In network byte-order
}

// GetDestPort returns the DestPortNetwork in host byte order
func (k *PolicyKey) GetDestPort() uint16 {
	return byteorder.NetworkToHost16(k.DestPortNetwork)
}

// GetPortMask returns the port mask of the key
func (k *PolicyKey) GetPortMask() uint16 {
	if k.DestPortNetwork == 0 {
		return 0
	}
	prefixLen := k.Prefixlen - StaticPrefixBits
	if prefixLen == FullPrefixBits {
		return 0xffff
	}
	if prefixLen == 0 || prefixLen == NexthdrBits {
		return 0
	}
	portPrefixLen := prefixLen - NexthdrBits
	portLen := prefixLenPortLenMap[portPrefixLen]
	return ^portLen
}

const (
	sizeofPolicyKey = int(unsafe.Sizeof(PolicyKey{}))
	sizeofPrefixlen = int(unsafe.Sizeof(PolicyKey{}.Prefixlen))
	sizeofNexthdr   = int(unsafe.Sizeof(PolicyKey{}.Nexthdr))
	sizeofDestPort  = int(unsafe.Sizeof(PolicyKey{}.DestPortNetwork))

	NexthdrBits    = uint32(sizeofNexthdr) * 8
	DestPortBits   = uint32(sizeofDestPort) * 8
	FullPrefixBits = NexthdrBits + DestPortBits

	StaticPrefixBits = uint32(sizeofPolicyKey-sizeofPrefixlen)*8 - FullPrefixBits
)

// PolicyEntry represents an entry in the BPF policy map for an endpoint. It must
// match the layout of policy_entry in bpf/lib/common.h.
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
	IsDeny             bool
	IsWildcardNexthdr  bool
	IsWildcardDestPort bool
}

// getPolicyEntryFlags returns a policyEntryFlags from the policyEntryFlagParams.
func getPolicyEntryFlags(p policyEntryFlagParams) policyEntryFlags {
	var flags policyEntryFlags

	if p.IsDeny {
		flags |= policyFlagDeny
	}
	if p.IsWildcardNexthdr {
		flags |= policyFlagWildcardNexthdr
	}
	if p.IsWildcardDestPort {
		flags |= policyFlagWildcardDestPort
	}

	return flags
}

// CallKey is the index into the prog array map.
type CallKey struct {
	index uint32
}

// CallValue is the program ID in the prog array map.
type CallValue struct {
	progID uint32
}

// String converts the key into a human readable string format.
func (k *CallKey) String() string  { return strconv.FormatUint(uint64(k.index), 10) }
func (k *CallKey) New() bpf.MapKey { return &CallKey{} }

// String converts the value into a human readable string format.
func (v *CallValue) String() string    { return strconv.FormatUint(uint64(v.progID), 10) }
func (v *CallValue) New() bpf.MapValue { return &CallValue{} }

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

// prefixLenPortLenMaskMap is the map of all the possible prefix lengths
// of the port field in the policy key, corresponding to the port
// length of that mask. The "16" prefix len implies a full mask (that is,
// 0 additional ports) and makes the default return value, 0, useful.
var prefixLenPortLenMap = map[uint32]uint16{
	0:  0xffff,
	1:  0x7fff,
	2:  0x3fff,
	3:  0x1fff,
	4:  0xfff,
	5:  0x7ff,
	6:  0x3ff,
	7:  0x1ff,
	8:  0xff,
	9:  0x7f,
	10: 0x3f,
	11: 0x1f,
	12: 0xf,
	13: 0x7,
	14: 0x3,
	15: 0x1,
}

func (key *PolicyKey) PortProtoString() string {
	dport := key.GetDestPort()
	protoStr := u8proto.U8proto(key.Nexthdr).String()
	prefixLen := key.Prefixlen - StaticPrefixBits
	portPrefixLen := prefixLen - NexthdrBits

	switch {
	case prefixLen == 0, prefixLen == NexthdrBits:
		// Protocol wildcarded or specified, wildcarded port
		return protoStr
	case prefixLen > NexthdrBits && prefixLen < FullPrefixBits:
		// Protocol specified, partially wildcarded port
		portLen := prefixLenPortLenMap[portPrefixLen]
		return fmt.Sprintf("%d-%d/%s", dport, dport+portLen, protoStr)
	case prefixLen == FullPrefixBits:
		// Both protocol and port specified, nothing wildcarded
		return fmt.Sprintf("%d/%s", dport, protoStr)
	default:
		// Invalid prefix length
		return fmt.Sprintf("<INVALID PREFIX LENGTH: %d>", prefixLen)
	}
}

func (key *PolicyKey) String() string {
	trafficDirectionString := trafficdirection.TrafficDirection(key.TrafficDirection).String()
	portProtoStr := key.PortProtoString()
	return fmt.Sprintf("%s: %d %s", trafficDirectionString, key.Identity, portProtoStr)
}

func (key *PolicyKey) New() bpf.MapKey { return &PolicyKey{} }

// NewKey returns a PolicyKey representing the specified parameters in network
// byte-order.
func NewKey(id uint32, dport, mask uint16, proto uint8, trafficDirection uint8) PolicyKey {

	prefixLen := StaticPrefixBits
	if proto != 0 || dport != 0 {
		prefixLen += NexthdrBits
		if dport != 0 {
			prefixLen += DestPortBits - uint32(bits.TrailingZeros16(mask))
		}
	}
	return PolicyKey{
		Prefixlen:        prefixLen,
		Identity:         id,
		TrafficDirection: trafficDirection,
		Nexthdr:          proto,
		DestPortNetwork:  byteorder.HostToNetwork16(dport),
	}
}

// newKey returns a PolicyKey representing the specified parameters in network
// byte-order.
func newKey(id uint32, dport, portMask uint16, proto u8proto.U8proto, trafficDirection trafficdirection.TrafficDirection) PolicyKey {
	return NewKey(id, dport, portMask, uint8(proto), trafficDirection.Uint8())
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

// newAllowEntry returns an allow PolicyEntry for the specified parameters in
// network byte-order.
// This is separated out to be used in unit testing.
func newAllowEntry(key PolicyKey, authType uint8, proxyPort uint16) PolicyEntry {
	pef := getPolicyEntryFlags(policyEntryFlagParams{
		IsWildcardNexthdr:  key.Nexthdr == 0,
		IsWildcardDestPort: key.DestPortNetwork == 0,
	})
	return newEntry(authType, proxyPort, pef)
}

// newDenyEntry returns a deny PolicyEntry for the specified parameters in
// network byte-order.
// This is separated out to be used in unit testing.
func newDenyEntry(key PolicyKey) PolicyEntry {
	pef := getPolicyEntryFlags(policyEntryFlagParams{
		IsDeny:             true,
		IsWildcardNexthdr:  key.Nexthdr == 0,
		IsWildcardDestPort: key.DestPortNetwork == 0,
	})
	return newEntry(0, 0, pef)
}

// AllowKey pushes an entry into the PolicyMap for the given PolicyKey k.
// Returns an error if the update of the PolicyMap fails.
func (pm *PolicyMap) AllowKey(key PolicyKey, authType uint8, proxyPort uint16) error {
	entry := newAllowEntry(key, authType, proxyPort)
	return pm.Update(&key, &entry)
}

// Allow pushes an entry into the PolicyMap to allow traffic in the given
// `trafficDirection` for identity `id` with destination port `dport` over
// protocol `proto`. It is assumed that `dport` and `proxyPort` are in host byte-order.
func (pm *PolicyMap) Allow(id uint32, dport, portMask uint16, proto u8proto.U8proto, trafficDirection trafficdirection.TrafficDirection, authType uint8, proxyPort uint16) error {
	key := newKey(id, dport, portMask, proto, trafficDirection)
	return pm.AllowKey(key, authType, proxyPort)
}

// DenyKey pushes an entry into the PolicyMap for the given PolicyKey k.
// Returns an error if the update of the PolicyMap fails.
func (pm *PolicyMap) DenyKey(key PolicyKey) error {
	entry := newDenyEntry(key)
	return pm.Update(&key, &entry)
}

// Deny pushes an entry into the PolicyMap to deny traffic in the given
// `trafficDirection` for identity `id` with destination port `dport` over
// protocol `proto`. It is assumed that `dport` is in host byte-order.
func (pm *PolicyMap) Deny(id uint32, dport, portMask uint16, proto u8proto.U8proto, trafficDirection trafficdirection.TrafficDirection) error {
	key := newKey(id, dport, portMask, proto, trafficDirection)
	return pm.DenyKey(key)
}

// Exists determines whether PolicyMap currently contains an entry that
// allows traffic in `trafficDirection` for identity `id` with destination port
// `dport`over protocol `proto`. It is assumed that `dport` is in host byte-order.
func (pm *PolicyMap) Exists(id uint32, dport, portMask uint16, proto u8proto.U8proto, trafficDirection trafficdirection.TrafficDirection) bool {
	key := newKey(id, dport, portMask, proto, trafficDirection)
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
func (pm *PolicyMap) Delete(id uint32, dport, portMask uint16, proto u8proto.U8proto, trafficDirection trafficdirection.TrafficDirection) error {
	k := newKey(id, dport, portMask, proto, trafficDirection)
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
			Key:         *key.(*PolicyKey),
			PolicyEntry: *value.(*PolicyEntry),
		}
		entries = append(entries, eDump)
	}
	err := pm.DumpWithCallback(cb)

	return entries, err
}

func newMap(path string) *PolicyMap {
	mapType := ebpf.LPMTrie
	flags := bpf.GetPreAllocateMapFlags(mapType)
	return &PolicyMap{
		Map: bpf.NewMap(
			path,
			mapType,
			&PolicyKey{},
			&PolicyEntry{},
			MaxEntries,
			flags,
		).WithGroupName("endpoint_policy"),
	}
}

// OpenOrCreate opens (or creates) a policy map at the specified path, which
// is used to govern which peer identities can communicate with the endpoint
// protected by this map.
func OpenOrCreate(path string) (*PolicyMap, error) {
	m := newMap(path)
	err := m.OpenOrCreate()
	return m, err
}

// Create creates a policy map at the specified path.
func Create(path string) error {
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
func InitCallMaps() error {
	policyCallMap := bpf.NewMap(PolicyCallMapName,
		ebpf.ProgramArray,
		&CallKey{},
		&CallValue{},
		int(PolicyCallMaxEntries),
		0,
	)
	err := policyCallMap.Create()

	if err == nil {
		policyEgressCallMap := bpf.NewMap(PolicyEgressCallMapName,
			ebpf.ProgramArray,
			&CallKey{},
			&CallValue{},
			int(PolicyCallMaxEntries),
			0,
		)

		err = policyEgressCallMap.Create()
	}
	return err
}
