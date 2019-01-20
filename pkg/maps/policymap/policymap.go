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

package policymap

import (
	"bytes"
	"fmt"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/u8proto"

	"github.com/sirupsen/logrus"
)

const (
	// CallMapName is the name of the map to do tail calls into policy
	// enforcement programs
	CallMapName = "cilium_policy"

	MapName = "cilium_policy_"

	// MaxEntries is the upper limit of entries in the per endpoint policy
	// table
	MaxEntries = 16384

	// ProgArrayMaxEntries is the upper limit of entries in the program
	// array for the tail calls to jump into the endpoint specific policy
	// programs. This number *MUST* be identical to the maximum endponit ID.
	ProgArrayMaxEntries = ^uint16(0)

	// AllPorts is used to ignore the L4 ports in PolicyMap lookups; all ports
	// are allowed. In the datapath, this is represented with the value 0 in the
	// port field of map elements.
	AllPorts = uint16(0)
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "map-policy")

type PolicyMap struct {
	path  string
	Fd    int
	mutex lock.Mutex
}

func (pe *PolicyEntry) String() string {
	return fmt.Sprintf("%d %d %d", pe.ProxyPort, pe.Packets, pe.Bytes)
}

// PolicyKey represents a key in the BPF policy map for an endpoint. It must
// match the layout of policy_key in bpf/lib/common.h.
type PolicyKey struct {
	Identity         uint32
	DestPort         uint16 // In network byte-order
	Nexthdr          uint8
	TrafficDirection uint8
}

// PolicyEntry represents an entry in the BPF policy map for an endpoint. It must
// match the layout of policy_entry in bpf/lib/common.h.
type PolicyEntry struct {
	ProxyPort uint16 // In network byte-order
	Pad0      uint16
	Pad1      uint16
	Pad2      uint16
	Packets   uint64
	Bytes     uint64
}

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

func (key *PolicyKey) String() string {

	trafficDirectionString := (trafficdirection.TrafficDirection)(key.TrafficDirection).String()
	if key.DestPort != 0 {
		return fmt.Sprintf("%s: %d %d/%d", trafficDirectionString, key.Identity, byteorder.NetworkToHost(key.DestPort), key.Nexthdr)
	}
	return fmt.Sprintf("%s: %d", trafficDirectionString, key.Identity)
}

// GetIdentity returns the identity in key.
func (key *PolicyKey) GetIdentity() uint32 {
	return key.Identity
}

// GetPort returns the port in key. Note that the port may be in host or network
// byte-order.
func (key *PolicyKey) GetPort() uint16 {
	return key.DestPort
}

// GetProto returns the protocol for key.
func (key *PolicyKey) GetProto() uint8 {
	return key.Nexthdr
}

// GetDirection returns the traffic direction for key.
func (key *PolicyKey) GetDirection() uint8 {
	return key.TrafficDirection
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

// AllowKey pushes an entry into the PolicyMap for the given PolicyKey k.
// Returns an error if the update of the PolicyMap fails.
func (pm *PolicyMap) AllowKey(k PolicyKey, proxyPort uint16) error {
	return pm.Allow(k.Identity, k.DestPort, u8proto.U8proto(k.Nexthdr), trafficdirection.TrafficDirection(k.TrafficDirection), proxyPort)
}

// Allow pushes an entry into the PolicyMap to allow traffic in the given
// `trafficDirection` for identity `id` with destination port `dport` over
// protocol `proto`. It is assumed that `dport` and `proxyPort` are in host byte-order.
func (pm *PolicyMap) Allow(id uint32, dport uint16, proto u8proto.U8proto, trafficDirection trafficdirection.TrafficDirection, proxyPort uint16) error {
	key := PolicyKey{Identity: id, DestPort: byteorder.HostToNetwork(dport).(uint16), Nexthdr: uint8(proto), TrafficDirection: trafficDirection.Uint8()}
	entry := PolicyEntry{ProxyPort: byteorder.HostToNetwork(proxyPort).(uint16)}
	return bpf.UpdateElement(pm.Fd, unsafe.Pointer(&key), unsafe.Pointer(&entry), 0)
}

// Exists determines whether PolicyMap currently contains an entry that
// allows traffic in `trafficDirection` for identity `id` with destination port
// `dport`over protocol `proto`. It is assumed that `dport` is in host byte-order.
func (pm *PolicyMap) Exists(id uint32, dport uint16, proto u8proto.U8proto, trafficDirection trafficdirection.TrafficDirection) bool {
	key := PolicyKey{Identity: id, DestPort: byteorder.HostToNetwork(dport).(uint16), Nexthdr: uint8(proto), TrafficDirection: trafficDirection.Uint8()}
	var entry PolicyEntry
	return bpf.LookupElement(pm.Fd, unsafe.Pointer(&key), unsafe.Pointer(&entry)) == nil
}

// DeleteKey deletes the key-value pair from the given PolicyMap with PolicyKey
// k. Returns an error if deletion from the PolicyMap fails.
func (pm *PolicyMap) DeleteKey(k PolicyKey) error {
	return pm.Delete(k.Identity, k.DestPort, u8proto.U8proto(k.Nexthdr), trafficdirection.TrafficDirection(k.TrafficDirection))
}

// Delete removes an entry from the PolicyMap for identity `id`
// sending traffic in direction `trafficDirection` with destination port `dport`
// over protocol `proto`. It is assumed that `dport` is in host byte-order.
// Returns an error if the deletion did not succeed.
func (pm *PolicyMap) Delete(id uint32, dport uint16, proto u8proto.U8proto, trafficDirection trafficdirection.TrafficDirection) error {
	key := PolicyKey{Identity: id, DestPort: byteorder.HostToNetwork(dport).(uint16), Nexthdr: uint8(proto), TrafficDirection: trafficDirection.Uint8()}
	return bpf.DeleteElement(pm.Fd, unsafe.Pointer(&key))
}

// DeleteEntry removes an entry from the PolicyMap. It can be used in
// conjunction with DumpToSlice() to inspect and delete map entries.
func (pm *PolicyMap) DeleteEntry(entry *PolicyEntryDump) error {
	return bpf.DeleteElement(pm.Fd, unsafe.Pointer(&entry.Key))
}

func (pm *PolicyMap) String() string {
	return pm.path
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
	var key, nextKey PolicyKey
	entries := PolicyEntriesDump{}
	for {
		var entry PolicyEntry
		err := bpf.GetNextKey(
			pm.Fd,
			unsafe.Pointer(&key),
			unsafe.Pointer(&nextKey),
		)

		if err != nil {
			break
		}

		err = bpf.LookupElement(
			pm.Fd,
			unsafe.Pointer(&nextKey),
			unsafe.Pointer(&entry),
		)

		if err != nil {
			return nil, err
		}
		eDump := PolicyEntryDump{Key: nextKey, PolicyEntry: entry}
		entries = append(entries, eDump)

		key = nextKey
	}

	return entries, nil
}

// Flush deletes all entries from the given policy map
func (pm *PolicyMap) Flush() error {
	var key, nextKey PolicyKey
	for {
		err := bpf.GetNextKey(
			pm.Fd,
			unsafe.Pointer(&key),
			unsafe.Pointer(&nextKey),
		)

		// FIXME: Ignore delete errors?
		bpf.DeleteElement(
			pm.Fd,
			unsafe.Pointer(&key),
		)

		if err != nil {
			break
		}

		key = nextKey
	}
	return nil
}

// Close closes the FD of the given PolicyMap. Returns an error if the close
// operation failed. If the close operation succeeds, pm's file descriptor
// is set to zero.
func (pm *PolicyMap) Close() error {
	pm.mutex.Lock()
	defer pm.mutex.Unlock()
	log.WithFields(logrus.Fields{
		logfields.BPFMapPath: pm.path,
		logfields.BPFMapFD:   pm.Fd,
	}).Debug("closing PolicyMap")
	err := bpf.ObjClose(pm.Fd)

	// Unconditionally set file descriptor to zero so that if accesses are
	// attempted on this PolicyMap even after this call to Close, the accesses
	// aren't to a file descriptor that has been reassigned elsewhere. Even
	// if the close fails, per close(2) manpages:
	//
	// "on Linux and many other implementations, where, as with other errors that
	// may be reported by close(), the file descriptor is guaranteed to be
	// closed".
	//
	// We are relying upon this behavior, so we can safely zero out the file
	// descriptor in the PolicyMap.
	pm.Fd = 0

	return err
}

func OpenMap(path string) (*PolicyMap, bool, error) {
	mapType := bpf.BPF_MAP_TYPE_HASH
	flags := bpf.GetPreAllocateMapFlags(bpf.MapType(mapType))
	fd, isNewMap, err := bpf.OpenOrCreateMap(
		path,
		mapType,
		uint32(unsafe.Sizeof(PolicyKey{})),
		uint32(unsafe.Sizeof(PolicyEntry{})),
		MaxEntries,
		flags, 0,
	)

	if err != nil {
		return nil, false, err
	}

	m := &PolicyMap{path: path, Fd: fd}

	return m, isNewMap, nil
}

func OpenGlobalMap(path string) (*PolicyMap, error) {
	fd, err := bpf.ObjGet(path)
	if err != nil {
		return nil, err
	}

	m := &PolicyMap{path: path, Fd: fd}
	return m, nil
}
