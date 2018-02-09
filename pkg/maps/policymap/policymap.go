// Copyright 2016-2017 Authors of Cilium
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
	"github.com/cilium/cilium/pkg/comparator"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

const (
	MapName = "cilium_policy_"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "policy-map")
)

type PolicyMap struct {
	path string
	Fd   int
}

const (
	MAX_KEYS = 1024
)

func (pe *PolicyEntry) String() string {
	return string(pe.Action)
}

type policyKey struct {
	Identity uint32
	DestPort uint16 // In network byte-order
	Nexthdr  uint8
	Pad      uint8
}

type PolicyEntry struct {
	Action  uint32
	Pad     uint32
	Packets uint64
	Bytes   uint64
}

func (pe *PolicyEntry) Add(oPe PolicyEntry) {
	pe.Packets += oPe.Packets
	pe.Bytes += oPe.Bytes
}

type PolicyEntryDump struct {
	PolicyEntry
	Key policyKey
}

func (key *policyKey) String() string {
	if key.DestPort != 0 {
		return fmt.Sprintf("%d %d/%d", key.Identity, byteorder.NetworkToHost(key.DestPort), key.Nexthdr)
	}
	return fmt.Sprintf("%d", key.Identity)
}

// AllowIdentity adds an entry into the PolicyMap with key id. Returns an error
// if the addition did not complete successfully.
func (pm *PolicyMap) AllowIdentity(id uint32) error {
	key := policyKey{Identity: id}
	entry := PolicyEntry{Action: 1}
	return bpf.UpdateElement(pm.Fd, unsafe.Pointer(&key), unsafe.Pointer(&entry), 0)
}

// AllowL4 pushes an entry into the PolicyMap to allow source identity `id`
// send traffic with destination port `dport` over protocol `proto`.
func (pm *PolicyMap) AllowL4(id uint32, dport uint16, proto uint8) error {
	key := policyKey{Identity: id, DestPort: byteorder.HostToNetwork(dport).(uint16), Nexthdr: proto}
	entry := PolicyEntry{Action: 1}
	return bpf.UpdateElement(pm.Fd, unsafe.Pointer(&key), unsafe.Pointer(&entry), 0)
}

// IdentityExists returns whether there is an entry in the PolicyMap with key id.
func (pm *PolicyMap) IdentityExists(id uint32) bool {
	key := policyKey{Identity: id}
	var entry PolicyEntry
	return bpf.LookupElement(pm.Fd, unsafe.Pointer(&key), unsafe.Pointer(&entry)) == nil
}

// L4Exists determines whether PolicyMap currently contains an entry that
// allows source identity `id` send traffic with destination port `dport` over
// protocol `proto`.
func (pm *PolicyMap) L4Exists(id uint32, dport uint16, proto uint8) bool {
	key := policyKey{Identity: id, DestPort: byteorder.HostToNetwork(dport).(uint16), Nexthdr: proto}
	var entry PolicyEntry
	return bpf.LookupElement(pm.Fd, unsafe.Pointer(&key), unsafe.Pointer(&entry)) == nil
}

// DeleteIdentity deletes id from the PolicyMap. Returns an error if the deletion
// did not succeed.
func (pm *PolicyMap) DeleteIdentity(id uint32) error {
	key := policyKey{Identity: id}
	return bpf.DeleteElement(pm.Fd, unsafe.Pointer(&key))
}

// DeleteL4 removes an entry from the PolicyMap for source identity `id`
// sending traffic with destination port `dport` over protocol `proto`.
func (pm *PolicyMap) DeleteL4(id uint32, dport uint16, proto uint8) error {
	key := policyKey{Identity: id, DestPort: byteorder.HostToNetwork(dport).(uint16), Nexthdr: proto}
	return bpf.DeleteElement(pm.Fd, unsafe.Pointer(&key))
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
		buffer.WriteString(fmt.Sprintf("%20s: %d %d %d\n",
			entry.Key.String(), entry.Action, entry.Packets, entry.Bytes))
	}
	return buffer.String(), nil
}

func (pm *PolicyMap) DumpToSlice() ([]PolicyEntryDump, error) {
	var key, nextKey policyKey
	entries := []PolicyEntryDump{}
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
	var key, nextKey policyKey
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

// Close closes the FD of the given PolicyMap
func (pm *PolicyMap) Close() error {
	return bpf.ObjClose(pm.Fd)
}

// Validate checks the map pinned to the specified path to ensure that the map
// attributes such as type, key length, value length are the same as for the
// current version of Cilium.
func Validate(path string) (bool, error) {
	dummy := bpf.NewMap(path, bpf.BPF_MAP_TYPE_HASH,
		int(unsafe.Sizeof(policyKey{})),
		int(unsafe.Sizeof(PolicyEntry{})), MAX_KEYS, 0)

	existing, err := bpf.OpenMap(path)
	if err != nil {
		return true, err
	}

	logging.MultiLine(log.Debug, comparator.Compare(existing, dummy))

	if existing != nil && !existing.DeepEquals(dummy) {
		return false, nil
	}

	return true, nil
}

func OpenMap(path string) (*PolicyMap, bool, error) {
	fd, isNewMap, err := bpf.OpenOrCreateMap(
		path,
		bpf.BPF_MAP_TYPE_HASH,
		uint32(unsafe.Sizeof(policyKey{})),
		uint32(unsafe.Sizeof(PolicyEntry{})),
		MAX_KEYS,
		0,
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
