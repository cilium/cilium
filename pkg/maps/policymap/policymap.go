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

/*
#cgo CFLAGS: -I../../../bpf/include
#include <linux/bpf.h>
*/
import "C"

import (
	"bytes"
	"fmt"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
)

const (
	MapName = "cilium_policy_"
)

type PolicyMap struct {
	path string
	Fd   int
}

func (pm *PolicyMap) DeepCopy() *PolicyMap {
	return &PolicyMap{
		path: pm.path,
		Fd:   pm.Fd,
	}
}

const (
	MAX_KEYS = 1024
)

func (pe *PolicyEntry) String() string {
	return string(pe.Action)
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
	ID uint32
}

func (pm *PolicyMap) AllowConsumer(id uint32) error {
	entry := PolicyEntry{Action: 1}
	return bpf.UpdateElement(pm.Fd, unsafe.Pointer(&id), unsafe.Pointer(&entry), 0)
}

func (pm *PolicyMap) ConsumerExists(id uint32) bool {
	var entry PolicyEntry
	return bpf.LookupElement(pm.Fd, unsafe.Pointer(&id), unsafe.Pointer(&entry)) == nil
}

func (pm *PolicyMap) DeleteConsumer(id uint32) error {
	return bpf.DeleteElement(pm.Fd, unsafe.Pointer(&id))
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
		buffer.WriteString(fmt.Sprintf("%8d: %d %d %d\n",
			entry.ID, entry.Action, entry.Packets, entry.Bytes))
	}
	return buffer.String(), nil
}

func (pm *PolicyMap) DumpToSlice() ([]PolicyEntryDump, error) {
	var key, nextKey uint32
	key = MAX_KEYS
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
		eDump := PolicyEntryDump{ID: nextKey, PolicyEntry: entry}
		entries = append(entries, eDump)

		key = nextKey
	}

	return entries, nil
}

func OpenMap(path string) (*PolicyMap, bool, error) {
	fd, isNewMap, err := bpf.OpenOrCreateMap(
		path,
		C.BPF_MAP_TYPE_HASH,
		uint32(unsafe.Sizeof(uint32(0))),
		uint32(unsafe.Sizeof(PolicyEntry{})),
		MAX_KEYS,
	)

	if err != nil {
		return nil, false, err
	}

	m := &PolicyMap{path: path, Fd: fd}

	return m, isNewMap, nil
}
