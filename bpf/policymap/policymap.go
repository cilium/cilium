package policymap

/*
#cgo CFLAGS: -I../include
#include <linux/bpf.h>
*/
import "C"

import (
	"bytes"
	"fmt"
	"unsafe"

	"github.com/noironetworks/cilium-net/common/bpf"
)

type PolicyMap struct {
	path string
	Fd   int
}

const (
	MAX_KEYS = 1024
)

func (e *PolicyEntry) String() string {
	return string(e.Action)
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

func (m *PolicyMap) AllowConsumer(id uint32) error {
	entry := PolicyEntry{Action: 1}
	return bpf.UpdateElement(m.Fd, unsafe.Pointer(&id), unsafe.Pointer(&entry), 0)
}

func (m *PolicyMap) DeleteConsumer(id uint32) error {
	return bpf.DeleteElement(m.Fd, unsafe.Pointer(&id))
}

func (m *PolicyMap) String() string {
	return m.path
}

func (m *PolicyMap) Dump() (string, error) {
	var buffer bytes.Buffer
	entries, err := m.DumpToSlice()
	if err != nil {
		return "", err
	}
	for _, entry := range entries {
		buffer.WriteString(fmt.Sprintf("%8d: %d %d %d\n",
			entry.ID, entry.Action, entry.Packets, entry.Bytes))
	}
	return buffer.String(), nil
}

func (m *PolicyMap) DumpToSlice() ([]PolicyEntryDump, error) {
	var key, nextKey uint32
	key = MAX_KEYS
	entries := []PolicyEntryDump{}
	for {
		var entry PolicyEntry
		err := bpf.GetNextKey(
			m.Fd,
			unsafe.Pointer(&key),
			unsafe.Pointer(&nextKey),
		)

		if err != nil {
			break
		}

		err = bpf.LookupElement(
			m.Fd,
			unsafe.Pointer(&nextKey),
			unsafe.Pointer(&entry),
		)

		if err != nil {
			return nil, err
		} else {
			eDump := PolicyEntryDump{ID: nextKey, PolicyEntry: entry}
			entries = append(entries, eDump)
		}

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
