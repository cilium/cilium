package ctmap

/*
#include <linux/bpf.h>
#include <sys/resource.h>
*/
import "C"

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"

	"github.com/noironetworks/cilium-net/common/bpf"
	"github.com/noironetworks/cilium-net/common/types"
)

type CtMap struct {
	path string
	Fd   int
}

const (
	TUPLE_F_OUT     = 0
	TUPLE_F_IN      = 1
	TUPLE_F_RELATED = 2
)

const (
	// FIXME: Change to common.MaxKeys
	MAX_KEYS = 1024
)

type CtKey struct {
	addr    types.IPv6
	sport   uint16
	dport   uint16
	nexthdr types.U8proto
	flags   uint8
}

type CtEntry struct {
	rx_packets uint64
	rx_bytes   uint64
	tx_packets uint64
	tx_bytes   uint64
	lifetime   uint16
}

type CtEntryDump struct {
	Key   CtKey
	Value CtEntry
}

func (m *CtMap) String() string {
	return m.path
}

func (m *CtMap) Dump() (string, error) {
	var buffer bytes.Buffer
	entries, err := m.DumpToSlice()
	if err != nil {
		return "", err
	}
	for _, entry := range entries {
		if entry.Key.nexthdr == 0 {
			continue
		}

		if entry.Key.flags&TUPLE_F_IN != 0 {
			buffer.WriteString(fmt.Sprintf(":%d => [%s]:%d ",
				entry.Key.sport, entry.Key.addr.String(), entry.Key.dport))

		} else {
			buffer.WriteString(fmt.Sprintf(":%d <= [%s]:%d ",
				entry.Key.dport, entry.Key.addr.String(), entry.Key.sport))
		}

		if entry.Key.flags&TUPLE_F_RELATED != 0 {
			buffer.WriteString("related ")
		}

		buffer.WriteString(fmt.Sprintf("proto=%s expires=%d rx_packets=%d rx_bytes=%d tx_packets=%d tx_bytes=%d\n",
			entry.Key.nexthdr.String(),
			entry.Value.lifetime,
			entry.Value.rx_packets,
			entry.Value.rx_bytes,
			entry.Value.tx_packets,
			entry.Value.tx_bytes))

	}
	return buffer.String(), nil
}

func (m *CtMap) DumpToSlice() ([]CtEntryDump, error) {
	var key, nextKey CtKey
	entries := []CtEntryDump{}
	for {
		var entry CtEntry
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
			eDump := CtEntryDump{Key: nextKey, Value: entry}
			entries = append(entries, eDump)
		}

		key = nextKey
	}

	return entries, nil
}

func (m *CtMap) GC(interval uint16) int {
	var key, nextKey CtKey

	deleted := 0

	for {
		var entry CtEntry
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
			break
		}

		if entry.lifetime <= interval {
			bpf.DeleteElement(m.Fd, unsafe.Pointer(&nextKey))
			deleted++
		} else {
			entry.lifetime -= interval
			bpf.UpdateElement(m.Fd, unsafe.Pointer(&nextKey), unsafe.Pointer(&entry), 0)
		}

		key = nextKey
	}

	return deleted
}

func OpenMap(path string) (*CtMap, error) {
	var fd int

	rl := syscall.Rlimit{
		Cur: math.MaxUint64,
		Max: math.MaxUint64,
	}

	err := syscall.Setrlimit(C.RLIMIT_MEMLOCK, &rl)
	if err != nil {
		return nil, fmt.Errorf("Unable to increase rlimit: %s", err)
	}

	if _, err = os.Stat(path); os.IsNotExist(err) {
		mapDir := filepath.Dir(path)
		if _, err = os.Stat(mapDir); os.IsNotExist(err) {
			if err = os.MkdirAll(mapDir, 0755); err != nil {
				return nil, fmt.Errorf("Unable create map base directory: %s", err)
			}
		}

		fd, err = bpf.CreateMap(
			C.BPF_MAP_TYPE_HASH,
			uint32(unsafe.Sizeof(CtKey{})),
			uint32(unsafe.Sizeof(CtEntry{})),
			MAX_KEYS,
		)

		if err != nil {
			return nil, err
		}

		err = bpf.ObjPin(fd, path)
		if err != nil {
			return nil, err
		}
	} else {
		fd, err = bpf.ObjGet(path)
		if err != nil {
			return nil, err
		}
	}

	m := &CtMap{path: path, Fd: fd}

	return m, nil
}
