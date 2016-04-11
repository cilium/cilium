package policymap

/*
#include <linux/bpf.h>
#include <sys/resource.h>
*/
import "C"

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"syscall"
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
	output := ""
	var key, nextKey uint32
	key = MAX_KEYS
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
			return "", err
		} else {
			output = output + fmt.Sprintf("%8d: %d %d %d\n",
				nextKey, entry.Action, entry.Packets, entry.Bytes)
		}

		key = nextKey
	}

	return output, nil
}

func OpenMap(path string) (*PolicyMap, error) {
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
			uint32(unsafe.Sizeof(uint32(0))),
			uint32(unsafe.Sizeof(PolicyEntry{})),
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

	m := &PolicyMap{path: path, Fd: fd}

	return m, nil
}
