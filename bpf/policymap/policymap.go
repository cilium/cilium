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
	fd int
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
	return bpf.UpdateElement(m.fd, unsafe.Pointer(&id), unsafe.Pointer(&entry), 0)
}

func (m *PolicyMap) DeleteConsumer(id uint32) error {
	return bpf.DeleteElement(m.fd, unsafe.Pointer(&id))
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

	m := new(PolicyMap)
	m.fd = fd

	return m, nil
}
