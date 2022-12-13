// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package probe

import (
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	bpfTypes "github.com/cilium/cilium/pkg/bpf/types"
	"github.com/cilium/cilium/pkg/option"
)

type probeKey struct {
	Prefixlen uint32
	Key       uint32
}

type probeValue struct {
	Value uint32
}

var (
	haveFullLPMOnce sync.Once
	haveFullLPM     bool
)

func (p *probeKey) String() string                  { return fmt.Sprintf("key=%d", p.Key) }
func (p *probeKey) GetKeyPtr() unsafe.Pointer       { return unsafe.Pointer(p) }
func (p *probeKey) NewValue() bpfTypes.MapValue     { return &probeValue{} }
func (p *probeKey) DeepCopyMapKey() bpfTypes.MapKey { return &probeKey{p.Prefixlen, p.Key} }

func (p *probeValue) String() string                      { return fmt.Sprintf("value=%d", p.Value) }
func (p *probeValue) GetValuePtr() unsafe.Pointer         { return unsafe.Pointer(p) }
func (p *probeValue) DeepCopyMapValue() bpfTypes.MapValue { return &probeValue{p.Value} }

// HaveFullLPM tests whether kernel supports fully functioning BPF LPM map
// with proper bpf.GetNextKey() traversal. Needs 4.16 or higher.
func HaveFullLPM() bool {
	haveFullLPMOnce.Do(func() {
		mapName := "cilium_test"
		m := bpf.NewMap(mapName, bpf.MapTypeLPMTrie,
			&probeKey{}, int(unsafe.Sizeof(probeKey{})),
			&probeValue{}, int(unsafe.Sizeof(probeValue{})),
			1, bpf.BPF_F_NO_PREALLOC, 0, bpf.ConvertKeyValue).WithCache().
			WithEvents(option.Config.GetEventBufferConfig(mapName))
		err := m.CreateUnpinned()
		defer m.Close()
		if err != nil {
			return
		}
		err = bpf.UpdateElement(m.GetFd(), m.Name(), unsafe.Pointer(&probeKey{}),
			unsafe.Pointer(&probeValue{}), bpf.BPF_ANY)
		if err != nil {
			return
		}
		err = bpf.GetNextKey(m.GetFd(), nil, unsafe.Pointer(&probeKey{}))
		if err != nil {
			return
		}

		haveFullLPM = true
	})

	return haveFullLPM
}

// HaveIPv6Support tests whether kernel can open an IPv6 socket. This will
// also implicitly auto-load IPv6 kernel module if available and not yet
// loaded.
func HaveIPv6Support() bool {
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_STREAM, 0)
	if errors.Is(err, unix.EAFNOSUPPORT) || errors.Is(err, unix.EPROTONOSUPPORT) {
		return false
	}
	unix.Close(fd)
	return true
}
