// Copyright 2019 Authors of Cilium
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

package probe

import (
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"

	"golang.org/x/sys/unix"
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

func (p *probeKey) String() string             { return fmt.Sprintf("key=%d", p.Key) }
func (p *probeKey) GetKeyPtr() unsafe.Pointer  { return unsafe.Pointer(p) }
func (p *probeKey) NewValue() bpf.MapValue     { return &probeValue{} }
func (p *probeKey) DeepCopyMapKey() bpf.MapKey { return &probeKey{p.Prefixlen, p.Key} }

func (p *probeValue) String() string                 { return fmt.Sprintf("value=%d", p.Value) }
func (p *probeValue) GetValuePtr() unsafe.Pointer    { return unsafe.Pointer(p) }
func (p *probeValue) DeepCopyMapValue() bpf.MapValue { return &probeValue{p.Value} }

// HaveFullLPM tests whether kernel supports fully functioning BPF LPM map
// with proper bpf.GetNextKey() traversal. Needs 4.16 or higher.
func HaveFullLPM() bool {
	haveFullLPMOnce.Do(func() {

		var oldLim unix.Rlimit

		tmpLim := unix.Rlimit{
			Cur: unix.RLIM_INFINITY,
			Max: unix.RLIM_INFINITY,
		}
		if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &oldLim); err != nil {
			return
		}
		// Otherwise opening the map might fail with EPERM
		if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &tmpLim); err != nil {
			return
		}
		defer unix.Setrlimit(unix.RLIMIT_MEMLOCK, &oldLim)

		m := bpf.NewMap("cilium_test", bpf.MapTypeLPMTrie,
			&probeKey{}, int(unsafe.Sizeof(probeKey{})),
			&probeValue{}, int(unsafe.Sizeof(probeValue{})),
			1, bpf.BPF_F_NO_PREALLOC, 0, bpf.ConvertKeyValue).WithCache()
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
