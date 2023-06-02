// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package signalmap

import (
	"fmt"
	"os"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"

	"github.com/cilium/cilium/pkg/bpf"
)

const (
	// MapName is the BPF map name.
	MapName = "cilium_signals"
)

// Key is the index into the prog array map.
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type Key struct {
	index uint32
}

// Value is the program ID in the prog array map.
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type Value struct {
	progID uint32
}

// GetKeyPtr returns the unsafe pointer to the BPF key.
func (k *Key) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

// GetValuePtr returns the unsafe pointer to the BPF value.
func (v *Value) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

// String converts the key into a human readable string format.
func (k *Key) String() string { return fmt.Sprintf("%d", k.index) }

// String converts the value into a human readable string format.
func (v *Value) String() string { return fmt.Sprintf("%d", v.progID) }

// NewValue returns a new empty instance of the structure representing the BPF
// map value.
func (k Key) NewValue() bpf.MapValue { return &Value{} }

type signalMap struct {
	oldBpfMap  *bpf.Map
	ebpfMap    *ebpf.Map
	maxEntries int
}

// initMap creates the signal map in the kernel.
func initMap(maxEntries int) *signalMap {
	return &signalMap{
		maxEntries: maxEntries,
		oldBpfMap: bpf.NewMap(MapName,
			bpf.MapTypePerfEventArray,
			&Key{},
			int(unsafe.Sizeof(Key{})),
			&Value{},
			int(unsafe.Sizeof(Value{})),
			maxEntries,
			0,
			bpf.ConvertKeyValue,
		),
	}
}

func (sm *signalMap) open() error {
	if err := sm.oldBpfMap.Create(); err != nil {
		return err
	}
	path := bpf.MapPath(MapName)

	var err error
	sm.ebpfMap, err = ebpf.LoadPinnedMap(path, nil)
	return err
}

func (sm *signalMap) close() error {
	if sm.ebpfMap != nil {
		return sm.ebpfMap.Close()
	}
	return nil
}

func (sm *signalMap) NewReader() (PerfReader, error) {
	return perf.NewReader(sm.ebpfMap, os.Getpagesize())
}

func (sm *signalMap) MapName() string {
	return MapName
}
