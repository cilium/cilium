// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package signalmap

import (
	"fmt"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
)

var (
	MaxEntries int
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

// InitMap creates the signal map in the kernel.
func InitMap(maxEntries int) error {
	MaxEntries = maxEntries
	signalMap := bpf.NewMap(MapName,
		bpf.MapTypePerfEventArray,
		&Key{},
		int(unsafe.Sizeof(Key{})),
		&Value{},
		int(unsafe.Sizeof(Value{})),
		MaxEntries,
		0,
		0,
		bpf.ConvertKeyValue,
	)
	_, err := signalMap.Create()
	return err
}
