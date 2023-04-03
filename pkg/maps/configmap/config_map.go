// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package configmap

import (
	"fmt"
	"sync"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
)

const (
	// MapName name of map used to pin map for datapath
	MapName = "cilium_runtime_config"

	// MaxEntries represents the maximum number of config entries.
	// Initially defined as 256, so that downgrade from a future version having more than one
	// entry works without necessarily resizing the map. Entries not known by the datapath
	// version are simply ignored.
	MaxEntries = 256
)

// Index is the index to the runtime config array.
type Index uint32

// All supported indices in one place.
// Must be in sync with RUNTIME_CONFIG_ enum in bpf/lib/common.h
const (
	UsedEntries Index = iota
)

// Value is the generic datapath runtime config value.
type Value uint64

// String pretty print the Index
func (k *Index) String() string {
	return fmt.Sprintf("%d", uint32(*k))
}

// GetKeyPtr returns the unsafe pointer to the BPF key
func (k *Index) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

// NewValue returns a new empty instance of the structure represeting the BPF
// map value
func (k *Index) NewValue() bpf.MapValue {
	var value Value
	return &value
}

// DeepCopyMapKey returns a deep copy of the map key
func (k *Index) DeepCopyMapKey() bpf.MapKey {
	index := *k
	return &index
}

// String pretty print the config Value.
func (v *Value) String() string {
	return fmt.Sprintf("%d", uint64(*v))
}

// GetValuePtr returns the unsafe pointer to the BPF value.
func (v *Value) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

// DeepCopyMapValue returns a deep copy of the map value
func (v *Value) DeepCopyMapValue() bpf.MapValue {
	value := *v
	return &value
}

type ConfigMap struct {
	*bpf.Map
}

var (
	once      sync.Once
	configMap ConfigMap
)

// MapCreate will create an config map
func InitMap() error {
	once.Do(func() {
		var index Index
		var value Value
		configMap = ConfigMap{
			Map: bpf.NewMap(MapName,
				bpf.MapTypeArray,
				&index,
				int(unsafe.Sizeof(index)),
				&value,
				int(unsafe.Sizeof(value)),
				MaxEntries,
				0, 0,
				bpf.ConvertKeyValue,
			),
		}
	})

	_, err := configMap.OpenOrCreate()
	return err
}

// Update writes the given uint64 value to the bpf map at the given index.
func Update(index Index, val uint64) error {
	value := Value(val)
	return configMap.Update(&index, &value)
}
