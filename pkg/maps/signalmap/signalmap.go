// Copyright 2020 Authors of Cilium
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

package signalmap

import (
	"fmt"
	"unsafe"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "map-events")
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
func InitMap() error {
	signalMap := bpf.NewMap(MapName,
		bpf.MapTypePerfEventArray,
		&Key{},
		int(unsafe.Sizeof(Key{})),
		&Value{},
		int(unsafe.Sizeof(Value{})),
		common.GetNumPossibleCPUs(log),
		0,
		0,
		bpf.ConvertKeyValue,
	)
	_, err := signalMap.Create()
	return err
}
