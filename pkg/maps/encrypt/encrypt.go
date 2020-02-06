// Copyright 2018-2019 Authors of Cilium
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

package encrypt

import (
	"fmt"
	"sync"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
)

// EncryptKey is the context ID for the encryption session
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapKey
type EncryptKey struct {
	key uint32 `align:"ctx"`
}

// EncryptValue is ID assigned to the keys
// +k8s:deepcopy-gen=true
// +k8s:deepcopy-gen:interfaces=github.com/cilium/cilium/pkg/bpf.MapValue
type EncryptValue struct {
	encryptKeyID uint8
}

// String pretty print the EncryptKey
func (k EncryptKey) String() string {
	return fmt.Sprintf("%d", k.key)
}

// String pretty print the encryption key index.
func (v EncryptValue) String() string {
	return fmt.Sprintf("%d", v.encryptKeyID)
}

// GetValuePtr returns the unsafe pointer to the BPF value.
func (v *EncryptValue) GetValuePtr() unsafe.Pointer { return unsafe.Pointer(v) }

// GetKeyPtr returns the unsafe pointer to the BPF key
func (k *EncryptKey) GetKeyPtr() unsafe.Pointer { return unsafe.Pointer(k) }

// NewValue returns a new empty instance of the structure represeting the BPF
// map value
func (k EncryptKey) NewValue() bpf.MapValue { return &EncryptValue{} }

func newEncryptKey(key uint32) *EncryptKey {
	return &EncryptKey{
		key: key,
	}
}

const (
	// MapName name of map used to pin map for datapath
	MapName = "cilium_encrypt_state"

	// MaxEntries represents the maximum number of current encryption contexts
	MaxEntries = 1
)

var (
	once       sync.Once
	encryptMap *bpf.Map
)

// MapCreate will create an encrypt map
func MapCreate() error {
	once.Do(func() {
		encryptMap = bpf.NewMap(MapName,
			bpf.MapTypeArray,
			&EncryptKey{},
			int(unsafe.Sizeof(EncryptKey{})),
			&EncryptValue{},
			int(unsafe.Sizeof(EncryptValue{})),
			MaxEntries,
			0, 0,
			bpf.ConvertKeyValue,
		).WithCache()
	})

	_, err := encryptMap.OpenOrCreate()
	return err
}

// MapUpdateContext updates the encrypt state with ctxID to use the new keyID
func MapUpdateContext(ctxID uint32, keyID uint8) error {
	k := newEncryptKey(ctxID)
	v := &EncryptValue{
		encryptKeyID: keyID,
	}
	return encryptMap.Update(k, v)
}
