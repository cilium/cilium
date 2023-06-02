// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package encrypt

import (
	"fmt"
	"sync"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/option"
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
			0,
			bpf.ConvertKeyValue,
		).WithCache().
			WithEvents(option.Config.GetEventBufferConfig(MapName))
	})

	return encryptMap.OpenOrCreate()
}

// MapUpdateContext updates the encrypt state with ctxID to use the new keyID
func MapUpdateContext(ctxID uint32, keyID uint8) error {
	k := newEncryptKey(ctxID)
	v := &EncryptValue{
		encryptKeyID: keyID,
	}
	return encryptMap.Update(k, v)
}
