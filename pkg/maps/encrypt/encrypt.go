// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package encrypt

import (
	"fmt"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/maps/registry"
	"github.com/cilium/cilium/pkg/option"
)

// encryptMap implements [EncryptMap]
type encryptMap struct {
	*bpf.Map
}

// EncryptKey is the context ID for the encryption session
type EncryptKey struct {
	Key uint32 `align:"ctx"`
}

// EncryptValue is ID assigned to the keys
type EncryptValue struct {
	KeyID uint8
}

// String pretty print the EncryptKey
func (k EncryptKey) String() string {
	return fmt.Sprintf("%d", k.Key)
}

func (k EncryptKey) New() bpf.MapKey { return &EncryptKey{} }

// String pretty print the EncryptValue.
func (v EncryptValue) String() string {
	return fmt.Sprintf("%d", v.KeyID)
}

func (v EncryptValue) New() bpf.MapValue { return &EncryptValue{} }

const (
	// MapName name of map used to pin map for datapath
	MapName = "cilium_encrypt_state"
)

// newMap will construct a bpf.Map that is not open or created yet.
func newMap(lc cell.Lifecycle, mapSpecRegistry *registry.MapSpecRegistry, ipsecCfg datapath.IPsecConfig, dc *option.DaemonConfig) *encryptMap {
	if !ipsecCfg.Enabled() {
		return &encryptMap{}
	}

	m := &encryptMap{}

	lc.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			spec, err := mapSpecRegistry.Get(MapName)
			if err != nil {
				return fmt.Errorf("Encrypt map spec not found: %w", err)
			}

			m.Map = bpf.NewMap(spec, &EncryptKey{}, &EncryptValue{}).
				WithCache().WithEvents(dc.GetEventBufferConfig(MapName))

			if err := m.OpenOrCreate(); err != nil {
				return fmt.Errorf("Encrypt map create failed: %w", err)
			}
			return nil
		},
		OnStop: func(ctx cell.HookContext) error {
			m.Close()
			return nil
		},
	})

	return m
}

func (m *encryptMap) Update(key EncryptKey, value EncryptValue) error {
	return m.Map.Update(key, value)
}

func (m *encryptMap) Lookup(key EncryptKey) (val EncryptValue, err error) {
	v, err := m.Map.Lookup(key)
	if err == nil {
		val = *(v.(*EncryptValue))
	}
	return
}
