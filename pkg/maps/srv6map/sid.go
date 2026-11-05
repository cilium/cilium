// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package srv6map

import (
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	mapregistry "github.com/cilium/cilium/pkg/maps/registry"
	"github.com/cilium/cilium/pkg/types"
)

const (
	sidMapName = "cilium_srv6_sid"
)

// SIDKey is a key for the SIDMap. Implements bpf.MapKey.
type SIDKey struct {
	SID types.IPv6
}

func (k *SIDKey) New() bpf.MapKey {
	return &SIDKey{}
}

func (k *SIDKey) String() string {
	return fmt.Sprintf("sid=%s", k.SID.String())
}

// SIDValue is a value for the SIDMap. Implements bpf.MapValue.
type SIDValue struct {
	VRFID uint32
}

func (v *SIDValue) New() bpf.MapValue {
	return &SIDValue{}
}

func (v *SIDValue) String() string {
	return fmt.Sprintf("vrfid=%d", v.VRFID)
}

// SIDMap is the internal representation of an SRv6 SID map.
type SIDMap struct {
	*bpf.Map
}

// SRv6SIDIterateCallback represents the signature of the callback function
// expected by the IterateWithCallback method, which in turn is used to iterate
// all the keys/values of an SRv6 SID map.
type SRv6SIDIterateCallback func(*SIDKey, *SIDValue)

// IterateWithCallback iterates through all the keys/values of an SRv6 SID map,
// passing each key/value pair to the cb callback.
func (m *SIDMap) IterateWithCallback(cb SRv6SIDIterateCallback) error {
	return m.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		key := k.(*SIDKey)
		value := v.(*SIDValue)
		cb(key, value)
	})
}

func newSIDMap(lc cell.Lifecycle, reg *mapregistry.MapRegistry) bpf.MapOut[*SIDMap] {
	m := &SIDMap{}

	lc.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			var err error
			m.Map, err = bpf.NewMapFromRegistry(reg, sidMapName, &SIDKey{}, &SIDValue{})
			if err != nil {
				return fmt.Errorf("create SRv6 SID map from registry: %w", err)
			}
			return m.OpenOrCreate()
		},
		OnStop: func(ctx cell.HookContext) error {
			return m.Close()
		},
	})

	return bpf.NewMapOut(m)
}

// OpenSIDMap opens the SIDMap on bpffs
func OpenSIDMap(logger *slog.Logger) (*SIDMap, error) {
	m, err := bpf.OpenMap(bpf.MapPath(logger, sidMapName), &SIDKey{}, &SIDValue{})
	if err != nil {
		return nil, err
	}
	return &SIDMap{m}, nil
}
