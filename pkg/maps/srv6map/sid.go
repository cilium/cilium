// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package srv6map

import (
	"fmt"
	"log/slog"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/types"
)

const (
	sidMapName    = "cilium_srv6_sid"
	maxSIDEntries = 16384
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

func newSIDMap(dc *option.DaemonConfig, lc cell.Lifecycle) (bpf.MapOut[*SIDMap], defines.NodeOut) {
	nodeOut := defines.NodeOut{
		NodeDefines: defines.Map{
			"SRV6_SID_MAP_SIZE": strconv.FormatUint(maxSIDEntries, 10),
		},
	}

	if !dc.EnableSRv6 {
		return bpf.MapOut[*SIDMap]{}, nodeOut
	}

	m := bpf.NewMap(
		sidMapName,
		ebpf.Hash,
		&SIDKey{},
		&SIDValue{},
		maxSIDEntries,
		bpf.BPF_F_NO_PREALLOC,
	)

	lc.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			return m.OpenOrCreate()
		},
		OnStop: func(ctx cell.HookContext) error {
			return m.Close()
		},
	})

	return bpf.NewMapOut(&SIDMap{m}), nodeOut
}

// OpenSIDMap opens the SIDMap on bpffs
func OpenSIDMap(logger *slog.Logger) (*SIDMap, error) {
	m, err := bpf.OpenMap(bpf.MapPath(logger, sidMapName), &SIDKey{}, &SIDValue{})
	if err != nil {
		return nil, err
	}
	return &SIDMap{m}, nil
}
