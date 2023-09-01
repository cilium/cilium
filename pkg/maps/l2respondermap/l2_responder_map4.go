// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package l2respondermap

import (
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/exp/slices"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/mapreconciler"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/types"
)

const (
	MapName           = "cilium_l2_responder_v4"
	DefaultMaxEntries = 4096
)

var Cell = cell.Group(
	cell.Provide(NewMap),
	mapreconciler.NewReconciler[L2ResponderEntry, L2ResponderKey, L2ResponderStats](
		// Ignore the value of the map entry, since the states are modified by the kernel.
		mapreconciler.WithMapEntryEqual(func(e L2ResponderEntry, k L2ResponderKey, v L2ResponderStats) bool {
			eKey := e.Key()
			return eKey.IP == k.IP && eKey.IfIndex == k.IfIndex
		}),
	),
)

func NewMap(lifecycle hive.Lifecycle, config *option.DaemonConfig) (mapreconciler.Map[L2ResponderKey, L2ResponderStats], error) {
	return newMap(lifecycle, config, DefaultMaxEntries)
}

type l2ResponderMap struct {
	name    string
	enabled bool
	*ebpf.Map
}

func newMap(lifecycle hive.Lifecycle, config *option.DaemonConfig, maxEntries int) (*l2ResponderMap, error) {
	enabled := config.EnableL2Announcements

	outerMap := &l2ResponderMap{
		name:    MapName,
		enabled: enabled,
	}

	if enabled {
		lifecycle.Append(hive.Hook{
			OnStart: func(hc hive.HookContext) error {
				var err error
				outerMap.Map, err = ebpf.LoadPinnedMap(bpf.MapPath(MapName), &ebpf.LoadPinOptions{})
				if err == nil {
					return nil
				}

				outerMap.Map, err = ebpf.NewMap(&ebpf.MapSpec{
					Name:       MapName,
					Type:       ebpf.Hash,
					KeySize:    uint32(unsafe.Sizeof(L2ResponderKey{})),
					ValueSize:  uint32(unsafe.Sizeof(L2ResponderStats{})),
					MaxEntries: uint32(maxEntries),
					Flags:      unix.BPF_F_NO_PREALLOC,
					Pinning:    ebpf.PinByName,
				})
				if err != nil {
					return err
				}

				err = outerMap.Pin(bpf.MapPath(MapName))
				if err != nil {
					return err
				}

				return nil
			},
		})
	}

	return outerMap, nil
}

// Name returns the name of the map.
func (m *l2ResponderMap) Name() string {
	return m.name
}

// Enabled returns true if the map is enabled.
func (m *l2ResponderMap) Enabled() bool {
	return m.enabled
}

// Create creates a new entry for the given IP and IfIndex tuple.
func (m *l2ResponderMap) Put(k L2ResponderKey, v L2ResponderStats) error {
	if m.Map == nil {
		return nil
	}

	return m.Map.Put(&k, &v)
}

// Delete deletes the entry associated with the provided IP and IfIndex tuple.
func (m *l2ResponderMap) Delete(k L2ResponderKey) error {
	if m.Map == nil {
		return nil
	}

	return m.Map.Delete(&k)
}

// Lookup returns the stats object associated with the provided IP and IfIndex tuple.
func (m *l2ResponderMap) Lookup(k L2ResponderKey) (L2ResponderStats, error) {
	val := L2ResponderStats{}
	if m.Map == nil {
		return val, nil
	}

	err := m.Map.Lookup(&k, &val)
	return val, err
}

func (m *l2ResponderMap) Iterate() mapreconciler.Iterator[L2ResponderKey, L2ResponderStats] {
	if m.Map == nil {
		return Iterator{}
	}

	return Iterator{m.Map.Iterate()}
}

type Iterator struct {
	*ebpf.MapIterator
}

func (i Iterator) Next(k *L2ResponderKey, v *L2ResponderStats) bool {
	if i.MapIterator == nil {
		return false
	}

	return i.MapIterator.Next(&k, &v)
}

func (i Iterator) Err() error {
	if i.MapIterator == nil {
		return nil
	}

	return i.MapIterator.Err()
}

type L2ResponderEntry struct {
	L2ResponderKey
	Origins []resource.Key
}

func (e L2ResponderEntry) DeepCopy() L2ResponderEntry {
	new := e
	new.L2ResponderKey.IP = types.IPv4{}
	copy(new.L2ResponderKey.IP[:], e.L2ResponderKey.IP[:])
	new.Origins = slices.Clone(e.Origins)
	return new
}

func (e L2ResponderEntry) Key() L2ResponderKey {
	return e.L2ResponderKey
}

func (e L2ResponderEntry) Value() L2ResponderStats {
	return L2ResponderStats{}
}

// L2ResponderKey is the key to the L2 responder map.
//
// Must be in sync with struct auth_key in <bpf/lib/common.h>
type L2ResponderKey struct {
	IP      types.IPv4 `align:"ip"`
	IfIndex uint32     `align:"ifindex"`
}

func (k L2ResponderKey) Marshal() []byte {
	buf := make([]byte, unsafe.Sizeof(k))
	copy(buf, k.IP[:])
	binary.BigEndian.AppendUint32(buf[4:], k.IfIndex)
	return buf
}

func (k L2ResponderKey) String() string {
	return fmt.Sprintf("ip=%s, ifIndex=%d", net.IP(k.IP[:]), k.IfIndex)
}

// L2ResponderStats is the key to the L2 responder map.
//
// Must be in sync with struct l2_responder_v4_stats in <bpf/lib/common.h>
type L2ResponderStats struct {
	ResponsesSent uint64 `align:"responses_sent"`
}

func (s L2ResponderStats) Marshal() []byte {
	buf := make([]byte, unsafe.Sizeof(s))
	binary.BigEndian.AppendUint64(buf, s.ResponsesSent)
	return buf
}

func (s L2ResponderStats) String() string {
	return fmt.Sprintf("responses_sent=%q", s.ResponsesSent)
}
