// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package l2v6respondermap

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"unsafe"

	"github.com/cilium/hive/cell"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/maps/l2respondermap"
	"github.com/cilium/cilium/pkg/types"
)

const (
	MapName           = "cilium_l2_responder_v6"
	DefaultMaxEntries = 4096
)

var Cell = cell.Provide(NewMap)

type Map interface {
	Create(ip netip.Addr, ifIndex uint32) error
	Lookup(ip netip.Addr, ifIndex uint32) (*l2respondermap.L2ResponderStats, error)
	Delete(ip netip.Addr, ifIndex uint32) error
	IterateWithCallback(cb IterateCallback) error
}

func NewMap(lifecycle cell.Lifecycle, logger *slog.Logger) Map {
	return newMap(lifecycle, DefaultMaxEntries, logger)
}

type l2V6ResponderMap struct {
	*ebpf.Map
}

func newMap(lifecycle cell.Lifecycle, maxEntries int, logger *slog.Logger) *l2V6ResponderMap {
	outerMap := &l2V6ResponderMap{}

	lifecycle.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			var (
				m   *ebpf.Map
				err error
			)

			if m, err = ebpf.LoadRegisterMap(logger, MapName); err != nil {
				m = ebpf.NewMap(logger, &ebpf.MapSpec{
					Name:       MapName,
					Type:       ebpf.Hash,
					KeySize:    uint32(unsafe.Sizeof(L2V6ResponderKey{})),
					ValueSize:  uint32(unsafe.Sizeof(l2respondermap.L2ResponderStats{})),
					MaxEntries: uint32(maxEntries),
					Flags:      unix.BPF_F_NO_PREALLOC,
					Pinning:    ebpf.PinByName,
				})
				if err := m.OpenOrCreate(); err != nil {
					return err
				}
			}

			outerMap.Map = m

			return nil
		},
	})

	return outerMap
}

// Create creates a new entry for the given IP and IfIndex tuple.
func (m *l2V6ResponderMap) Create(ip netip.Addr, ifIndex uint32) error {
	key := newL2V6ResponderKey(ip, ifIndex)
	return m.Map.Put(key, l2respondermap.L2ResponderStats{})
}

// Delete deletes the entry associated with the provided IP and IfIndex tuple.
func (m *l2V6ResponderMap) Delete(ip netip.Addr, ifIndex uint32) error {
	key := newL2V6ResponderKey(ip, ifIndex)
	return m.Map.Delete(key)
}

// Lookup returns the stats object associated with the provided IP and IfIndex tuple.
func (m *l2V6ResponderMap) Lookup(ip netip.Addr, ifIndex uint32) (*l2respondermap.L2ResponderStats, error) {
	key := newL2V6ResponderKey(ip, ifIndex)
	val := l2respondermap.L2ResponderStats{}

	err := m.Map.Lookup(&key, &val)

	return &val, err
}

// IterateCallback represents the signature of the callback function
// expected by the IterateWithCallback method, which in turn is used to iterate
// all the keys/values of a L2 responder map.
type IterateCallback func(*L2V6ResponderKey, *l2respondermap.L2ResponderStats)

// IterateWithCallback iterates through all the keys/values of a L2 responder map,
// passing each key/value pair to the cb callback.
func (m *l2V6ResponderMap) IterateWithCallback(cb IterateCallback) error {
	return m.Map.IterateWithCallback(&L2V6ResponderKey{}, &l2respondermap.L2ResponderStats{},
		func(k, v any) {
			key := k.(*L2V6ResponderKey)
			value := v.(*l2respondermap.L2ResponderStats)
			cb(key, value)
		},
	)
}

// L2V6ResponderKey implements the bpf.MapKey interface.
//
// Must be in sync with struct l2_responder_v6_key in <bpf/lib/l2_responder.h>
type L2V6ResponderKey struct {
	IP      types.IPv6 `align:"ip6"`
	IfIndex uint32     `align:"ifindex"`
	Pad     uint32     `align:"pad"`
}

func (k *L2V6ResponderKey) String() string {
	return fmt.Sprintf("ip=%s, ifIndex=%d", net.IP(k.IP[:]), k.IfIndex)
}

func newL2V6ResponderKey(ip netip.Addr, ifIndex uint32) L2V6ResponderKey {
	return L2V6ResponderKey{
		IP:      types.IPv6(ip.As16()),
		IfIndex: ifIndex,
		Pad:     uint32(0),
	}
}
