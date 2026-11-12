// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package l2v6respondermap

import (
	"fmt"
	"net/netip"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/maps/l2respondermap"
	mapregistry "github.com/cilium/cilium/pkg/maps/registry"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/types"
)

const MapName = "cilium_l2_responder_v6"

var Cell = cell.Provide(NewMap)

type Map interface {
	Create(ip netip.Addr, ifIndex uint32) error
	Lookup(ip netip.Addr, ifIndex uint32) (*l2respondermap.L2ResponderStats, error)
	Delete(ip netip.Addr, ifIndex uint32) error
	IterateWithCallback(cb IterateCallback) error
}

type l2V6ResponderMap struct {
	*bpf.Map
}

func NewMap(
	lifecycle cell.Lifecycle,
	mapRegistry *mapregistry.MapRegistry,
	daemonConfig *option.DaemonConfig,
) bpf.MapOut[Map] {
	outerMap := &l2V6ResponderMap{}

	lifecycle.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			if !daemonConfig.EnableL2Announcements {
				return nil
			}

			m, err := bpf.NewMapFromRegistry(mapRegistry, MapName, &L2V6ResponderKey{},
				&l2respondermap.L2ResponderStats{})
			if err != nil {
				return fmt.Errorf("failed to get %s map from registry: %w", MapName, err)
			}
			outerMap.Map = m

			if err := outerMap.OpenOrCreate(); err != nil {
				return fmt.Errorf("failed to open/create %s map: %w", MapName, err)
			}

			return nil
		},
		OnStop: func(hc cell.HookContext) error {
			if outerMap.Map == nil {
				return nil
			}

			return outerMap.Map.Close()
		},
	})

	return bpf.NewMapOut[Map](outerMap)
}

// Create creates a new entry for the given IP and IfIndex tuple.
func (m *l2V6ResponderMap) Create(ip netip.Addr, ifIndex uint32) error {
	key := newL2V6ResponderKey(ip, ifIndex)
	return m.Map.Update(&key, &l2respondermap.L2ResponderStats{})
}

// Delete deletes the entry associated with the provided IP and IfIndex tuple.
func (m *l2V6ResponderMap) Delete(ip netip.Addr, ifIndex uint32) error {
	key := newL2V6ResponderKey(ip, ifIndex)
	return m.Map.Delete(&key)
}

// Lookup returns the stats object associated with the provided IP and IfIndex tuple.
func (m *l2V6ResponderMap) Lookup(ip netip.Addr, ifIndex uint32) (*l2respondermap.L2ResponderStats, error) {
	key := newL2V6ResponderKey(ip, ifIndex)
	val, err := m.Map.Lookup(&key)
	if err != nil {
		return nil, err
	}

	return val.(*l2respondermap.L2ResponderStats), nil
}

// IterateCallback represents the signature of the callback function
// expected by the IterateWithCallback method, which in turn is used to iterate
// all the keys/values of a L2 responder map.
type IterateCallback func(*L2V6ResponderKey, *l2respondermap.L2ResponderStats)

// IterateWithCallback iterates through all the keys/values of a L2 responder map,
// passing each key/value pair to the cb callback.
func (m *l2V6ResponderMap) IterateWithCallback(cb IterateCallback) error {
	return m.Map.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
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

func (k *L2V6ResponderKey) New() bpf.MapKey { return &L2V6ResponderKey{} }

func (k *L2V6ResponderKey) String() string {
	return fmt.Sprintf("ip=%s, ifIndex=%d", k.IP, k.IfIndex)
}

func newL2V6ResponderKey(ip netip.Addr, ifIndex uint32) L2V6ResponderKey {
	return L2V6ResponderKey{
		IP:      ip.As16(),
		IfIndex: ifIndex,
		Pad:     uint32(0),
	}
}
