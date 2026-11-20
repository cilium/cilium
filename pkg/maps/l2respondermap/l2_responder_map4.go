// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package l2respondermap

import (
	"fmt"
	"net/netip"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf"
	mapregistry "github.com/cilium/cilium/pkg/maps/registry"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/types"
)

const MapName = "cilium_l2_responder_v4"

var Cell = cell.Provide(NewMap)

type Map interface {
	Create(ip netip.Addr, ifIndex uint32) error
	Lookup(ip netip.Addr, ifIndex uint32) (*L2ResponderStats, error)
	Delete(ip netip.Addr, ifIndex uint32) error
	IterateWithCallback(cb IterateCallback) error
}

type l2ResponderMap struct {
	*bpf.Map
}

func NewMap(
	lifecycle cell.Lifecycle,
	mapRegistry *mapregistry.MapRegistry,
	daemonConfig *option.DaemonConfig,
) bpf.MapOut[Map] {
	outerMap := &l2ResponderMap{}

	lifecycle.Append(cell.Hook{
		OnStart: func(hc cell.HookContext) error {
			if !daemonConfig.EnableL2Announcements {
				return nil
			}

			m, err := bpf.NewMapFromRegistry(mapRegistry, MapName, &L2ResponderKey{},
				&L2ResponderStats{})
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
func (m *l2ResponderMap) Create(ip netip.Addr, ifIndex uint32) error {
	key := newL2ResponderKey(ip, ifIndex)
	return m.Map.Update(&key, &L2ResponderStats{})
}

// Delete deletes the entry associated with the provided IP and IfIndex tuple.
func (m *l2ResponderMap) Delete(ip netip.Addr, ifIndex uint32) error {
	key := newL2ResponderKey(ip, ifIndex)
	return m.Map.Delete(&key)
}

// Lookup returns the stats object associated with the provided IP and IfIndex tuple.
func (m *l2ResponderMap) Lookup(ip netip.Addr, ifIndex uint32) (*L2ResponderStats, error) {
	key := newL2ResponderKey(ip, ifIndex)
	val, err := m.Map.Lookup(&key)
	if err != nil {
		return nil, err
	}

	return val.(*L2ResponderStats), nil
}

// IterateCallback represents the signature of the callback function
// expected by the IterateWithCallback method, which in turn is used to iterate
// all the keys/values of a L2 responder map.
type IterateCallback func(*L2ResponderKey, *L2ResponderStats)

// IterateWithCallback iterates through all the keys/values of a L2 responder map,
// passing each key/value pair to the cb callback.
func (m *l2ResponderMap) IterateWithCallback(cb IterateCallback) error {
	return m.Map.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		key := k.(*L2ResponderKey)
		value := v.(*L2ResponderStats)
		cb(key, value)
	})
}

// L2ResponderKey implements the bpf.MapKey interface.
//
// Must be in sync with struct l2_responder_v4_key in <bpf/lib/l2_responder.h>
type L2ResponderKey struct {
	IP      types.IPv4 `align:"ip4"`
	IfIndex uint32     `align:"ifindex"`
}

func (k *L2ResponderKey) New() bpf.MapKey { return &L2ResponderKey{} }

func (k *L2ResponderKey) String() string {
	return fmt.Sprintf("ip=%s, ifIndex=%d", k.IP, k.IfIndex)
}

func newL2ResponderKey(ip netip.Addr, ifIndex uint32) L2ResponderKey {
	return L2ResponderKey{
		IP:      ip.As4(),
		IfIndex: ifIndex,
	}
}

// L2ResponderStats implements the bpf.MapValue interface.
//
// Must be in sync with struct l2_responder_stats in <bpf/lib/l2_responder.h>
type L2ResponderStats struct {
	ResponsesSent uint64 `align:"responses_sent"`
}

func (s *L2ResponderStats) New() bpf.MapValue { return &L2ResponderStats{} }

func (s *L2ResponderStats) String() string {
	return fmt.Sprintf("responses_sent=%d", s.ResponsesSent)
}
