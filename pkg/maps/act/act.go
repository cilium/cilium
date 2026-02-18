// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package act

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/maps/registry"
	"github.com/cilium/cilium/pkg/option"
)

const (
	ACTMapName = "cilium_lb_act"
	FCTMapName = "cilium_lb_fct"
)

// Cell provides the [ACTMap] containing information about opened and closed
// connections to each service-zone pair.
var Cell = cell.Module(
	"active-connection-tracking",
	"eBPF map with counts of open-closed connections for each service-zone pair",

	cell.Provide(provide),
	cell.Config(defaultConfig),
)

type Config struct {
	EnableActiveConnectionTracking bool
}

func (c Config) Flags(fs *pflag.FlagSet) {
	fs.Bool("enable-active-connection-tracking", defaultConfig.EnableActiveConnectionTracking,
		"Count open and active connections to services, grouped by zones defined in fixed-zone-mapping.")
}

var defaultConfig = Config{
	EnableActiveConnectionTracking: false,
}

type ACTIterator func(*ActiveConnectionTrackerKey, *ActiveConnectionTrackerValue)

type ACTMap interface {
	IterateWithCallback(context.Context, ACTIterator) error
	Delete(*ActiveConnectionTrackerKey) error
	SaveFailed(*ActiveConnectionTrackerKey, uint64) error
	RestoreFailed(*ActiveConnectionTrackerKey) (uint64, error)
}

type actMap struct {
	m *bpf.Map
	f *bpf.Map
}

func provide(in struct {
	cell.In

	Lifecycle   cell.Lifecycle
	Conf        Config
	LBConfig    loadbalancer.Config
	MapRegistry *registry.MapRegistry
}) (out struct {
	cell.Out

	bpf.MapOut[ACTMap]
	defines.NodeOut
}, err error) {
	if !in.Conf.EnableActiveConnectionTracking {
		return out, nil
	}

	svcSize := in.LBConfig.LBServiceMapEntries
	zoneSize := len(option.Config.FixedZoneMapping)
	size := svcSize * zoneSize
	if size == 0 {
		return out, fmt.Errorf("unexpected map size: %d = svc[%d] * zones[%d]", size, svcSize, zoneSize)
	}

	out.NodeDefines = map[string]string{
		"ENABLE_ACTIVE_CONNECTION_TRACKING": "1",
	}

	if err := in.MapRegistry.Modify(ACTMapName, func(m *registry.MapSpecPatch) {
		m.MaxEntries = uint32(size)
	}); err != nil {
		return out, err
	}

	if err := in.MapRegistry.Modify(FCTMapName, func(m *registry.MapSpecPatch) {
		m.MaxEntries = uint32(size)
	}); err != nil {
		return out, err
	}

	actMap := &actMap{}
	in.Lifecycle.Append(cell.Hook{
		OnStart: func(cell.HookContext) (err error) {
			actMap.m, err = bpf.NewMapFromRegistry(in.MapRegistry, ACTMapName,
				&ActiveConnectionTrackerKey{}, &ActiveConnectionTrackerValue{})
			if err != nil {
				return fmt.Errorf("create act map: %w", err)
			}

			actMap.f, err = bpf.NewMapFromRegistry(in.MapRegistry, FCTMapName,
				&ActiveConnectionTrackerKey{}, &FailedConnectionTrackerValue{})
			if err != nil {
				return fmt.Errorf("create fct map: %w", err)
			}

			return errors.Join(actMap.m.OpenOrCreate(), actMap.f.OpenOrCreate())
		},
		OnStop: func(cell.HookContext) error {
			return errors.Join(actMap.m.Close(), actMap.f.Close())
		},
	})

	out.MapOut = bpf.NewMapOut(ACTMap(actMap))

	return out, nil
}

func (m *actMap) IterateWithCallback(ctx context.Context, cb ACTIterator) error {
	if m.m == nil {
		return fmt.Errorf("map not started")
	}

	return m.m.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		select {
		case <-ctx.Done():
			return
		default:
		}
		key := k.(*ActiveConnectionTrackerKey)
		value := v.(*ActiveConnectionTrackerValue)

		cb(key, value)
	})
}

func (m *actMap) Delete(key *ActiveConnectionTrackerKey) error {
	if m.m == nil || m.f == nil {
		return fmt.Errorf("map not started")
	}

	_, err1 := m.m.SilentDelete(key)
	_, err2 := m.f.SilentDelete(key)
	return errors.Join(err1, err2)
}

func (m *actMap) SaveFailed(key *ActiveConnectionTrackerKey, count uint64) error {
	if m.f == nil {
		return fmt.Errorf("map not started")
	}

	// We store overflow so that it matches overflown opened/closed counts.
	return m.f.Update(key, &FailedConnectionTrackerValue{uint32(count)})
}

func (m *actMap) RestoreFailed(key *ActiveConnectionTrackerKey) (uint64, error) {
	if m.f == nil {
		return 0, fmt.Errorf("map not started")
	}

	val, err := m.f.Lookup(key)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		// Ignore not found.
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return uint64(val.(*FailedConnectionTrackerValue).Failed), nil
}

// ActiveConnectionTrackerKey is the key to ActiveConnectionTrackingMap.
//
// It must match 'struct lb_act_key' in "bpf/lib/act.h".
type ActiveConnectionTrackerKey struct {
	SvcID uint16 `align:"svc_id"`
	Zone  uint8  `align:"zone"`
	Pad   uint8  `align:"pad"`
}

func (s *ActiveConnectionTrackerKey) New() bpf.MapKey { return &ActiveConnectionTrackerKey{} }

func (v *ActiveConnectionTrackerKey) String() string {
	svcID := byteorder.HostToNetwork16(v.SvcID)
	return fmt.Sprintf("%d[%s]", svcID, option.Config.GetZone(v.Zone))
}

// ActiveConnectionTrackerValue is the value in ActiveConnectionTrackingMap.
//
// It must match 'struct lb_act_value' in "bpf/lib/act.h".
type ActiveConnectionTrackerValue struct {
	Opened uint32 `align:"opened"`
	Closed uint32 `align:"closed"`
}

func (s *ActiveConnectionTrackerValue) New() bpf.MapValue { return &ActiveConnectionTrackerValue{} }

func (s *ActiveConnectionTrackerValue) String() string {
	return fmt.Sprintf("+%d -%d", s.Opened, s.Closed)
}

// FailedConnectionTrackerValue is the value in FailedConnectionTrackingMap.
type FailedConnectionTrackerValue struct {
	Failed uint32 `align:"failed"`
}

func (s *FailedConnectionTrackerValue) New() bpf.MapValue { return &FailedConnectionTrackerValue{} }

func (s *FailedConnectionTrackerValue) String() string {
	return strconv.Itoa(int(s.Failed))
}
