// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package act

import (
	"fmt"
	"strconv"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/service"
)

const ActiveConnectionTrackingMapName = "cilium_lb_act"

// Cell provides the ActiveConnectionTrackingMap which contains information about opened
// and closed connection to each service-zone pair.
var Cell = cell.Module(
	"active-connection-tracking",
	"eBPF map with counts of open-closed connections for each service-zone pair",

	cell.Provide(newActiveConnectionTrackingMap),
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

type ActiveConnectionTrackingIterateCallback func(*ActiveConnectionTrackerKey, *ActiveConnectionTrackerValue)

type ActiveConnectionTrackingMap interface {
	IterateWithCallback(ActiveConnectionTrackingIterateCallback) error
}

type actMap struct {
	m *bpf.Map
}

func newActiveConnectionTrackingMap(in struct {
	cell.In

	Lifecycle cell.Lifecycle
	Conf      Config
}) (out struct {
	cell.Out

	bpf.MapOut[ActiveConnectionTrackingMap]
	defines.NodeOut
}) {
	if !in.Conf.EnableActiveConnectionTracking {
		return
	}
	size := option.Config.LBServiceMapEntries * len(option.Config.FixedZoneMapping)
	if size == 0 {
		return
	}

	out.NodeDefines = map[string]string{
		"ENABLE_ACTIVE_CONNECTION_TRACKING": "1",
		"LB_ACT_MAP":                        ActiveConnectionTrackingMapName,
		"CILIUM_LB_ACT_MAP_MAX_ENTRIES":     strconv.Itoa(size),
	}

	out.MapOut = bpf.NewMapOut(ActiveConnectionTrackingMap(createActiveConnectionTrackingMap(in.Lifecycle, size)))
	return
}

func createActiveConnectionTrackingMap(lc cell.Lifecycle, size int) *actMap {
	m := bpf.NewMap(ActiveConnectionTrackingMapName,
		ebpf.LRUHash,
		&ActiveConnectionTrackerKey{},
		&ActiveConnectionTrackerValue{},
		size,
		0,
	)

	lc.Append(cell.Hook{
		OnStart: func(context cell.HookContext) error {
			return m.OpenOrCreate()
		},
		OnStop: func(context cell.HookContext) error {
			return m.Close()
		},
	})

	return &actMap{m}
}

func (m actMap) IterateWithCallback(cb ActiveConnectionTrackingIterateCallback) error {
	return m.m.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
		key := k.(*ActiveConnectionTrackerKey)
		value := v.(*ActiveConnectionTrackerValue)

		cb(key, value)
	})
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
	if svcAddr, err := service.GetID(uint32(svcID)); err == nil && svcAddr != nil {
		return fmt.Sprintf("%s[%s]", svcAddr.String(), option.Config.GetZone(v.Zone))
	}
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
