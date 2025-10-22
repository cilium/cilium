// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/registry"
	"github.com/cilium/cilium/pkg/option"
)

var Cell = cell.Module(
	"policymap",
	"Policymap provides access to the datapath policy maps",
	cell.Config(DefaultPolicyConfig),
	cell.Provide(createFactory),
)

type PolicyConfig struct {
	// BpfPolicyMapMax is the maximum number of peer identities that an
	// endpoint may allow traffic to exchange traffic with.
	BpfPolicyMapMax int

	// PolicyStatsMapMax is the maximum number of entries allowed in a BPF policy map.
	BpfPolicyStatsMapMax int
}

var DefaultPolicyConfig = PolicyConfig{
	BpfPolicyMapMax:      16384,
	BpfPolicyStatsMapMax: 1 << 16,
}

const (
	PolicyMapMaxName      = "bpf-policy-map-max"
	PolicyStatsMapMaxName = "bpf-policy-stats-map-max"
)

func (def PolicyConfig) Flags(flags *pflag.FlagSet) {
	flags.Int(PolicyMapMaxName, def.BpfPolicyMapMax, "Maximum number of entries in endpoint policy map (per endpoint)")
	flags.Int(PolicyStatsMapMaxName, def.BpfPolicyStatsMapMax, "Maximum number of entries in bpf policy stats map")
}

type Factory interface {
	OpenEndpoint(id uint16) (*PolicyMap, error)
	RemoveEndpoint(id uint16) error

	PolicyMaxEntries() int
	StatsMaxEntries() int
}

type factory struct {
	logger          *slog.Logger
	mapSpecRegistry *registry.MapSpecRegistry
	stats           *StatsMap
}

func newFactory(logger *slog.Logger, mapSpecRegistry *registry.MapSpecRegistry, stats *StatsMap) *factory {
	return &factory{
		logger:          logger,
		mapSpecRegistry: mapSpecRegistry,
		stats:           stats,
	}
}

// OpenEndpoint opens (or creates) a policy for the specified endpoint, which
// is used to govern which peer identities can communicate with the endpoint
// protected by this map.
func (f *factory) OpenEndpoint(id uint16) (*PolicyMap, error) {
	m, err := newPolicyMap(f.logger, f.mapSpecRegistry, id, f.stats)
	if err != nil {
		return nil, err
	}
	err = m.OpenOrCreate()
	if err != nil {
		return nil, err
	}
	return m, nil
}

// RemoveEndpoint removes the policy map of the specified endpoint.
func (f *factory) RemoveEndpoint(id uint16) error {
	return os.RemoveAll(bpf.LocalMapPath(f.logger, MapNamePrefix, id))
}

func (f *factory) PolicyMaxEntries() int {
	spec, err := f.mapSpecRegistry.Get(MapName)
	if err != nil {
		return 0
	}

	return int(spec.MaxEntries)
}

func (f *factory) StatsMaxEntries() int {
	return int(f.stats.MaxEntries())
}

func createFactory(in struct {
	cell.In

	Lifecycle       cell.Lifecycle
	Log             *slog.Logger
	MapSpecRegistry *registry.MapSpecRegistry
	PolicyConfig
}) (out struct {
	cell.Out

	Factory
	bpf.MapOut[*StatsMap]
}, err error) {
	if in.BpfPolicyMapMax < option.PolicyMapMin {
		in.Log.Warn("specified PolicyMap max entries too low, using minimum value instead",
			logfields.Entries, in.BpfPolicyMapMax,
			logfields.Minimum, option.PolicyMapMin)
		in.BpfPolicyMapMax = option.PolicyMapMin
	}
	if in.BpfPolicyMapMax > option.PolicyMapMax {
		in.Log.Warn("specified PolicyMap max entries too high, using maximum value instead",
			logfields.Entries, in.BpfPolicyMapMax,
			logfields.Maximum, option.PolicyMapMax)
		in.BpfPolicyMapMax = option.PolicyMapMax
	}

	if in.BpfPolicyStatsMapMax < option.LimitTableMin {
		in.Log.Warn("specified policy stats map max entries too low, using minimum value instead",
			logfields.Entries, in.BpfPolicyStatsMapMax,
			logfields.Minimum, option.LimitTableMin)
		in.BpfPolicyStatsMapMax = option.LimitTableMin
	}
	if in.BpfPolicyStatsMapMax > option.LimitTableMax {
		in.Log.Warn("specified policy stats map max entries too high, using maximum value instead",
			logfields.Entries, in.BpfPolicyStatsMapMax,
			logfields.Maximum, option.LimitTableMax)
		in.BpfPolicyStatsMapMax = option.LimitTableMax
	}

	maxStatsEntries := calcMaxStatsEntries(in.BpfPolicyStatsMapMax, in.Log)
	if int(maxStatsEntries) != in.BpfPolicyStatsMapMax {
		in.Log.Debug("Rounded policy stats map size down to the closest multiple of the number of possible CPUs",
			logfields.Entries, maxStatsEntries)
	}

	err = in.MapSpecRegistry.ModifyMapSpec(StatsMapName, func(spec *ebpf.MapSpec) error {
		spec.MaxEntries = uint32(maxStatsEntries)
		return nil
	})
	if err != nil {
		return out, err
	}

	err = in.MapSpecRegistry.ModifyMapSpec(MapName, func(spec *ebpf.MapSpec) error {
		spec.MaxEntries = uint32(in.BpfPolicyMapMax)
		spec.Flags = bpf.GetMapMemoryFlags(spec.Type)
		return nil
	})
	if err != nil {
		return out, err
	}

	m := &StatsMap{log: in.Log}

	out.Factory = Factory(newFactory(in.Log, in.MapSpecRegistry, m))

	in.Lifecycle.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			err := initCallMaps(in.MapSpecRegistry)
			if err != nil {
				return fmt.Errorf("Policy call map creation failed: %w", err)
			}

			spec, err := in.MapSpecRegistry.Get(StatsMapName)
			if err != nil {
				return err
			}
			m.Map = ebpf.NewMap(in.Log, spec)

			return m.OpenOrCreate()
		},
		OnStop: func(cell.HookContext) error {
			return m.Close()
		},
	})

	out.MapOut = bpf.NewMapOut(m)
	return
}
