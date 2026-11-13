// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/maps"
	"github.com/cilium/cilium/pkg/logging/logfields"
	mapregistry "github.com/cilium/cilium/pkg/maps/registry"
	"github.com/cilium/cilium/pkg/option"
)

var Cell = cell.Module(
	"policymap",
	"Policymap provides access to the datapath policy maps",
	cell.Config(DefaultPolicyConfig),
	cell.Provide(newStatsMap),
	cell.Provide(createFactory),
	cell.Invoke(configurePolicyMaps),
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
	OpenEndpoint(id uint16) (PolicyMap, error)
	RemoveEndpoint(id uint16) error
	RemoveGlobalMapping(id uint32) error

	PolicyMaxEntries() int
	StatsMaxEntries() int
}

type factory struct {
	logger      *slog.Logger
	mapRegistry *mapregistry.MapRegistry

	// policyMapEntries is the upper limit of entries in the per endpoint policy
	// table ie the maximum number of peer identities that the endpoint could
	// send/receive traffic to/from.
	policyMapEntries int

	statsMapEntries int

	stats *StatsMap
}

func newFactory(logger *slog.Logger, mapRegistry *mapregistry.MapRegistry, stats *StatsMap,
	policyMapEntries int, statsMapEntries int) Factory {
	return &factory{
		logger:           logger,
		mapRegistry:      mapRegistry,
		policyMapEntries: policyMapEntries,
		statsMapEntries:  statsMapEntries,
		stats:            stats,
	}
}

// OpenEndpoint opens (or creates) a policy for the specified endpoint, which
// is used to govern which peer identities can communicate with the endpoint
// protected by this map.
func (f *factory) OpenEndpoint(id uint16) (PolicyMap, error) {
	m, err := newPolicyMap(id, f.mapRegistry, f.stats)
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
	return os.RemoveAll(bpf.LocalMapPath(f.logger, MapName, id))
}

func (f *factory) RemoveGlobalMapping(id uint32) error {
	return RemoveGlobalMapping(f.logger, id)
}

func (f *factory) PolicyMaxEntries() int {
	return f.policyMapEntries
}

func (f *factory) StatsMaxEntries() int {
	return f.statsMapEntries
}

type createFactoryParams struct {
	cell.In

	Lifecycle   cell.Lifecycle
	Log         *slog.Logger
	MapRegistry *mapregistry.MapRegistry
	Stats       *StatsMap
	PolicyConfig
}

func createFactory(in createFactoryParams) Factory {
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

	nCPU := possibleCPU(in.Log)
	roundDown := in.BpfPolicyStatsMapMax % nCPU
	in.BpfPolicyStatsMapMax -= roundDown
	in.Lifecycle.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			if err := initCallMaps(); err != nil {
				return fmt.Errorf("failed to create policy call map: %w", err)
			}
			return nil
		},
	})
	return newFactory(in.Log, in.MapRegistry, in.Stats, in.BpfPolicyMapMax, in.BpfPolicyStatsMapMax)
}

func configurePolicyMaps(reg *mapregistry.MapRegistry, factory Factory) error {
	flags := bpf.GetMapMemoryFlags(ebpf.LPMTrie) | unix.BPF_F_RDONLY_PROG
	maxEntries := uint32(factory.PolicyMaxEntries())
	if err := reg.Modify(maps.CiliumPolicy, func(patch *mapregistry.MapSpecPatch) {
		patch.Flags = flags
		patch.MaxEntries = maxEntries
	}); err != nil {
		return fmt.Errorf("error setting %s map flags and max entries: %w",
			maps.CiliumPolicy, err)
	}

	if err := reg.Modify(maps.CiliumPolicystats, func(patch *mapregistry.MapSpecPatch) {
		patch.MaxEntries = uint32(factory.StatsMaxEntries())
	}); err != nil {
		return fmt.Errorf("error setting %s map max entries: %w",
			maps.CiliumPolicystats, err)
	}
	return nil
}
