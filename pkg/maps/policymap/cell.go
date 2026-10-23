// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"os"

	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/registry"
	"github.com/cilium/cilium/pkg/option"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
)

var Cell = cell.Module(
	"policymap",
	"Policymap provides access to the datapath policy maps",
	cell.Config(DefaultPolicyConfig),
	cell.Provide(createFactory),
	cell.Invoke(configure),
)

type PolicyConfig struct {
	// BpfPolicyMapMax is the maximum number of peer identities that an
	// endpoint may allow traffic to exchange traffic with.
	BpfPolicyMapMax int

	// PolicyStatsMapMax is the maximum number of entries allowed in a BPF policy map.
	BpfPolicyStatsMapMax int

	// BpfPolicySharedMapMax is the maximum number of entries allowed in the shared BPF policy map.
	BpfPolicySharedMapMax int
}

var DefaultPolicyConfig = PolicyConfig{
	BpfPolicyMapMax:       16384,
	BpfPolicyStatsMapMax:  1 << 16,
	BpfPolicySharedMapMax: 1 << 21,
}

const (
	PolicyMapMaxName       = "bpf-policy-map-max"
	PolicyStatsMapMaxName  = "bpf-policy-stats-map-max"
	PolicySharedMapMaxName = "bpf-policy-shared-map-max"
)

func (def PolicyConfig) Flags(flags *pflag.FlagSet) {
	flags.Int(PolicyMapMaxName, def.BpfPolicyMapMax, "Maximum number of entries in endpoint policy map (per endpoint)")
	flags.Int(PolicyStatsMapMaxName, def.BpfPolicyStatsMapMax, "Maximum number of entries in bpf policy stats map")
	flags.Int(PolicySharedMapMaxName, def.BpfPolicySharedMapMax, "Maximum number of entries in shared BPF policy map")
}

type Factory interface {
	OpenEndpoint(id uint16) (PolicyMap, error)
	// RemoveEndpoint removes the endpoint's policy program from the global policy
	// call maps, and its policy map pin, or with the shared policy map, its overlay
	// entry and its reference to its rule set.
	RemoveEndpoint(id uint16) error

	PolicyMaxEntries() int
	StatsMaxEntries() int

	SharedPolicyEnabled() bool
	SyncEndpointOverlay(epID uint16, entries iter.Seq2[policyTypes.Key, policyTypes.MapStateEntry]) error
	DumpEndpointSharedEntries(epID uint16) (PolicyEntriesDump, error)
	HasEndpointOverlay(epID uint16) bool
	RemoveStaleEndpointOverlays(exists func(uint16) bool) error
}

type factory struct {
	logger *slog.Logger
	// policyMapEntries is the upper limit of entries in the per endpoint policy
	// table ie the maximum number of peer identities that the endpoint could
	// send/receive traffic to/from.
	policyMapEntries int

	stats *StatsMap

	sharedMap  policyBPFMap
	overlayMap policyBPFMap
	allocator  *RuleSetAllocator
}

func newFactory(logger *slog.Logger, stats *StatsMap, policyMapEntries int) *factory {
	return &factory{
		logger:           logger,
		policyMapEntries: policyMapEntries,
		stats:            stats,
	}
}

// OpenEndpoint opens (or creates) a policy for the specified endpoint, which
// is used to govern which peer identities can communicate with the endpoint
// protected by this map.
func (f *factory) OpenEndpoint(id uint16) (PolicyMap, error) {
	m, err := newPolicyMap(f.logger, id, f.policyMapEntries, f.stats)
	if err != nil {
		return nil, err
	}
	err = m.OpenOrCreate()
	if err != nil {
		return nil, err
	}
	return m, nil
}

// RemoveEndpoint removes the policy state of the specified endpoint. All steps are
// attempted even if some fail, and the errors are joined.
func (f *factory) RemoveEndpoint(id uint16) error {
	var errs error
	if err := RemoveGlobalMapping(f.logger, uint32(id)); err != nil {
		errs = errors.Join(errs, fmt.Errorf("removing endpoint program from global policymap: %w", err))
	}
	if f.SharedPolicyEnabled() {
		f.removeEndpointOverlay(id)
	} else if err := os.RemoveAll(bpf.LocalMapPath(f.logger, MapName, id)); err != nil {
		errs = errors.Join(errs, fmt.Errorf("removing policy map pin: %w", err))
	}
	return errs
}

func (f *factory) PolicyMaxEntries() int {
	return f.policyMapEntries
}

func (f *factory) StatsMaxEntries() int {
	return int(f.stats.MaxEntries())
}

func configure(reg *registry.MapRegistry, cfg PolicyConfig, daemonConfig *option.DaemonConfig) error {
	if !daemonConfig.EnableSharedPolicy {
		return nil
	}
	if cfg.BpfPolicySharedMapMax > 0 {
		if err := reg.Modify(SharedPolicyMapName, func(m *registry.MapSpecPatch) {
			m.MaxEntries = uint32(cfg.BpfPolicySharedMapMax)
		}); err != nil && !errors.Is(err, registry.ErrMapNotFound) {
			return err
		}
	}
	if err := reg.Modify(PolicyOverlayMapName, func(m *registry.MapSpecPatch) {
		m.MaxEntries = defaults.MaxEndpointID
	}); err != nil && !errors.Is(err, registry.ErrMapNotFound) {
		return err
	}
	return nil
}

func createFactory(in struct {
	cell.In

	Lifecycle cell.Lifecycle
	Log       *slog.Logger
	Registry  *registry.MapRegistry
	PolicyConfig
	DaemonConfig *option.DaemonConfig
}) (out struct {
	cell.Out

	Factory
	bpf.MapOut[*StatsMap]
	defines.NodeOut
}) {
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

	m, maxStatsEntries := newStatsMap(in.BpfPolicyStatsMapMax, in.Log)
	if int(maxStatsEntries) != in.BpfPolicyStatsMapMax {
		in.Log.Debug("Rounded policy stats map size down to the closest multiple of the number of possible CPUs",
			logfields.Entries, maxStatsEntries)
	}

	f := newFactory(in.Log, m, in.BpfPolicyMapMax)
	out.Factory = f
	if in.DaemonConfig.EnableSharedPolicy {
		f.registerSharedPolicy(in.Lifecycle, in.Registry)
	}

	out.NodeDefines = map[string]string{
		"POLICY_MAP_SIZE":       fmt.Sprint(in.BpfPolicyMapMax),
		"POLICY_STATS_MAP_SIZE": fmt.Sprint(maxStatsEntries),
	}

	in.Lifecycle.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			err := initCallMaps()
			if err != nil {
				return fmt.Errorf("Policy call map creation failed: %w", err)
			}
			return m.OpenOrCreate()
		},
		OnStop: func(cell.HookContext) error {
			return m.Close()
		},
	})

	out.MapOut = bpf.NewMapOut(m)
	return
}
