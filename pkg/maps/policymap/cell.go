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
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/logging/logfields"
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

	// BpfPolicySharedMapMax is the maximum number of entries allowed in the shared BPF policy map.
	BpfPolicySharedMapMax int

	// BpfPolicyOverlayMapMax is the maximum number of entries allowed in the policy overlay BPF map.
	BpfPolicyOverlayMapMax int

	// BpfPolicyMaxRuleSets is the maximum number of unique rule sets per node.
	BpfPolicyMaxRuleSets int
}

var DefaultPolicyConfig = PolicyConfig{
	BpfPolicyMapMax:        16384,
	BpfPolicyStatsMapMax:   1 << 16,
	BpfPolicySharedMapMax:  131072,
	BpfPolicyOverlayMapMax: 16384,
	BpfPolicyMaxRuleSets:   4096,
}

const (
	PolicyMapMaxName        = "bpf-policy-map-max"
	PolicyStatsMapMaxName   = "bpf-policy-stats-map-max"
	PolicySharedMapMaxName  = "bpf-policy-shared-map-max"
	PolicyOverlayMapMaxName = "bpf-policy-overlay-map-max"
	PolicyMaxRuleSetsName   = "bpf-policy-max-rule-sets"
)

func (def PolicyConfig) Flags(flags *pflag.FlagSet) {
	flags.Int(PolicyMapMaxName, def.BpfPolicyMapMax, "Maximum number of entries in endpoint policy map (per endpoint)")
	flags.Int(PolicyStatsMapMaxName, def.BpfPolicyStatsMapMax, "Maximum number of entries in bpf policy stats map")
	flags.Int(PolicySharedMapMaxName, def.BpfPolicySharedMapMax, "Maximum number of entries in node-scoped shared BPF policy map")
	flags.Int(PolicyOverlayMapMaxName, def.BpfPolicyOverlayMapMax, "Maximum number of entries in BPF policy overlay map")
	flags.Int(PolicyMaxRuleSetsName, def.BpfPolicyMaxRuleSets, "Maximum number of unique policy rule sets per node")
}

type Factory interface {
	OpenEndpoint(id uint16) (PolicyMap, error)
	RemoveEndpoint(id uint16) error

	PolicyMaxEntries() int
	StatsMaxEntries() int
}

type factory struct {
	logger *slog.Logger
	// policyMapEntries is the upper limit of entries in the per endpoint policy
	// table ie the maximum number of peer identities that the endpoint could
	// send/receive traffic to/from.
	policyMapEntries int

	stats *StatsMap
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

// RemoveEndpoint removes the policy map of the specified endpoint.
func (f *factory) RemoveEndpoint(id uint16) error {
	return os.RemoveAll(bpf.LocalMapPath(f.logger, MapName, id))
}

func (f *factory) PolicyMaxEntries() int {
	return f.policyMapEntries
}

func (f *factory) StatsMaxEntries() int {
	return int(f.stats.MaxEntries())
}

func createFactory(in struct {
	cell.In

	Lifecycle cell.Lifecycle
	Log       *slog.Logger
	PolicyConfig
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

	out.Factory = Factory(newFactory(in.Log, m, in.BpfPolicyMapMax))

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
			if option.Config.EnableSharedPolicy {
				if in.BpfPolicyMaxRuleSets > 0 {
					InitSharedManager(uint32(in.BpfPolicyMaxRuleSets))
				}
				if in.BpfPolicySharedMapMax > 0 {
					SharedPolicyMap.WithMaxEntries(in.BpfPolicySharedMapMax)
				}
				if in.BpfPolicyOverlayMapMax > 0 {
					PolicyOverlayMap.WithMaxEntries(in.BpfPolicyOverlayMapMax)
				}
				if err := SharedPolicyMap.OpenOrCreate(); err != nil {
					return fmt.Errorf("failed to create SharedPolicyMap: %w", err)
				}
				if err := PolicyOverlayMap.OpenOrCreate(); err != nil {
					return fmt.Errorf("failed to create PolicyOverlayMap: %w", err)
				}

				// Recover shared policy state from pinned maps
				in.Log.Info("Recovering shared policy overlays...")
				err = PolicyOverlayMap.DumpWithCallback(func(k bpf.MapKey, v bpf.MapValue) {
					epID := uint16(k.(*OverlayKey).EndpointID)
					ruleSetID := v.(*OverlayValue).RuleSetID
					RestoreEndpointOverlay(epID, ruleSetID)
				})
				if err != nil {
					in.Log.Warn("Failed to iterate overlay map during recovery", logfields.Error, err)
				}
			}
			return m.OpenOrCreate()
		},
		OnStop: func(cell.HookContext) error {
			if option.Config.EnableSharedPolicy {
				SharedPolicyMap.Close()
				PolicyOverlayMap.Close()
			}
			return m.Close()
		},
	})

	out.MapOut = bpf.NewMapOut(m)
	return
}
