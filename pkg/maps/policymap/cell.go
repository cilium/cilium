// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"fmt"
	"log/slog"

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
	cell.Provide(createStatsMap),
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

func createStatsMap(in struct {
	cell.In

	Lifecycle cell.Lifecycle
	Log       *slog.Logger
	PolicyConfig
}) (out struct {
	cell.Out

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
	MaxEntries = in.BpfPolicyMapMax

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
			"entries", maxStatsEntries)
	}

	out.NodeDefines = map[string]string{
		"POLICY_STATS_MAP":      StatsMapName,
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
