// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package stats

import (
	"io"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/script"
	"github.com/spf13/pflag"
	"golang.org/x/sys/unix"

	statstypes "github.com/cilium/cilium/pkg/bpf/stats/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

// Cell defines the BPF stats cell.
var Cell = cell.Module(
	"bpf-stats",
	"BPF Stats commands",

	cell.Provide(statsCommands),
	cell.Config(Config{}),
	cell.Provide(registerBPFStatsEnable),
	cell.Provide(newProgStatsCollector),
)

type bpfStatsStatus struct {
	enabled bool
}

type Config struct {
	EnableBPFStats bool
}

func (s bpfStatsStatus) Enabled() bool {
	return s.enabled
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-bpf-stats", def.EnableBPFStats, "Enable BPF statistics collection")
}

func registerBPFStatsEnable(logger *slog.Logger, lc cell.Lifecycle, cfg Config) bpfStatsStatus {
	if !cfg.EnableBPFStats {
		return bpfStatsStatus{enabled: false}
	}
	var statsCloser io.Closer
	lc.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			closer, err := ebpf.EnableStats(unix.BPF_STATS_RUN_TIME)
			if err != nil {
				logger.Error("Failed to enable BPF stats", logfields.Error, err)
				return err
			}
			statsCloser = closer
			return nil
		},
		OnStop: func(cell.HookContext) error {
			if statsCloser != nil {
				err := statsCloser.Close()
				if err != nil {
					logger.Error("Failed to disable BPF stats", logfields.Error, err)
					return err
				}
			}
			return nil
		},
	})
	return bpfStatsStatus{enabled: true}
}

func statsCommands(
	status bpfStatsStatus,
	progStatsCollector statstypes.ProgStatsCollector,
) hive.ScriptCmdsOut {
	return hive.NewScriptCmds(map[string]script.Cmd{
		"bpf/stats/report": reportCommand(status, progStatsCollector),
	})
}
