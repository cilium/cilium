// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package stats

import (
	"io"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"
	"github.com/spf13/pflag"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/logging/logfields"
)

// Cell defines the BPF stats cell.
var Cell = cell.Module(
	"bpf-stats",
	"BPF Stats commands",

	cell.Config(Config{}),
	cell.Invoke(registerBPFStatsEnable),
)

type Config struct {
	EnableBPFStats bool
}

func (def Config) Flags(flags *pflag.FlagSet) {
	flags.Bool("enable-bpf-stats", def.EnableBPFStats, "Enable BPF statistics collection")
}

func registerBPFStatsEnable(logger *slog.Logger, lc cell.Lifecycle, cfg Config) {
	if cfg.EnableBPFStats {
		logger.Info("BPF stats enabled in config, registering activation hook")
		var statsCloser io.Closer
		lc.Append(cell.Hook{
			OnStart: func(cell.HookContext) error {
				logger.Info("Enabling BPF stats")
				closer, err := ebpf.EnableStats(unix.BPF_STATS_RUN_TIME)
				if err != nil {
					logger.Error("Failed to enable BPF stats", logfields.Error, err)
					return err
				}
				statsCloser = closer
				return nil
			},
			OnStop: func(cell.HookContext) error {
				logger.Info("Disabling BPF stats")
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
	}
}
