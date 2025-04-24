// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gops

import (
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	gopsAgent "github.com/google/gops/agent"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

// Cell creates the cell for the gops agent, a tool to list and diagnose Go processes.
// See https://github.com/google/gops.
func Cell(enable bool, defaultPort uint16) cell.Cell {
	return cell.Module(
		"gops",
		"Gops Agent",

		cell.Config(GopsConfig{EnableGops: enable, GopsPort: defaultPort}),
		cell.Invoke(registerGopsHooks),
	)
}

type GopsConfig struct {
	EnableGops bool
	GopsPort   uint16 // Port for gops server to listen on
}

func (def GopsConfig) Flags(flags *pflag.FlagSet) {
	flags.Uint16(option.GopsPort, def.GopsPort, "Port for gops server to listen on")
	flags.Bool(option.EnableGops, def.EnableGops, "Enable gops server")
}

func registerGopsHooks(lc cell.Lifecycle, log *slog.Logger, cfg GopsConfig) {
	if !cfg.EnableGops {
		return
	}
	addr := fmt.Sprintf("127.0.0.1:%d", cfg.GopsPort)
	scopedLog := log.With(logfields.Address, addr)
	lc.Append(cell.Hook{
		OnStart: func(cell.HookContext) error {
			scopedLog.Info("Started gops server")
			return gopsAgent.Listen(gopsAgent.Options{
				Addr:                   addr,
				ReuseSocketAddrAndPort: true,
			})
		},
		OnStop: func(cell.HookContext) error {
			gopsAgent.Close()
			scopedLog.Info("Stopped gops server")
			return nil
		},
	})
}
