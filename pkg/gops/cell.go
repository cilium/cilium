// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gops

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

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

// gopsConfigDir returns a writable directory for the gops config.
// By default, gops derives the config directory via os.UserConfigDir():
// In any environment where $HOME is set to / (ex. containers running as a
// randomly assigned UID with no /etc/passwd entry, as is common on OpenShift),
// os.UserConfigDir() resolves to /. The portfile path then becomes /<PID>, which
// is not writable. In such case fall back to os.TempDir().
func gopsConfigDir(log *slog.Logger) string {
	dir, err := os.UserConfigDir()
	if err != nil || filepath.Clean(dir) == "/" {
		p := filepath.Join(os.TempDir(), "gops")
		log.Debug("os.UserConfigDir() was empty, will use tmp dir instead",
			logfields.Directory, p)
		return p
	}
	return filepath.Join(dir, "gops")
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
				ConfigDir:              gopsConfigDir(log),
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
