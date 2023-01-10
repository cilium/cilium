// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gops

import (
	"fmt"

	gopsAgent "github.com/google/gops/agent"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

// Cell creates the cell for the gops agent, a tool to list and diagnose Go processes.
// See https://github.com/google/gops.
func Cell(defaultPort uint16) cell.Cell {
	return cell.Module(
		"gops",
		"Gops Agent",

		cell.Config(GopsConfig{GopsPort: defaultPort}),
		cell.Invoke(registerGopsHooks),
	)
}

type GopsConfig struct {
	GopsPort uint16 // Port for gops server to listen on
}

func (def GopsConfig) Flags(flags *pflag.FlagSet) {
	flags.Uint16(option.GopsPort, def.GopsPort, "Port for gops server to listen on")
}

func registerGopsHooks(lc hive.Lifecycle, log logrus.FieldLogger, cfg GopsConfig) {
	addr := fmt.Sprintf("127.0.0.1:%d", cfg.GopsPort)
	addrField := logrus.Fields{"address": addr, logfields.LogSubsys: "gops"}
	log = log.WithFields(addrField)
	lc.Append(hive.Hook{
		OnStart: func(hive.HookContext) error {
			log.Info("Started gops server")
			return gopsAgent.Listen(gopsAgent.Options{
				Addr:                   addr,
				ReuseSocketAddrAndPort: true,
			})
		},
		OnStop: func(hive.HookContext) error {
			gopsAgent.Close()
			log.Info("Stopped gops server")
			return nil
		},
	})
}
