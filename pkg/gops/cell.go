// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gops

import (
	"context"
	"fmt"

	gopsAgent "github.com/google/gops/agent"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"go.uber.org/fx"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

// Gops runs the gops agent, a tool to list and diagnose Go processes.
// See https://github.com/google/gops.
var Cell = hive.NewCellWithConfig(
	"gops",
	GopsConfig{},
	fx.Invoke(registerGopsHooks),
)

type GopsConfig struct {
	GopsPort uint16 // Port for gops server to listen on
}

func (GopsConfig) Flags(flags *pflag.FlagSet) {
	flags.Uint16(option.GopsPort, defaults.GopsPortAgent, "Port for gops server to listen on")
}

func (GopsConfig) Validate() error {
	return nil
}

func registerGopsHooks(lc fx.Lifecycle, log logrus.FieldLogger, cfg GopsConfig) {
	addr := fmt.Sprintf("127.0.0.1:%d", cfg.GopsPort)
	addrField := logrus.Fields{"address": addr, logfields.LogSubsys: "gops"}
	log = log.WithFields(addrField)
	lc.Append(fx.Hook{
		OnStart: func(context.Context) error {
			log.Info("Started gops server")
			return gopsAgent.Listen(gopsAgent.Options{
				Addr:                   addr,
				ReuseSocketAddrAndPort: true,
			})
		},
		OnStop: func(context.Context) error {
			gopsAgent.Close()
			log.Info("Stopped gops server")
			return nil
		},
	})
}
