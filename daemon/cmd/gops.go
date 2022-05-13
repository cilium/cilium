package cmd

import (
	"context"
	"fmt"

	gopsAgent "github.com/google/gops/agent"
	"github.com/sirupsen/logrus"
	"go.uber.org/fx"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/option"
)

type GopsConfig struct {
	GopsPort option.Opt[uint16] // Port for gops server to listen on
}

var gopsConfigOpts = GopsConfig{
	GopsPort: option.Uint16(option.GopsPort, defaults.GopsPortAgent, "Port for gops server to listen on"),
}

func GopsModule() fx.Option {
	return fx.Module(
		"gops",
		fx.Provide(
			option.Register(gopsConfigOpts),
			option.GetConfig[GopsConfig],
		),
		fx.Invoke(registerGopsHooks),
	)
}

func registerGopsHooks(lc fx.Lifecycle, cfg GopsConfig) {
	addr := fmt.Sprintf("127.0.0.1:%d", cfg.GopsPort.Get())
	addrField := logrus.Fields{"address": addr}
	log := log.WithFields(addrField)
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
