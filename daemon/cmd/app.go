// SPDX-License-Identifier: Apache-2.0
// Copyright 2016-2021 Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/cilium/cilium/pkg/bandwidth"
	"github.com/cilium/cilium/pkg/option"
	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"
)

// LegacyDaemon is an adapter for managing the lifecycle of the legacy daemon
// code that has not yet been converted to use Fx.
type LegacyDaemon struct {
}

func NewLegacyDaemon(lc fx.Lifecycle) *LegacyDaemon {

	lc.Append(fx.Hook{
		OnStart: func(context.Context) error {
			// TODO start context?
			go runDaemon()
			return nil
		},

		OnStop: func(context.Context) error {
			// TODO stop context?
			return nil
		},
	})

	return &LegacyDaemon{}
}

// Dummy is a placeholder for grabbing reference to everything we want
// to start. To be replaced by the proper leaf functions of the daemon.
func Dummy(ld *LegacyDaemon, bw *bandwidth.BandwidthManager) {
	fmt.Printf("DUMMY START\n")
}

func ValidateDaemonConfig(cfg *option.DaemonConfig) error {
	// Validate the daemon-specific global options.
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid daemon configuration: %s", err)
	}
	return nil
}

func newDaemonApp() *fx.App {
	return fx.New(
		fx.Provide(
			func() *option.DaemonConfig { return option.Config },
			NewLegacyDaemon,
			bandwidth.NewBandwidthManager,
		),

		fx.Invoke(
			ValidateDaemonConfig,
			Dummy,
		),

		fx.WithLogger(
			func() fxevent.Logger {
				// FIXME(JM): Use pkg/logging.
				return &fxevent.ConsoleLogger{W: os.Stdout}
			},
		),
	)
}

func RunDaemonApp() {

	bootstrapStats.earlyInit.Start()
	initEnv()
	bootstrapStats.earlyInit.End(true)

	bootstrapStats.overall.Start()
	interruptCh := cleaner.registerSigHandler()

	app := newDaemonApp()
	startCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := app.Start(startCtx); err != nil {
		log.WithError(err).Fatal("Failed to start cilium-agent")
	}

	<-interruptCh

	stopCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := app.Stop(stopCtx); err != nil {
		log.WithError(err).Fatal("Failed to stop cilium-agent")
	}

}
