// SPDX-License-Identifier: Apache-2.0
// Copyright 2016-2021 Authors of Cilium

package cmd

import (
	"context"
	"os"
	"time"

	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"
)

// LegacyDaemon is an adapter for managing the lifecycle of the legacy daemon
// code that has not yet been converted for use with Fx.
type LegacyDaemon struct {
}

func NewLegacyDaemon(lc fx.Lifecycle) *LegacyDaemon {

	lc.Append(fx.Hook{
		OnStart: func(context.Context) error {
			// TODO start context?
			go RootCmd.Execute()
			return nil
		},

		OnStop: func(context.Context) error {
			// TODO stop context?
			return nil
		},
	})

	return &LegacyDaemon{}
}

func Dummy(ld *LegacyDaemon) {

}

func newDaemonApp() *fx.App {
	return fx.New(
		fx.Provide(
			NewLegacyDaemon,
		),

		fx.Invoke(
			Dummy,
		),

		fx.WithLogger(
			func() fxevent.Logger { return &fxevent.ConsoleLogger{os.Stdout} },
		),
	)
}

func RunDaemonApp() {
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
