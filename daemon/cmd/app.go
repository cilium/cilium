// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"

	"go.uber.org/fx"
)

func runApp() {
	ctx, cancel := context.WithCancel(context.Background())
	app := fx.New(
		fx.WithLogger(newAppLogger),
		fx.Supply(fx.Annotate(ctx, fx.As(new(context.Context)))),
		cleanerModule,
		fx.Provide(daemonModule),
		fx.Invoke(func(*Daemon) {}),

		// The first thing to do when stopping is to cancel the
		// daemon-wide context.
		fx.Invoke(appendOnStop(cancel)),
	)

	if app.Err() != nil {
		log.WithError(app.Err()).Fatal("Failed to initialize daemon")
	}

	app.Run()
}

func appendOnStop(onStop func()) func(fx.Lifecycle) {
	return func(lc fx.Lifecycle) {
		lc.Append(fx.Hook{
			OnStop: func(context.Context) error {
				onStop()
				return nil
			},
		})
	}
}
