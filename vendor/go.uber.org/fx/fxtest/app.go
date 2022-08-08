// Copyright (c) 2019-2021 Uber Technologies, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package fxtest

import (
	"context"

	"go.uber.org/fx"
	"go.uber.org/fx/fxevent"
)

// App is a wrapper around fx.App that provides some testing helpers. By
// default, it uses the provided TB as the application's logging backend.
type App struct {
	*fx.App

	tb TB
}

// New creates a new test application.
func New(tb TB, opts ...fx.Option) *App {
	allOpts := make([]fx.Option, 0, len(opts)+1)
	allOpts = append(allOpts, fx.WithLogger(func() fxevent.Logger { return NewTestLogger(tb) }))
	allOpts = append(allOpts, opts...)

	app := fx.New(allOpts...)
	if err := app.Err(); err != nil {
		tb.Errorf("fx.New failed: %v", err)
		tb.FailNow()
	}

	return &App{
		App: app,
		tb:  tb,
	}
}

// RequireStart calls Start, failing the test if an error is encountered.
func (app *App) RequireStart() *App {
	startCtx, cancel := context.WithTimeout(context.Background(), app.StartTimeout())
	defer cancel()

	if err := app.Start(startCtx); err != nil {
		app.tb.Errorf("application didn't start cleanly: %v", err)
		app.tb.FailNow()
	}
	return app
}

// RequireStop calls Stop, failing the test if an error is encountered.
func (app *App) RequireStop() {
	stopCtx, cancel := context.WithTimeout(context.Background(), app.StopTimeout())
	defer cancel()

	if err := app.Stop(stopCtx); err != nil {
		app.tb.Errorf("application didn't stop cleanly: %v", err)
		app.tb.FailNow()
	}
}
