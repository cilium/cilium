// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"

	gops "github.com/google/gops/agent"
	"go.uber.org/fx"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/pidfile"
)

// cleanerModule exposes the cleaner as a fx module and runs
// the cleanup functions on stop.
var cleanerModule = fx.Module(
	"cleaner",
	fx.Provide(newCleaner),
)

func newCleaner(lc fx.Lifecycle) *daemonCleanup {
	cleaner := NewDaemonCleanup()
	lc.Append(fx.Hook{
		OnStop: func(context.Context) error {
			cleaner.Clean()
			return nil
		},
	})
	return cleaner
}

type daemonCleanup struct {
	preCleanupFuncs *cleanupFuncList
	cleanupFuncs    *cleanupFuncList
}

func NewDaemonCleanup() *daemonCleanup {
	return &daemonCleanup{
		cleanupFuncs: &cleanupFuncList{
			funcs: make([]func(), 0),
		},
		preCleanupFuncs: &cleanupFuncList{
			funcs: make([]func(), 0),
		},
	}
}

type cleanupFuncList struct {
	funcs []func()
	lock  lock.Mutex
}

func (c *cleanupFuncList) Add(newFunc func()) {
	c.lock.Lock()
	c.funcs = append(c.funcs, newFunc)
	c.lock.Unlock()
}

func (c *cleanupFuncList) Run() {
	c.lock.Lock()
	defer c.lock.Unlock()
	for k := range c.funcs {
		c.funcs[k]()
	}
}

// Clean cleans up everything created by this package.
func (d *daemonCleanup) Clean() {
	gops.Close()
	d.preCleanupFuncs.Run()
	pidfile.Clean()
	d.cleanupFuncs.Run()

}
