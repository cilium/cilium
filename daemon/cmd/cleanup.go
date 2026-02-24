// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	gops "github.com/google/gops/agent"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/pidfile"
)

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
