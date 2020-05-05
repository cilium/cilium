// Copyright 2018-2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"context"
	"os"
	"os/signal"
	"sync"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/pidfile"

	"golang.org/x/sys/unix"
)

var cleaner = &daemonCleanup{
	cleanUPSig: make(chan struct{}),
	cleanUPWg:  &sync.WaitGroup{},
	cleanupFuncs: &cleanupFuncList{
		funcs: make([]func(), 0),
	},
}

type daemonCleanup struct {
	lock.Mutex
	// cleanUPSig channel that is closed when the daemon agent should be
	// terminated.
	cleanUPSig chan struct{}
	// cleanUPWg all cleanup operations will be marked as Done() when completed.
	cleanUPWg *sync.WaitGroup

	cleanupFuncs *cleanupFuncList

	sigHandlerCancel context.CancelFunc
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

func (d *daemonCleanup) registerSigHandler() <-chan struct{} {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, unix.SIGQUIT, unix.SIGINT, unix.SIGHUP, unix.SIGTERM)
	interrupt := make(chan struct{})
	go func() {
		for s := range sig {
			log.WithField("signal", s).Info("Exiting due to signal")
			log.Debug("canceling context in signal handler")
			d.Lock()
			if d.sigHandlerCancel != nil {
				d.sigHandlerCancel()
			}
			d.Unlock()
			pidfile.Clean()
			d.Clean()
			d.cleanupFuncs.Run()
			break
		}
		close(interrupt)
	}()
	return interrupt
}

// Clean cleans up everything created by this package.
func (d *daemonCleanup) Clean() {
	close(d.cleanUPSig)
	d.cleanUPWg.Wait()
}

// SetCancelFunc sets the function which is called when we receive a signal to
// propagate cancelation down to ongoing operations. If it's already set,
// it does nothing.
func (d *daemonCleanup) SetCancelFunc(cfunc context.CancelFunc) {
	d.Lock()
	defer d.Unlock()
	if d.sigHandlerCancel != nil {
		return
	}
	d.sigHandlerCancel = cfunc
}
