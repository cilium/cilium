// Copyright 2018-2019 Authors of Cilium
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

package main

import (
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/pidfile"
)

var (
	// cleanUPSig channel that is closed when the daemon agent should be
	// terminated.
	cleanUPSig = make(chan struct{})
	// cleanUPWg all cleanup operations will be marked as Done() when completed.
	cleanUPWg = &sync.WaitGroup{}

	cleanupFuncs = &cleanupFuncList{
		funcs: make([]func(), 0),
	}
)

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

func registerSigHandler() <-chan struct{} {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGQUIT, syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM)
	interrupt := make(chan struct{})
	go func() {
		for s := range sig {
			log.WithField("signal", s).Info("Exiting due to signal")
			pidfile.Clean()
			Clean()
			cleanupFuncs.Run()
			break
		}
		close(interrupt)
	}()
	return interrupt
}

// Clean cleans up everything created by this package.
func Clean() {
	close(cleanUPSig)
	cleanUPWg.Wait()
}
