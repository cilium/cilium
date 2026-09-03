// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package commands

import (
	"context"
	"sync"

	"github.com/cilium/hive/script"
)

// DatapathWaiter is a test implementation of agent.DatapathWaiter that blocks
// until Initialize is called. When a test uses --wait-datapath, the BGP
// controller blocks on Wait until bgp/datapath-initialized is called.
type DatapathWaiter struct {
	once sync.Once
	ch   chan struct{}
}

// NewDatapathWaiter creates a new DatapathWaiter. Wait will block until
// Initialize is called.
func NewDatapathWaiter() *DatapathWaiter {
	return &DatapathWaiter{ch: make(chan struct{})}
}

// Initialize releases the datapath gate. Subsequent calls are no-ops.
func (w *DatapathWaiter) Initialize() {
	w.once.Do(func() { close(w.ch) })
}

// Wait implements agent.DatapathWaiter.
func (w *DatapathWaiter) Wait(ctx context.Context) error {
	select {
	case <-w.ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// DatapathScriptCmds returns script commands for controlling the datapath
// waiter in tests.
func DatapathScriptCmds(w *DatapathWaiter) map[string]script.Cmd {
	return map[string]script.Cmd{
		"bgp/datapath-initialized": datapathInitializedCmd(w),
	}
}

func datapathInitializedCmd(w *DatapathWaiter) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Signal that the datapath is initialized",
			Detail: []string{
				"Releases the BGP controller's datapath initialization gate,",
				"allowing BGP route announcements to proceed.",
				"",
				"Only meaningful when the test was started with --wait-datapath.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			w.Initialize()
			return nil, nil
		},
	)
}
