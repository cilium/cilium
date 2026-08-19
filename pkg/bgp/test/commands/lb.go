// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package commands

import (
	"context"
	"sync"

	"github.com/cilium/hive/script"

	"github.com/cilium/cilium/pkg/loadbalancer"
)

// ControllableLBInitWait is a loadbalancer.InitWaitFunc that blocks until
// SetReady is called. This is used in tests to simulate the load-balancing
// state initialization gate.
type ControllableLBInitWait struct {
	once sync.Once
	ch   chan struct{}
}

// NewControllableLBInitWait creates a new ControllableLBInitWait. The wait
// function returned by WaitFunc will block until SetReady is called.
func NewControllableLBInitWait() *ControllableLBInitWait {
	return &ControllableLBInitWait{ch: make(chan struct{})}
}

// WaitFunc returns a loadbalancer.InitWaitFunc that blocks until SetReady is called.
func (c *ControllableLBInitWait) WaitFunc() loadbalancer.InitWaitFunc {
	return func(ctx context.Context) error {
		select {
		case <-c.ch:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// SetReady unblocks the wait function. Subsequent calls are no-ops.
func (c *ControllableLBInitWait) SetReady() {
	c.once.Do(func() { close(c.ch) })
}

// LBScriptCmds returns script commands for controlling the LB init wait in tests.
func LBScriptCmds(ctrl *ControllableLBInitWait) map[string]script.Cmd {
	return map[string]script.Cmd{
		"lb/set-ready": lbSetReadyCmd(ctrl),
	}
}

// lbSetReadyCmd signals that the load-balancing state is ready, unblocking
// any BGP controller waiting on the LB init gate.
func lbSetReadyCmd(ctrl *ControllableLBInitWait) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Signal that load-balancing state is ready",
			Detail: []string{
				"Unblocks the BGP controller's LB init wait gate, simulating",
				"the load-balancing BPF state becoming ready.",
				"",
				"Only meaningful when the test was started with --block-lb-init-wait.",
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			ctrl.SetReady()
			return nil, nil
		},
	)
}
