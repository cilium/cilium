// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"context"

	loadertypes "github.com/cilium/cilium/pkg/datapath/loader/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
)

// DatapathWaiter is called by the BGP controller to wait for the datapath to
// be ready before announcing routes. It abstracts the individual initialization
// gates so that the controller does not need to know about each component.
type DatapathWaiter interface {
	Wait(ctx context.Context) error
}

// datapathWaiter is the production implementation of DatapathWaiter. It waits
// for the host datapath BPF programs to be attached (via Loader) and for the
// load-balancing BPF maps to be populated (via InitWaitFunc).
type datapathWaiter struct {
	loader     loadertypes.Loader
	lbInitWait loadbalancer.InitWaitFunc
}

// NewDatapathWaiter returns a DatapathWaiter that waits for the host datapath
// and load-balancing state to be initialized before BGP route announcements
// are allowed.
func NewDatapathWaiter(loader loadertypes.Loader, lbInitWait loadbalancer.InitWaitFunc) DatapathWaiter {
	return &datapathWaiter{
		loader:     loader,
		lbInitWait: lbInitWait,
	}
}

func (w *datapathWaiter) Wait(ctx context.Context) error {
	select {
	case <-w.loader.HostDatapathInitialized():
	case <-ctx.Done():
		return ctx.Err()
	}
	return w.lbInitWait(ctx)
}
