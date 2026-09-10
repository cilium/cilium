// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// This only runs on linux, since it imports some linux-specific logic from
// loader package.
//go:build linux

package agent

import (
	"context"

	"github.com/cilium/cilium/pkg/bgp/types"
	loadertypes "github.com/cilium/cilium/pkg/datapath/loader/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
)

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
func NewDatapathWaiter(loader loadertypes.Loader, lbInitWait loadbalancer.InitWaitFunc) types.DatapathWaiter {
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
