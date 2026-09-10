// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package agent

import (
	"context"

	"github.com/cilium/cilium/pkg/bgp/types"
	loadertypes "github.com/cilium/cilium/pkg/datapath/loader/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
)

// nopDatapathWaiter is a no-op implementation of DatapathWaiter for non-Linux platforms.
type nopDatapathWaiter struct {
	loader     loadertypes.Loader
	lbInitWait loadbalancer.InitWaitFunc
}

func NewDatapathWaiter(loader loadertypes.Loader, lbInitWait loadbalancer.InitWaitFunc) types.DatapathWaiter {
	return &nopDatapathWaiter{
		loader:     loader,
		lbInitWait: lbInitWait,
	}
}

func (w *nopDatapathWaiter) Wait(_ context.Context) error {
	// Nothing to wait. Unblock immediately.
	return nil
}
