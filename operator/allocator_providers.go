// SPDX-License-Identifier: Apache-2.0
// Copyright 2020 Authors of Cilium

package main

import (
	"context"
	"time"

	"github.com/cilium/cilium/pkg/ipam/allocator"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

var (
	allocatorProviders = make(map[string]allocator.AllocatorProvider)

	// NOPNodeManager is a NodeEventHandler that does nothing
	NOPNodeManager allocator.NodeEventHandler = &nopNodeManager{}
)

// nopNodeManager is used for allocation types that need no node management.
// This is needed to allow node watcher maintain a CiliumNode store for the
// use in CEP GC even when operator does not do anything for IPAM.
type nopNodeManager struct{}

func (nm *nopNodeManager) Create(resource *v2.CiliumNode) bool { return true }

func (nm *nopNodeManager) Update(resource *v2.CiliumNode) bool { return true }

func (nm *nopNodeManager) Delete(nodeName string) {}

func (nm *nopNodeManager) Resync(context.Context, time.Time) {}
