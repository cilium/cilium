// Copyright 2020 Authors of Cilium
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
