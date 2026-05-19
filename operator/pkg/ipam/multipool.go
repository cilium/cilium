// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build ipam_provider_operator

package ipam

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/operator/pkg/ipam/allocator/multipool"
)

func init() {
	allocators = append(allocators, cell.Module(
		"multipool-ipam-allocator",
		"Multi Pool IP Allocator",

		cell.Config(multipool.MultiPoolDefaultConfig),
		cell.Invoke(multipool.StartMultiPoolAllocator),
	))
}
