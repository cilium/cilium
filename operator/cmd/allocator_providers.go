// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/cilium/cilium/pkg/ipam/allocator"
)

var (
	allocatorProviders = make(map[string]allocator.AllocatorProvider)
)
