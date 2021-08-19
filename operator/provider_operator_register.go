// SPDX-License-Identifier: Apache-2.0
// Copyright 2017-2020 Authors of Cilium

//go:build ipam_provider_operator
// +build ipam_provider_operator

package main

import (
	// These dependencies should be included only when this file is included in the build.
	"github.com/cilium/cilium/pkg/ipam/allocator/clusterpool"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
)

func init() {
	allocatorProviders[ipamOption.IPAMClusterPool] = &clusterpool.AllocatorOperator{}
}
