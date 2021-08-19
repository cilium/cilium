// SPDX-License-Identifier: Apache-2.0
// Copyright 2017-2020 Authors of Cilium

//go:build ipam_provider_azure
// +build ipam_provider_azure

package main

import (
	// These dependencies should be included only when this file is included in the build.
	allocatorAzure "github.com/cilium/cilium/pkg/ipam/allocator/azure" // Azure allocator task.
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
)

func init() {
	allocatorProviders[ipamOption.IPAMAzure] = &allocatorAzure.AllocatorAzure{}
}
