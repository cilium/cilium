// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

//go:build ipam_provider_alibabacloud
// +build ipam_provider_alibabacloud

package main

import (
	"github.com/cilium/cilium/pkg/ipam/allocator/alibabacloud"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
)

func init() {
	allocatorProviders[ipamOption.IPAMAlibabaCloud] = &alibabacloud.AllocatorAlibabaCloud{}
}
