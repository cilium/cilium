// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build ipam_provider_alibabacloud

package cmd

import (
	"github.com/cilium/cilium/pkg/ipam/allocator/alibabacloud"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
)

func init() {
	allocatorProviders[ipamOption.IPAMAlibabaCloud] = &alibabacloud.AllocatorAlibabaCloud{}
}
