// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build ipam_provider_aws

package cmd

import (
	// These dependencies should be included only when this file is included in the build.
	allocatorAWS "github.com/cilium/cilium/pkg/ipam/allocator/aws" // AWS allocator.
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	_ "github.com/cilium/cilium/pkg/policy/groups/aws" // Register AWS policy group provider.
)

func init() {
	allocatorProviders[ipamOption.IPAMENI] = &allocatorAWS.AllocatorAWS{}
}
