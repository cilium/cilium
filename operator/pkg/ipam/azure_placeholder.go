// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !ipam_provider_azure

package ipam

import "github.com/cilium/hive/cell"

var azureCell = cell.Module(
	"azure-ipam-placeholder",
	"Azure IP Allocator Placeholder",
)
