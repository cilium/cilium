// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !ipam_provider_alibabacloud

package ipam

import "github.com/cilium/hive/cell"

var alibabaCloudCell = cell.Module(
	"alibabacloud-ipam-placeholder",
	"Alibaba Cloud IP Allocator Placeholder",
)
