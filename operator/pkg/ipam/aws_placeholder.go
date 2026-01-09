// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !ipam_provider_aws

package ipam

import "github.com/cilium/hive/cell"

var awsCell = cell.Module(
	"aws-ipam-placeholder",
	"AWS IP Allocator Placeholder",
)
