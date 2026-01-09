// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !ipam_provider_operator

package ipam

import (
	"github.com/cilium/hive/cell"
)

var multiPoolCell = cell.Module(
	"multipool-ipam-placeholder",
	"Multi Pool IP Allocator Placeholder",
)
