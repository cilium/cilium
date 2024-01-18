// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package synced

import (
	"github.com/cilium/cilium/pkg/hive/cell"
)

var Cell = cell.Module(
	"k8s-synced",
	"Provides types for internal K8s resource synchronization",

	cell.Provide(func() *APIGroups {
		return new(APIGroups)
	}),

	cell.Provide(func() *Resources {
		return new(Resources)
	}),
)
