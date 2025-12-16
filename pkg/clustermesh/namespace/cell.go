// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package namespace

import "github.com/cilium/hive/cell"

var Cell = cell.Module(
	"clustermesh-namespace",
	"Clustermesh global namespace management",

	cell.Config(DefaultConfig),
	cell.Provide(
		func(params managerParams) Manager {
			return newManager(params)
		},
	),
)
