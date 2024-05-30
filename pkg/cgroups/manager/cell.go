// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"github.com/cilium/hive/cell"
)

// Cell provides access to the cgroup manager.
var Cell = cell.Module(
	"cgroup-manager",
	"CGroup Manager",

	cell.Provide(newCGroupManager),
)

type cgroupManagerParams struct {
	cell.In

	Lifecycle cell.Lifecycle
}

func newCGroupManager(params cgroupManagerParams) *CgroupManager {
	cm := newManager(cgroupImpl{}, podEventsChannelSize)

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(hookContext cell.HookContext) error {
			cm.enable()
			go cm.processPodEvents()

			return nil
		},
		OnStop: func(cell.HookContext) error {
			cm.Close()

			return nil
		},
	})

	return cm
}
