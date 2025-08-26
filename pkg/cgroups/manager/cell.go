// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"log/slog"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

// Cell provides access to the cgroup manager.
var Cell = cell.Module(
	"cgroup-manager",
	"CGroup Manager",

	cell.Provide(newCGroupManager),
	cell.Provide(newGetCgroupDumpMetadataRestApiHandler),
)

type cgroupManagerParams struct {
	cell.In

	Logger    *slog.Logger
	Lifecycle cell.Lifecycle

	AgentConfig *option.DaemonConfig
}

func newCGroupManager(params cgroupManagerParams) CGroupManager {
	if !params.AgentConfig.EnableSocketLBTracing {
		return &noopCGroupManager{}
	}

	pathProvider, err := getCgroupPathProvider()
	if err != nil {
		params.Logger.
			Info(
				"Failed to setup socket load-balancing tracing with Hubble. See the kubeproxy-free guide for more details.",
				logfields.Error, err,
			)

		return &noopCGroupManager{}
	}

	cm := newManager(params.Logger, cgroupImpl{}, pathProvider, podEventsChannelSize)

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(hookContext cell.HookContext) error {
			go cm.processPodEvents()
			return nil
		},
		OnStop: func(cell.HookContext) error {
			cm.Close()
			return nil
		},
	})

	params.Logger.Info("Cgroup metadata manager is enabled")

	return cm
}
