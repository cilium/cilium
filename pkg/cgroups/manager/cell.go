// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/pkg/kpr"
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

	Logger   *slog.Logger
	JobGroup job.Group

	AgentConfig *option.DaemonConfig
	KPRConfig   kpr.KPRConfig
}

func newCGroupManager(params cgroupManagerParams) CGroupManager {
	if !params.KPRConfig.EnableSocketLB || !params.AgentConfig.UnsafeDaemonConfigOption.EnableSocketLBTracing {
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

	params.JobGroup.Add(job.OneShot("process-pod-events", cm.processPodEvents))

	params.Logger.Info("Cgroup metadata manager is enabled")

	return cm
}
