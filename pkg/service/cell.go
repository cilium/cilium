// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package service

import (
	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/datapath/types"
	monitorAgent "github.com/cilium/cilium/pkg/monitor/agent"
)

// Cell provides access to the Service Manager.
var Cell = cell.Module(
	"service-manager",
	"Service Manager",

	cell.Provide(newServiceManager),

	cell.ProvidePrivate(func(sm ServiceManager) syncNodePort { return sm }),
	cell.Invoke(registerServiceReconciler),
)

type serviceManagerParams struct {
	cell.In

	Datapath     types.Datapath
	MonitorAgent monitorAgent.Agent
}

func newServiceManager(params serviceManagerParams) ServiceManager {
	return newService(params.MonitorAgent, params.Datapath.LBMap(), params.Datapath.NodeNeighbors())
}
