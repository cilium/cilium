// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package service

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/pkg/datapath/types"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	monitorAgent "github.com/cilium/cilium/pkg/monitor/agent"
)

// Cell provides access to the Service Manager.
var Cell = cell.Module(
	"service-manager",
	"Service Manager",

	cell.ProvidePrivate(newServiceInternal),
	cell.Provide(func(svc *Service) ServiceManager { return svc }),
	cell.Provide(func(svc *Service) ServiceHealthCheckManager { return svc }),
	cell.Provide(newServiceRestApiHandler),

	cell.ProvidePrivate(func(sm ServiceManager) syncNodePort { return sm }),
	cell.Invoke(registerServiceReconciler),
)

type serviceManagerParams struct {
	cell.In

	JG           job.Group
	LBMap        types.LBMap
	MonitorAgent monitorAgent.Agent

	HealthCheckers []HealthChecker `group:"healthCheckers"`
	Clientset      k8sClient.Clientset
	NodeNeighbors  types.NodeNeighbors
}

func newServiceInternal(params serviceManagerParams) *Service {
	enabledHealthCheckers := []HealthChecker{}
	for _, hc := range params.HealthCheckers {
		if hc != nil {
			enabledHealthCheckers = append(enabledHealthCheckers, hc)
		}
	}

	svc := newService(params.MonitorAgent, params.LBMap, params.NodeNeighbors, enabledHealthCheckers, params.Clientset.IsEnabled())

	params.JG.Add(job.OneShot("health-check-event-watcher", svc.handleHealthCheckEvent))

	return svc
}
