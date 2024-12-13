// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"github.com/cilium/hive/cell"

	serviceapi "github.com/cilium/cilium/api/v1/server/restapi/service"
	agentK8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/service"
)

// Cell provides access to the Local Redirect Policy Manager.
var Cell = cell.Module(
	"lrp-manager",
	"LRP Manager",

	cell.Provide(newLRPManager),
	cell.Provide(newLRPApiHandler),
)

type lrpManagerParams struct {
	cell.In

	Svc            service.ServiceManager
	SvcCache       *k8s.ServiceCache
	Lpr            agentK8s.LocalPodResource
	Ep             endpointmanager.EndpointManager
	MetricsManager LRPMetrics
}

func newLRPManager(params lrpManagerParams) *Manager {
	return NewRedirectPolicyManager(params.Svc, params.SvcCache, params.Lpr, params.Ep, params.MetricsManager)
}

func newLRPApiHandler(lrpManager *Manager) serviceapi.GetLrpHandler {
	return &getLrpHandler{
		lrpManager: lrpManager,
	}
}
