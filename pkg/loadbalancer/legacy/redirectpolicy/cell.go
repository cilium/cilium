// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package redirectpolicy

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

	serviceapi "github.com/cilium/cilium/api/v1/server/restapi/service"
	agentK8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/loadbalancer/legacy/service"
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

	Logger         *slog.Logger
	DB             *statedb.DB
	Svc            service.ServiceManager
	SvcCache       k8s.ServiceCache
	Pods           statedb.Table[agentK8s.LocalPod]
	Ep             endpointmanager.EndpointManager
	MetricsManager LRPMetrics
	ExpConfig      loadbalancer.Config
}

func newLRPManager(params lrpManagerParams) *Manager {
	if params.ExpConfig.EnableExperimentalLB {
		// The experimental implementation is enabled, do nothing here.
		return nil
	}
	return NewRedirectPolicyManager(params.Logger, params.DB, params.Svc, params.SvcCache, params.Pods, params.Ep, params.MetricsManager)
}

func newLRPApiHandler(logger *slog.Logger, lrpManager *Manager) serviceapi.GetLrpHandler {
	return &getLrpHandler{
		logger:     logger,
		lrpManager: lrpManager,
	}
}
