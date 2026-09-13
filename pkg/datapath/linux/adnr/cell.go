// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package adnr

import (
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/datapath/linux"
	routeReconciler "github.com/cilium/cilium/pkg/datapath/linux/route/reconciler"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

const componentName = "auto-direct-node-routes"

var Cell = cell.Module(
	componentName,
	"Maintains routes to node PodCIDRs on the same L2 segment",
	cell.Invoke(RegisterHandler),
)

type Params struct {
	cell.In

	DB            *statedb.DB
	Nodes         statedb.Table[*node.Node]
	Routes        statedb.Table[*tables.Route]
	DesiredRoutes statedb.Table[*routeReconciler.DesiredRoute]
	RouteManager  *routeReconciler.DesiredRouteManager
	DaemonConfig  *option.DaemonConfig
	NodePolicy    *linux.NodePolicy
	JobGroup      job.Group
	Logger        *slog.Logger
}

func RegisterHandler(params Params) {
	if !params.DaemonConfig.EnableAutoDirectRouting {
		return
	}

	h := &Handler{
		db:            params.DB,
		nodes:         params.Nodes,
		routes:        params.Routes,
		desiredRoutes: params.DesiredRoutes,
		routeManager:  params.RouteManager,
		nodePolicy:    params.NodePolicy,
		initializer:   params.RouteManager.RegisterInitializer(componentName),
		cfg:           params.DaemonConfig,
		logger:        params.Logger,
	}

	params.JobGroup.Add(job.OneShot(
		componentName,
		h.run,
	))
}

type Handler struct {
	db            *statedb.DB
	nodes         statedb.Table[*node.Node]
	routes        statedb.Table[*tables.Route]
	desiredRoutes statedb.Table[*routeReconciler.DesiredRoute]
	routeManager  *routeReconciler.DesiredRouteManager
	nodePolicy    *linux.NodePolicy
	initializer   routeReconciler.Initializer
	cfg           *option.DaemonConfig
	logger        *slog.Logger
}
