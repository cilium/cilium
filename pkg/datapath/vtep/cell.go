// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vtep

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/endpointmanager"
	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/maps/vtep"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

var Cell = cell.Module(
	"vtep-integration",
	"VXLAN Tunnel Endpoint Integration",

	cell.Invoke(newVTEPController),
)

type vtepControllerParams struct {
	cell.In

	Logger    *slog.Logger
	Lifecycle cell.Lifecycle
	JobGroup  job.Group

	VTEPMap         vtep.Map
	Clientset       client.Clientset
	EndpointManager endpointmanager.EndpointManager

	DB             *statedb.DB
	LocalNodeTable statedb.Table[*node.LocalNode]

	// VTEPConfigResource is optional - only available when k8s is enabled
	VTEPConfigResource resource.Resource[*cilium_api_v2.CiliumVTEPConfig] `optional:"true"`
}

func newVTEPController(params vtepControllerParams) error {
	if !option.Config.EnableVTEP {
		return nil
	}

	if params.VTEPConfigResource == nil {
		return fmt.Errorf("VTEP is enabled but Kubernetes is not available. " +
			"CiliumVTEPConfig CRD requires a Kubernetes cluster")
	}

	mgr := &vtepManager{
		logger: params.Logger,
		config: vtepManagerConfig{},
	}

	reconciler := newVTEPReconciler(vtepReconcilerParams{
		Logger:          params.Logger,
		VTEPMap:         params.VTEPMap,
		Clientset:       params.Clientset,
		Resource:        params.VTEPConfigResource,
		Manager:         mgr,
		EndpointManager: params.EndpointManager,
		DB:              params.DB,
		LocalNodeTable:  params.LocalNodeTable,
	})

	ctrl := &vtepController{
		logger:     params.Logger,
		manager:    mgr,
		reconciler: reconciler,
		jobGroup:   params.JobGroup,
	}

	params.Lifecycle.Append(cell.Hook{
		OnStart: func(ctx cell.HookContext) error {
			return ctrl.start(ctx)
		},
		OnStop: func(ctx cell.HookContext) error {
			return nil
		},
	})

	return nil
}

// vtepController manages VTEP configuration from CiliumVTEPConfig CRD.
type vtepController struct {
	logger     *slog.Logger
	manager    *vtepManager
	reconciler *VTEPReconciler
	jobGroup   job.Group
}

// start initializes the VTEP controller and spawns the reconciler goroutines.
// With LPM trie there is no global CIDR mask to initialize — each entry
// carries its own prefix length derived from the CIDR notation in the CRD.
func (c *vtepController) start(ctx context.Context) error {
	c.logger.Info("Starting VTEP controller with CiliumVTEPConfig CRD")

	c.jobGroup.Add(job.OneShot("vtep-crd-reconciler", func(ctx context.Context, _ cell.Health) error {
		return c.reconciler.Run(ctx)
	}))

	c.jobGroup.Add(job.OneShot("vtep-node-label-watcher", c.reconciler.watchNodeLabels))

	return nil
}
