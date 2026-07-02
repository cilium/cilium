// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vtep

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	cilium_api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/maps/vtep"
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

	VTEPMap   vtep.Map
	Clientset client.Clientset

	// VTEPNodeConfigResource is the agent's own per-node CiliumVTEPNodeConfig
	// (field-selected to metadata.name == node name in daemon/k8s). It is optional -
	// only available when k8s is enabled. The operator creates and populates it.
	VTEPNodeConfigResource resource.Resource[*cilium_api_v2alpha1.CiliumVTEPNodeConfig] `optional:"true"`
}

func newVTEPController(params vtepControllerParams) error {
	if !option.Config.EnableVTEP {
		return nil
	}

	if params.VTEPNodeConfigResource == nil {
		return fmt.Errorf("VTEP is enabled but Kubernetes is not available. " +
			"CiliumVTEPNodeConfig CRD requires a Kubernetes cluster")
	}

	mgr := &vtepManager{
		logger: params.Logger,
		config: vtepManagerConfig{},
	}

	reconciler := newVTEPReconciler(vtepReconcilerParams{
		Logger:    params.Logger,
		VTEPMap:   params.VTEPMap,
		Clientset: params.Clientset,
		Resource:  params.VTEPNodeConfigResource,
		Manager:   mgr,
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

// vtepController reconciles this node's CiliumVTEPNodeConfig into the BPF map.
type vtepController struct {
	logger     *slog.Logger
	manager    *vtepManager
	reconciler *VTEPReconciler
	jobGroup   job.Group
}

// start initializes the VTEP controller and spawns the reconciler goroutine.
// With LPM trie there is no global CIDR mask to initialize — each entry
// carries its own prefix length derived from the CIDR notation in the resolved spec.
func (c *vtepController) start(ctx context.Context) error {
	c.logger.Info("Starting VTEP controller watching this node's CiliumVTEPNodeConfig")

	c.jobGroup.Add(job.OneShot("vtep-node-config-reconciler", func(ctx context.Context, _ cell.Health) error {
		return c.reconciler.Run(ctx)
	}))

	return nil
}
