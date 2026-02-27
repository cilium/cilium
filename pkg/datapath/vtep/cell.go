// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package vtep

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/spf13/pflag"

	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/resource"
	"github.com/cilium/cilium/pkg/maps/vtep"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

var Cell = cell.Module(
	"vtep-integration",
	"VXLAN Tunnel Endpoint Integration",

	cell.Config(config{
		VTEPProbeInterval:       defaultProbeInterval,
		VTEPProbeTimeout:        defaultProbeTimeout,
		VTEPFailureThreshold:    defaultFailureThreshold,
		VTEPMinFailoverInterval: defaultMinFailoverInterval,
	}),
	cell.Invoke(newVTEPController),
)

type vtepControllerParams struct {
	cell.In

	Logger    *slog.Logger
	Lifecycle cell.Lifecycle
	JobGroup  job.Group

	VTEPMap   vtep.Map
	Config    config
	Clientset client.Clientset

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

	// Create the manager for route management
	mgr := &vtepManager{
		logger:  params.Logger,
		vtepMap: params.VTEPMap,
		config:  vtepManagerConfig{},
	}

	failoverCh := make(chan failoverEvent, 16)

	healthMonitor := newVTEPHealthMonitor(params.Logger, failoverCh)
	healthMonitor.probeInterval = params.Config.VTEPProbeInterval
	healthMonitor.probeTimeout = params.Config.VTEPProbeTimeout
	healthMonitor.failureThreshold = params.Config.VTEPFailureThreshold
	healthMonitor.minFailoverInterval = params.Config.VTEPMinFailoverInterval

	reconciler := newVTEPReconciler(vtepReconcilerParams{
		Logger:        params.Logger,
		VTEPMap:       params.VTEPMap,
		Clientset:     params.Clientset,
		Resource:      params.VTEPConfigResource,
		Manager:       mgr,
		HealthMonitor: healthMonitor,
		FailoverCh:    failoverCh,
	})

	ctrl := &vtepController{
		logger:        params.Logger,
		manager:       mgr,
		reconciler:    reconciler,
		healthMonitor: healthMonitor,
		jobGroup:      params.JobGroup,
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
	logger        *slog.Logger
	manager       *vtepManager
	reconciler    *VTEPReconciler
	healthMonitor *vtepHealthMonitor
	jobGroup      job.Group
}

// start initializes the VTEP controller.
func (c *vtepController) start(ctx context.Context) error {
	c.logger.Info("Starting VTEP controller with CiliumVTEPConfig CRD")

	// Do initial sync from CRD
	if err := c.reconciler.SyncFromCRD(ctx); err != nil {
		c.logger.Error("Initial VTEP CRD sync failed", "error", err)
		// Continue anyway, reconciler will retry
	}

	// Start the reconciler job to watch for CRD changes and failover events
	c.jobGroup.Add(job.OneShot("vtep-crd-reconciler", func(ctx context.Context, _ cell.Health) error {
		return c.reconciler.Run(ctx)
	}))

	// Start the health monitor as a periodic timer.
	// The monitor only probes endpoints that have standby configured.
	c.jobGroup.Add(job.Timer("vtep-health-monitor", c.healthMonitor.probe, c.healthMonitor.probeInterval))

	return nil
}

type config struct {
	VTEPProbeInterval       time.Duration
	VTEPProbeTimeout        time.Duration
	VTEPFailureThreshold    int
	VTEPMinFailoverInterval time.Duration
}

func (r config) Flags(flags *pflag.FlagSet) {
	flags.Duration("vtep-probe-interval", r.VTEPProbeInterval, "Interval between ICMP health probes for VTEP endpoints with standby")
	flags.Duration("vtep-probe-timeout", r.VTEPProbeTimeout, "Timeout for ICMP health probes")
	flags.Int("vtep-failure-threshold", r.VTEPFailureThreshold, "Number of consecutive probe failures before triggering failover")
	flags.Duration("vtep-min-failover-interval", r.VTEPMinFailoverInterval, "Minimum time between failovers for the same endpoint")
}
