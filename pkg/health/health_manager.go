// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package health

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/cilium/hive/cell"

	healthApi "github.com/cilium/cilium/api/v1/health/server"
	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath/linux/bigtcp"
	linuxrouting "github.com/cilium/cilium/pkg/datapath/linux/routing"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/endpoint"
	endpointcreator "github.com/cilium/cilium/pkg/endpoint/creator"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/health/defaults"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/pidfile"
	"github.com/cilium/cilium/pkg/time"
)

const (
	controllerInterval    = 60 * time.Second
	successfulPingTimeout = 5 * time.Minute
)

// Cell provides the Cilium health infrastructure that is responsible for
// checking the connectivity between Cilium nodes and Cilium endpoints.
var Cell = cell.Module(
	"cilium-health",
	"Cilium health infrastructure",
	cell.Provide(newCiliumHealthManager),
)

type CiliumHealthManager interface {
	Init(ctx context.Context, routingInfo *linuxrouting.RoutingInfo, addCleanerFunc func(newFunc func())) error
	GetStatus() *models.Status
}

type ciliumHealthManager struct {
	logger          *slog.Logger
	healthSpec      *healthApi.Spec
	sysctl          sysctl.Sysctl
	loader          datapath.Loader
	mtuConfig       mtu.MTU
	bigTCPConfig    *bigtcp.Configuration
	endpointCreator endpointcreator.EndpointCreator
	endpointManager endpointmanager.EndpointManager
	k8sClientSet    k8sClient.Clientset

	ctrlMgr      *controller.Manager
	ciliumHealth *CiliumHealth
}

type ciliumHealthParams struct {
	cell.In

	Logger          *slog.Logger
	Lifecycle       cell.Lifecycle
	HealthSpec      *healthApi.Spec
	Sysctl          sysctl.Sysctl
	Loader          datapath.Loader
	MtuConfig       mtu.MTU
	BigTCPConfig    *bigtcp.Configuration
	EndpointCreator endpointcreator.EndpointCreator
	EndpointManager endpointmanager.EndpointManager
	K8sClientSet    k8sClient.Clientset
}

func newCiliumHealthManager(params ciliumHealthParams) CiliumHealthManager {
	h := &ciliumHealthManager{
		logger:          params.Logger,
		healthSpec:      params.HealthSpec,
		sysctl:          params.Sysctl,
		loader:          params.Loader,
		mtuConfig:       params.MtuConfig,
		bigTCPConfig:    params.BigTCPConfig,
		endpointCreator: params.EndpointCreator,
		endpointManager: params.EndpointManager,
		k8sClientSet:    params.K8sClientSet,
	}

	return h
}

func (h *ciliumHealthManager) Init(ctx context.Context, routingInfo *linuxrouting.RoutingInfo, addCleanerFunc func(newFunc func())) error {
	// Launch cilium-health in the same process (and namespace) as cilium.
	h.logger.Info("Launching Cilium health daemon")
	ch, err := h.launchCiliumNodeHealth(h.healthSpec, h.loader.HostDatapathInitialized())
	if err != nil {
		return fmt.Errorf("failed to start cilium health: %w", err)
	}

	h.ciliumHealth = ch

	// If endpoint health checking is disabled, the virtual endpoint does not need to be launched
	if !option.Config.EnableEndpointHealthChecking {
		return nil
	}

	// Launch the cilium-health-responder as an endpoint, managed by cilium.
	h.logger.Info("Launching Cilium health endpoint")
	if h.k8sClientSet.IsEnabled() {
		// When Cilium starts up in k8s mode, it is guaranteed to be
		// running inside a new PID namespace which means that existing
		// PIDfiles are referring to PIDs that may be reused. Clean up.
		pidfilePath := filepath.Join(option.Config.StateDir, defaults.PidfilePath)
		if err := pidfile.Remove(pidfilePath); err != nil {
			h.logger.Warn("Failed to remove pidfile",
				logfields.PIDFile, pidfilePath,
				logfields.Error, err,
			)
		}
	}

	// Wait for the API, then launch the controller
	var client *Client
	var lastSuccessfulPing time.Time

	h.ctrlMgr = controller.NewManager()
	h.ctrlMgr.UpdateController(
		defaults.HealthEPName,
		controller.ControllerParams{
			Group: controller.NewGroup("cilium-health"),
			DoFunc: func(ctx context.Context) error {
				var err error

				if client != nil {
					err = client.PingEndpoint()
					if err == nil {
						h.logger.Debug("Successfully pinged health endpoint")
						lastSuccessfulPing = time.Now()
					} else {
						h.logger.Debug("Failed to ping health endpoint", logfields.Error, err)
					}
				}

				// Restart the health EP if too much time has gone since the
				// lastSuccessfulPing time, which is also true for a non-existent
				// client
				if time.Since(lastSuccessfulPing) > successfulPingTimeout {
					h.logger.Debug("Restart health endpoint after timeout")
					h.cleanupHealthEndpoint()

					client, err = h.launchAsEndpoint(ctx, h.endpointCreator, h.endpointManager, h.mtuConfig, h.bigTCPConfig, routingInfo, h.sysctl)
					if err == nil {
						// Reset lastSuccessfulPing after the new endpoint
						// is launched to give it time to come up before
						// killing it again
						lastSuccessfulPing = time.Now()
						h.logger.Debug("Successfully launched health endpoint")
					} else {
						h.logger.Debug("Failed to launch health endpoint", logfields.Error, err)
					}
				}
				return err
			},
			StopFunc: func(ctx context.Context) error {
				h.logger.Info("Stopping health endpoint")
				h.cleanupHealthEndpoint()
				return err
			},
			RunInterval: controllerInterval,
			Context:     ctx,
		},
	)

	// Make sure to clean up the endpoint namespace when cilium-agent terminates
	addCleanerFunc(h.ctrlMgr.RemoveAllAndWait)

	return nil
}

func (h *ciliumHealthManager) cleanupHealthEndpoint() {
	var ep *endpoint.Endpoint

	h.logger.Info("Cleaning up Cilium health endpoint")

	// Clean up agent resources
	healthIPv4 := node.GetEndpointHealthIPv4()
	healthIPv6 := node.GetEndpointHealthIPv6()
	if healthIPv4 != nil {
		ep = h.endpointManager.LookupIPv4(healthIPv4.String())
	}
	if ep == nil && healthIPv6 != nil {
		ep = h.endpointManager.LookupIPv6(healthIPv6.String())
	}
	if ep == nil {
		h.logger.Debug("Didn't find existing cilium-health endpoint to delete")
	} else {
		h.logger.Debug("Removing existing cilium-health endpoint")
		errs := h.endpointManager.RemoveEndpoint(ep, endpoint.DeleteConfig{NoIPRelease: true})
		for _, err := range errs {
			h.logger.Warn("Ignoring error while deleting Cilium health endpoint", logfields.Error, err)
		}
	}

	// The CNI plugin is not invoked for the health endpoint since it was
	// spawned by the agent itself. The endpoint manager will only down the
	// device, but not remove it. Hence we need to trigger final removal.

	// Delete the process
	h.killEndpoint()

	// Remove health endpoint devices
	h.cleanupEndpoint()
}

func (h *ciliumHealthManager) GetStatus() *models.Status {
	if h.ciliumHealth == nil {
		return nil
	}

	return h.ciliumHealth.GetStatus()
}
