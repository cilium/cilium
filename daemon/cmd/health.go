// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"path/filepath"

	healthApi "github.com/cilium/cilium/api/v1/health/server"
	health "github.com/cilium/cilium/cilium-health/launch"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath/linux/sysctl"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/health/defaults"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/pidfile"
	"github.com/cilium/cilium/pkg/time"
)

var healthControllerGroup = controller.NewGroup("cilium-health")

const (
	controllerInterval    = 60 * time.Second
	successfulPingTimeout = 3 * time.Minute
)

func (d *Daemon) initHealth(spec *healthApi.Spec, cleaner *daemonCleanup, sysctl sysctl.Sysctl) {
	// Launch cilium-health in the same process (and namespace) as cilium.
	log.Info("Launching Cilium health daemon")
	if ch, err := health.Launch(spec, d.datapath.Loader().HostDatapathInitialized()); err != nil {
		log.WithError(err).Fatal("Failed to launch cilium-health")
	} else {
		d.ciliumHealth = ch
	}

	// If endpoint health checking is disabled, the virtual endpoint does not need to be launched
	if !option.Config.EnableEndpointHealthChecking {
		return
	}

	// Launch the cilium-health-responder as an endpoint, managed by cilium.
	log.Info("Launching Cilium health endpoint")
	if d.clientset.IsEnabled() {
		// When Cilium starts up in k8s mode, it is guaranteed to be
		// running inside a new PID namespace which means that existing
		// PIDfiles are referring to PIDs that may be reused. Clean up.
		pidfilePath := filepath.Join(option.Config.StateDir, health.PidfilePath)
		if err := pidfile.Remove(pidfilePath); err != nil {
			log.WithField(logfields.PIDFile, pidfilePath).
				WithError(err).
				Warning("Failed to remove pidfile")
		}
	}

	// Wait for the API, then launch the controller
	var client *health.Client
	var lastSuccessfulPing time.Time

	controller.NewManager().UpdateController(
		defaults.HealthEPName,
		controller.ControllerParams{
			Group: healthControllerGroup,
			DoFunc: func(ctx context.Context) error {
				var err error

				if client != nil {
					err = client.PingEndpoint()
				}

				// Reset lastSuccessfulPing if err is nil, which happens
				// a) if we successfully pinged the endpoint above
				// b) on first initialization, i.e. we have not attempted to ping yet
				if err == nil {
					lastSuccessfulPing = time.Now()
				}

				// On the first initialization (client == nil), or if we have not
				// successfully pinged it since successfulPingTimeout, restart the health EP.
				if client == nil || time.Since(lastSuccessfulPing) > successfulPingTimeout {
					var launchErr error
					d.cleanupHealthEndpoint()

					client, launchErr = health.LaunchAsEndpoint(
						ctx,
						d,
						d,
						d.ipcache,
						d.mtuConfig,
						d.bigTCPConfig,
						d.endpointManager,
						d.identityAllocator,
						d.healthEndpointRouting,
						sysctl,
					)
					if launchErr != nil {
						if err != nil {
							return fmt.Errorf("failed to restart endpoint (check failed: %w): %w", err, launchErr)
						}
						return launchErr
					}
				}
				return err
			},
			StopFunc: func(ctx context.Context) error {
				log.Info("Stopping health endpoint")
				err := client.PingEndpoint()
				d.cleanupHealthEndpoint()
				return err
			},
			RunInterval: controllerInterval,
			Context:     d.ctx,
		},
	)

	// Make sure to clean up the endpoint namespace when cilium-agent terminates
	cleaner.cleanupFuncs.Add(d.cleanupHealthEndpoint)
}

func (d *Daemon) cleanupHealthEndpoint() {
	// Delete the process
	health.KillEndpoint()

	// Clean up agent resources
	var ep *endpoint.Endpoint
	healthIPv4 := node.GetEndpointHealthIPv4()
	healthIPv6 := node.GetEndpointHealthIPv6()
	if healthIPv4 != nil {
		ep = d.endpointManager.LookupIPv4(healthIPv4.String())
	}
	if ep == nil && healthIPv6 != nil {
		ep = d.endpointManager.LookupIPv6(healthIPv6.String())
	}
	if ep == nil {
		log.Debug("Didn't find existing cilium-health endpoint to delete")
	} else {
		log.Debug("Removing existing cilium-health endpoint")
		errs := d.deleteEndpointQuiet(ep, endpoint.DeleteConfig{
			NoIPRelease: true,
		})
		for _, err := range errs {
			log.WithError(err).Debug("Error occurred while deleting cilium-health endpoint")
		}
	}
	health.CleanupEndpoint()
}
