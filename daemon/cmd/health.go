// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	healthApi "github.com/cilium/cilium/api/v1/health/server"
	health "github.com/cilium/cilium/cilium-health/launch"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/health/defaults"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/pidfile"
)

func (d *Daemon) initHealth(spec *healthApi.Spec, cleaner *daemonCleanup) {
	// Launch cilium-health in the same process (and namespace) as cilium.
	log.Info("Launching Cilium health daemon")
	if ch, err := health.Launch(spec); err != nil {
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

	controller.NewManager().UpdateController(defaults.HealthEPName,
		controller.ControllerParams{
			DoFunc: func(ctx context.Context) error {
				var err error

				if client != nil {
					err = client.PingEndpoint()
				}
				// On the first initialization, or on
				// error, restart the health EP.
				if client == nil || err != nil {
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
						d.l7Proxy,
						d.identityAllocator,
						d.healthEndpointRouting,
					)
					if launchErr != nil {
						if err != nil {
							return fmt.Errorf("failed to restart endpoint (check failed: %q): %s", err, launchErr)
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
			RunInterval: 60 * time.Second,
			Context:     d.ctx,
		},
	)

	// Make sure to clean up the endpoint namespace when cilium-agent terminates
	cleaner.cleanupFuncs.Add(health.KillEndpoint)
	cleaner.cleanupFuncs.Add(health.CleanupEndpoint)
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
