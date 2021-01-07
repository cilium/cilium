// Copyright 2016-2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	health "github.com/cilium/cilium/cilium-health/launch"
	"github.com/cilium/cilium/pkg/cleanup"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/pidfile"
)

func (d *Daemon) initHealth() {
	if option.Config.IsFlannelMasterDeviceSet() {
		// Do not run health endpoint in policy enforcement mode as we can't
		// allocate an IP address for this endpoint and the datapath is not
		// controlled by Cilium.
		return
	}

	// Launch cilium-health in the same process (and namespace) as cilium.
	log.Info("Launching Cilium health daemon")
	if ch, err := health.Launch(); err != nil {
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
	if k8s.IsEnabled() {
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

	controller.NewManager().UpdateController("cilium-health-ep",
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

					client, launchErr = health.LaunchAsEndpoint(ctx,
						d,
						&d.nodeDiscovery.LocalNode,
						d.mtuConfig,
						d.endpointManager,
						d.l7Proxy,
						d.identityAllocator,
						d.healthEndpointRouting)
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
	cleanup.DeferTerminationCleanupFunction(cleaner.cleanUPWg, cleaner.cleanUPSig, func() {
		health.KillEndpoint()
		health.CleanupEndpoint()
	})
}

func (d *Daemon) cleanupHealthEndpoint() {
	localNode := d.nodeDiscovery.LocalNode

	// Delete the process
	health.KillEndpoint()

	// Clean up agent resources
	var ep *endpoint.Endpoint
	if localNode.IPv4HealthIP != nil {
		ep = d.endpointManager.LookupIPv4(localNode.IPv4HealthIP.String())
	}
	if ep == nil && localNode.IPv6HealthIP != nil {
		ep = d.endpointManager.LookupIPv6(localNode.IPv6HealthIP.String())
	}
	if ep == nil {
		log.Debug("Didn't find existing cilium-health endpoint to delete")
	} else {
		log.Debug("Removing existing cilium-health endpoint")
		errs := d.endpointManager.deleteEndpointQuiet(ep, endpoint.DeleteConfig{
			NoIPRelease: true,
		})
		for _, err := range errs {
			log.WithError(err).Debug("Error occurred while deleting cilium-health endpoint")
		}
	}
	health.CleanupEndpoint()
}
