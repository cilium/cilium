// Copyright 2016-2018 Authors of Cilium
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
	"path/filepath"
	"time"

	health "github.com/cilium/cilium/cilium-health/launch"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/node"
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

	// Allocate health endpoint IPs after restoring state
	log.Info("Building health endpoint")

	// Launch cilium-health in the same namespace as cilium.
	log.Info("Launching Cilium health daemon")
	d.ciliumHealth = &health.CiliumHealth{}
	go d.ciliumHealth.Run()

	// Launch another cilium-health as an endpoint, managed by cilium.
	log.Info("Launching Cilium health endpoint")
	if k8s.IsEnabled() {
		// When Cilium starts up in k8s mode, it is guaranteed to be
		// running inside a new PID namespace which means that existing
		// PIDfiles are referring to PIDs that may be reused. Clean up.
		pidfile.Remove(filepath.Join(option.Config.StateDir, health.PidfilePath))
	}
	controller.NewManager().UpdateController("cilium-health-ep",
		controller.ControllerParams{
			DoFunc: func() error {
				return d.runCiliumHealthEndpoint(d.nodeDiscovery.localNode)
			},
			StopFunc: func() error {
				log.Info("Stopping health endpoint")
				err := health.PingEndpoint()
				d.cleanupHealthEndpoint(d.nodeDiscovery.localNode)
				return err
			},
			RunInterval: 30 * time.Second,
		})
}

func (d *Daemon) cleanupHealthEndpoint(localNode node.Node) {
	// Delete the process
	health.KillEndpoint()

	// Clean up agent resources
	var ep *endpoint.Endpoint
	if localNode.IPv4HealthIP != nil {
		ep = endpointmanager.LookupIPv4(localNode.IPv4HealthIP.String())
	}
	if ep == nil && localNode.IPv6HealthIP != nil {
		ep = endpointmanager.LookupIPv6(localNode.IPv6HealthIP.String())
	}
	if ep == nil {
		log.Debug("Didn't find existing cilium-health endpoint to delete")
	} else {
		log.Debug("Removing existing cilium-health endpoint")
		errs := d.deleteEndpointQuiet(ep, false)
		for _, err := range errs {
			log.WithError(err).Debug("Error occurred while deleting cilium-health endpoint")
		}
	}
	health.CleanupEndpoint()
}

// runCiliumHealthEndpoint attempts to contact the cilium-health endpoint, and
// if it cannot be reached, restarts it.
func (d *Daemon) runCiliumHealthEndpoint(localNode node.Node) error {
	// PingEndpoint will always fail the first time (initialization).
	if err := health.PingEndpoint(); err != nil {
		log.WithError(err).Warning("health endpoint is unreachable, restarting health endpoint")
		d.cleanupHealthEndpoint(localNode)
		addressing := node.GetNodeAddressing()
		return health.LaunchAsEndpoint(d, addressing, d.mtuConfig,
			localNode.IPv4HealthIP, localNode.IPv6HealthIP)
	}
	return nil
}
