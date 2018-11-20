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
	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/k8s"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/pidfile"
)

func (d *Daemon) initHealth() {
	if option.Config.IsPolicyEnforcementInterfaceSet() {
		// Do not run health endpoint in policy enforcement mode as we can't
		// allocate an IP address for this endpoint and the datapath is not
		// controlled by Cilium.
		return
	}

	// Allocate health endpoint IPs after restoring state
	log.Info("Building health endpoint")
	health4, health6, err := ipam.AllocateNext("")
	if err != nil {
		log.WithError(err).Fatal("IPAM allocation failed. For more detail, see https://cilium.link/ipam-range-full")
	}

	err = node.SetIPv4HealthIP(health4)
	if err != nil {
		log.WithError(err).Fatal("Error while set health IPv4 ip on the local node.")
	}

	err = node.SetIPv6HealthIP(health6)
	if err != nil {
		log.WithError(err).Fatal("Error while set health IPv6 ip on the local node.")
	}

	log.Debugf("IPv4 health endpoint address: %s", node.GetIPv4HealthIP())
	log.Debugf("IPv6 health endpoint address: %s", node.GetIPv6HealthIP())
	node.NotifyLocalNodeUpdated()

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

		// Inject K8s dependency into packages which need to annotate K8s resources.
		endpoint.EpAnnotator = k8s.Client()
		health.NodeEpAnnotator = k8s.Client()
	}
	controller.NewManager().UpdateController("cilium-health-ep",
		controller.ControllerParams{
			DoFunc: func() error {
				return d.runCiliumHealthEndpoint()
			},
			StopFunc: func() error {
				err := health.PingEndpoint()
				d.cleanupHealthEndpoint()
				return err
			},
			RunInterval: 30 * time.Second,
		})
}

func (d *Daemon) cleanupHealthEndpoint() {
	// Delete the process
	health.KillEndpoint()
	// Clean up agent resources
	ip6 := node.GetIPv6HealthIP()
	id := addressing.CiliumIPv6(ip6).EndpointID()
	ep := endpointmanager.LookupCiliumID(id)
	if ep == nil {
		log.WithField(logfields.EndpointID, id).Debug("Didn't find existing cilium-health endpoint to delete")
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
func (d *Daemon) runCiliumHealthEndpoint() error {
	// PingEndpoint will always fail the first time (initialization).
	if err := health.PingEndpoint(); err != nil {
		d.cleanupHealthEndpoint()
		addressing := d.getNodeAddressing()
		return health.LaunchAsEndpoint(d, addressing)
	}
	return nil
}
