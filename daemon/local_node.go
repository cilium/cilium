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
	"net"
	"time"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	"github.com/cilium/cilium/pkg/option"
)

// LocalNode returns the identity and node spec for the local node
func (d *Daemon) LocalNode() *node.Node {
	return &d.localNode
}

func (d *Daemon) setIPv4HealthIP(ip net.IP) {
	d.localNode.IPv4HealthIP = ip
}

func (d *Daemon) setIPv6HealthIP(ip net.IP) {
	d.localNode.IPv6HealthIP = ip
}

// configureLocalNode configures the local node. This is called on agent
// startup to configure the local node based on the configuration options
// passed to the agent
func (d *Daemon) configureLocalNode() {
	d.localNode.Name = node.GetName()
	d.localNode.Cluster = option.Config.ClusterName
	d.localNode.IPAddresses = []node.Address{
		{
			Type: addressing.NodeInternalIP,
			IP:   node.GetExternalIPv4(),
		},
	}
	d.localNode.IPv4AllocCIDR = node.GetIPv4AllocRange()
	d.localNode.IPv6AllocCIDR = node.GetIPv6AllocRange()
	d.localNode.ClusterID = option.Config.ClusterID

	d.nodeManager.NodeUpdated(d.localNode)

	go func() {
		log.Info("Adding local node to cluster")
		if err := d.nodeRegistrar.RegisterNode(&d.localNode, d.nodeManager); err != nil {
			log.WithError(err).Fatal("Unable to initialize local node")
		}
		close(d.nodeRegistered)
	}()

	go func() {
		select {
		case <-d.nodeRegistered:
		case <-time.NewTimer(defaults.NodeInitTimeout).C:
			log.Fatalf("Unable to initialize local node due timeout")
		}
	}()

	go func() {
		<-d.nodeRegistered
		controller.NewManager().UpdateController("propagating local node change to kv-store",
			controller.ControllerParams{
				DoFunc: func() error {
					err := d.nodeRegistrar.UpdateLocalKeySync(&d.localNode)
					if err != nil {
						log.WithError(err).Error("Unable to propagate local node change to kvstore")
					}
					return err
				},
			})
	}()
}
