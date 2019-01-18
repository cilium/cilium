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
	"time"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodemanager "github.com/cilium/cilium/pkg/node/manager"
	nodestore "github.com/cilium/cilium/pkg/node/store"
	"github.com/cilium/cilium/pkg/option"
)

type nodeDiscovery struct {
	manager     *nodemanager.Manager
	localConfig datapath.LocalNodeConfiguration
	registrar   nodestore.NodeRegistrar
	localNode   node.Node
	registered  chan struct{}
}

func enableLocalNodeRoute() bool {
	if option.Config.DatapathMode == option.DatapathModeIpvlan {
		return false
	}

	if option.Config.IsFlannelMasterDeviceSet() {
		return false
	}

	return true
}

func newNodeDiscovery(manager *nodemanager.Manager, mtuConfig mtu.Configuration) *nodeDiscovery {
	auxPrefixes := []*cidr.CIDR{}

	if option.Config.IPv4ServiceRange != AutoCIDR {
		serviceCIDR, err := cidr.ParseCIDR(option.Config.IPv4ServiceRange)
		if err != nil {
			log.WithError(err).WithField(logfields.V4Prefix, option.Config.IPv4ServiceRange).Fatal("Invalid IPv4 service prefix")
		}

		auxPrefixes = append(auxPrefixes, serviceCIDR)
	}

	if option.Config.IPv6ServiceRange != AutoCIDR {
		serviceCIDR, err := cidr.ParseCIDR(option.Config.IPv6ServiceRange)
		if err != nil {
			log.WithError(err).WithField(logfields.V6Prefix, option.Config.IPv6ServiceRange).Fatal("Invalid IPv6 service prefix")
		}

		auxPrefixes = append(auxPrefixes, serviceCIDR)
	}

	return &nodeDiscovery{
		manager: manager,
		localConfig: datapath.LocalNodeConfiguration{
			MtuConfig:               mtuConfig,
			UseSingleClusterRoute:   option.Config.UseSingleClusterRoute,
			EnableIPv4:              option.Config.EnableIPv4,
			EnableIPv6:              option.Config.EnableIPv6,
			EnableEncapsulation:     option.Config.Tunnel != option.TunnelDisabled,
			EnableAutoDirectRouting: option.Config.EnableAutoDirectRouting,
			EnableLocalNodeRoute:    enableLocalNodeRoute(),
			AuxiliaryPrefixes:       auxPrefixes,
		},
		localNode: node.Node{
			Source: node.FromLocalNode,
		},
		registered: make(chan struct{}),
	}
}

// start configures the local node and starts node discovery. This is called on
// agent startup to configure the local node based on the configuration options
// passed to the agent
func (n *nodeDiscovery) startDiscovery() {
	n.localNode.Name = node.GetName()
	n.localNode.Cluster = option.Config.ClusterName
	n.localNode.IPAddresses = []node.Address{
		{
			Type: addressing.NodeInternalIP,
			IP:   node.GetExternalIPv4(),
		},
	}
	n.localNode.IPv4AllocCIDR = node.GetIPv4AllocRange()
	n.localNode.IPv6AllocCIDR = node.GetIPv6AllocRange()
	n.localNode.ClusterID = option.Config.ClusterID

	n.manager.NodeUpdated(n.localNode)

	go func() {
		log.Info("Adding local node to cluster")
		if err := n.registrar.RegisterNode(&n.localNode, n.manager); err != nil {
			log.WithError(err).Fatal("Unable to initialize local node")
		}
		close(n.registered)
	}()

	go func() {
		select {
		case <-n.registered:
		case <-time.NewTimer(defaults.NodeInitTimeout).C:
			log.Fatalf("Unable to initialize local node due to timeout")
		}
	}()

	go func() {
		<-n.registered
		controller.NewManager().UpdateController("propagating local node change to kv-store",
			controller.ControllerParams{
				DoFunc: func() error {
					err := n.registrar.UpdateLocalKeySync(&n.localNode)
					if err != nil {
						log.WithError(err).Error("Unable to propagate local node change to kvstore")
					}
					return err
				},
			})
	}()
}

// Close shuts down the node discovery engine
func (n *nodeDiscovery) Close() {
	n.manager.Close()
}
