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

package nodediscovery

import (
	"context"
	"time"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodemanager "github.com/cilium/cilium/pkg/node/manager"
	nodestore "github.com/cilium/cilium/pkg/node/store"
	"github.com/cilium/cilium/pkg/option"
)

const (
	// AutoCIDR indicates that a CIDR should be allocated
	AutoCIDR = "auto"

	nodeDiscoverySubsys = "nodediscovery"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, nodeDiscoverySubsys)

// NodeDiscovery represents a node discovery action
type NodeDiscovery struct {
	Manager     *nodemanager.Manager
	LocalConfig datapath.LocalNodeConfiguration
	Registrar   nodestore.NodeRegistrar
	LocalNode   node.Node
	Registered  chan struct{}
}

func enableLocalNodeRoute() bool {
	if option.Config.IsFlannelMasterDeviceSet() {
		return false
	}

	return true
}

// NewNodeDiscovery returns a pointer to new node discovery object
func NewNodeDiscovery(manager *nodemanager.Manager, mtuConfig mtu.Configuration) *NodeDiscovery {
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

	return &NodeDiscovery{
		Manager: manager,
		LocalConfig: datapath.LocalNodeConfiguration{
			MtuConfig:               mtuConfig,
			UseSingleClusterRoute:   option.Config.UseSingleClusterRoute,
			EnableIPv4:              option.Config.EnableIPv4,
			EnableIPv6:              option.Config.EnableIPv6,
			EnableEncapsulation:     option.Config.Tunnel != option.TunnelDisabled,
			EnableAutoDirectRouting: option.Config.EnableAutoDirectRouting,
			EnableLocalNodeRoute:    enableLocalNodeRoute(),
			AuxiliaryPrefixes:       auxPrefixes,
			EnableIPSec:             option.Config.EnableIPSec,
		},
		LocalNode: node.Node{
			Source: node.FromLocalNode,
		},
		Registered: make(chan struct{}),
	}
}

// start configures the local node and starts node discovery. This is called on
// agent startup to configure the local node based on the configuration options
// passed to the agent. nodeName is the name to be used in the local agent.
func (n *NodeDiscovery) StartDiscovery(nodeName string) {
	n.LocalNode.Name = nodeName
	n.LocalNode.Cluster = option.Config.ClusterName
	n.LocalNode.IPAddresses = []node.Address{}
	n.LocalNode.IPv4AllocCIDR = node.GetIPv4AllocRange()
	n.LocalNode.IPv6AllocCIDR = node.GetIPv6AllocRange()
	n.LocalNode.ClusterID = option.Config.ClusterID
	n.LocalNode.EncryptionKey = node.GetIPsecKeyIdentity()

	if node.GetExternalIPv4() != nil {
		n.LocalNode.IPAddresses = append(n.LocalNode.IPAddresses, node.Address{
			Type: addressing.NodeInternalIP,
			IP:   node.GetExternalIPv4(),
		})
	}

	if node.GetIPv6() != nil {
		n.LocalNode.IPAddresses = append(n.LocalNode.IPAddresses, node.Address{
			Type: addressing.NodeInternalIP,
			IP:   node.GetIPv6(),
		})
	}

	if node.GetInternalIPv4() != nil {
		n.LocalNode.IPAddresses = append(n.LocalNode.IPAddresses, node.Address{
			Type: addressing.NodeCiliumInternalIP,
			IP:   node.GetInternalIPv4(),
		})
	}

	if node.GetIPv6Router() != nil {
		n.LocalNode.IPAddresses = append(n.LocalNode.IPAddresses, node.Address{
			Type: addressing.NodeCiliumInternalIP,
			IP:   node.GetIPv6Router(),
		})
	}

	n.Manager.NodeUpdated(n.LocalNode)

	go func() {
		log.Info("Adding local node to cluster")
		if err := n.Registrar.RegisterNode(&n.LocalNode, n.Manager); err != nil {
			log.WithError(err).Fatal("Unable to initialize local node")
		}
		close(n.Registered)
	}()

	go func() {
		select {
		case <-n.Registered:
		case <-time.NewTimer(defaults.NodeInitTimeout).C:
			log.Fatalf("Unable to initialize local node due to timeout")
		}
	}()

	go func() {
		<-n.Registered
		controller.NewManager().UpdateController("propagating local node change to kv-store",
			controller.ControllerParams{
				DoFunc: func(ctx context.Context) error {
					err := n.Registrar.UpdateLocalKeySync(&n.LocalNode)
					if err != nil {
						log.WithError(err).Error("Unable to propagate local node change to kvstore")
					}
					return err
				},
			})
	}()
}

// Close shuts down the node discovery engine
func (n *NodeDiscovery) Close() {
	n.Manager.Close()
}
