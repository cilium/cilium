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

	"github.com/cilium/cilium/pkg/aws/metadata"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodemanager "github.com/cilium/cilium/pkg/node/manager"
	nodestore "github.com/cilium/cilium/pkg/node/store"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"

	cnitypes "github.com/cilium/cilium/plugins/cilium-cni/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	return !option.Config.IsFlannelMasterDeviceSet() && option.Config.IPAM != option.IPAMENI
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
			EncryptNode:             option.Config.EncryptNode,
			IPv4PodSubnets:          option.Config.IPv4PodSubnets,
			IPv6PodSubnets:          option.Config.IPv6PodSubnets,
		},
		LocalNode: node.Node{
			Source: source.Local,
		},
		Registered: make(chan struct{}),
	}
}

// Configuration is the configuration interface that must be implemented in
// order to manage node discovery
type Configuration interface {
	// GetNetConf must return the CNI configuration as passed in by the
	// user
	GetNetConf() *cnitypes.NetConf
}

// start configures the local node and starts node discovery. This is called on
// agent startup to configure the local node based on the configuration options
// passed to the agent. nodeName is the name to be used in the local agent.
func (n *NodeDiscovery) StartDiscovery(nodeName string, conf Configuration) {
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
		for {
			if err := n.Registrar.RegisterNode(&n.LocalNode, n.Manager); err != nil {
				log.WithError(err).Error("Unable to initialize local node. Retrying...")
				time.Sleep(time.Second)
			} else {
				break
			}
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

	if k8s.IsEnabled() {
		// Creation of the CiliumNode can be done in the background,
		// nothing depends on the completion of this.
		go n.createCiliumNodeResource(conf)
	}

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

func (n *NodeDiscovery) createCiliumNodeResource(conf Configuration) {
	if !option.Config.AutoCreateCiliumNodeResource {
		return
	}

	ciliumClient := k8s.CiliumClient()

	nodeResource := &ciliumv2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: node.GetName(),
		},
	}

	// Tie the CiliumNode custom resource lifecycle to the lifecycle of the
	// Kubernetes node
	if k8sNode, err := k8s.GetNode(k8s.Client(), node.GetName()); err != nil {
		log.Warning("Kubernetes node resource representing own node is not available, cannot set OwnerReference")
	} else {
		nodeResource.ObjectMeta.OwnerReferences = []metav1.OwnerReference{{
			APIVersion: "v1",
			Kind:       "Node",
			Name:       node.GetName(),
			UID:        k8sNode.UID,
		}}
	}

	if option.Config.IPAM == option.IPAMENI {
		instanceID, instanceType, availabilityZone, vpcID, err := metadata.GetInstanceMetadata()
		if err != nil {
			log.WithError(err).Fatal("Unable to retrieve InstanceID of own EC2 instance")
		}

		nodeResource.Spec.ENI.VpcID = vpcID
		nodeResource.Spec.ENI.FirstInterfaceIndex = 1
		nodeResource.Spec.ENI.DeleteOnTermination = true
		nodeResource.Spec.ENI.PreAllocate = defaults.ENIPreAllocation

		if c := conf.GetNetConf(); c != nil {
			if c.ENI.MinAllocate != 0 {
				nodeResource.Spec.ENI.MinAllocate = c.ENI.MinAllocate
			}

			if c.ENI.PreAllocate != 0 {
				nodeResource.Spec.ENI.PreAllocate = c.ENI.PreAllocate
			}

			if c.ENI.FirstInterfaceIndex != 0 {
				nodeResource.Spec.ENI.FirstInterfaceIndex = c.ENI.FirstInterfaceIndex
			}

			if len(c.ENI.SecurityGroups) > 0 {
				nodeResource.Spec.ENI.SecurityGroups = c.ENI.SecurityGroups
			}

			if len(c.ENI.SubnetTags) > 0 {
				nodeResource.Spec.ENI.SubnetTags = c.ENI.SubnetTags
			}

			if c.ENI.VpcID != "" {
				nodeResource.Spec.ENI.VpcID = c.ENI.VpcID
			}

			nodeResource.Spec.ENI.DeleteOnTermination = c.ENI.DeleteOnTermination
		}

		nodeResource.Spec.ENI.InstanceID = instanceID
		nodeResource.Spec.ENI.InstanceType = instanceType
		nodeResource.Spec.ENI.AvailabilityZone = availabilityZone
	}

	_, err := ciliumClient.CiliumV2().CiliumNodes().Create(nodeResource)
	if err != nil {
		log.WithError(err).Fatal("Unable to create CiliumNode resource")
	}
}
