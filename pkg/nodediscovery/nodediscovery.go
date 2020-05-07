// Copyright 2016-2020 Authors of Cilium
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
	"strings"
	"time"

	eniTypes "github.com/cilium/cilium/pkg/aws/eni/types"
	"github.com/cilium/cilium/pkg/aws/metadata"
	azureTypes "github.com/cilium/cilium/pkg/azure/types"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/defaults"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/core/v1"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodemanager "github.com/cilium/cilium/pkg/node/manager"
	nodestore "github.com/cilium/cilium/pkg/node/store"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
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
	LocalNode   nodeTypes.Node
	Registered  chan struct{}
	NetConf     *cnitypes.NetConf
}

func enableLocalNodeRoute() bool {
	return option.Config.EnableLocalNodeRoute && !option.Config.IsFlannelMasterDeviceSet() && option.Config.IPAM != ipamOption.IPAMENI
}

func getInt(i int) *int {
	return &i
}

// NewNodeDiscovery returns a pointer to new node discovery object
func NewNodeDiscovery(manager *nodemanager.Manager, mtuConfig mtu.Configuration, netConf *cnitypes.NetConf) *NodeDiscovery {
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
		LocalNode: nodeTypes.Node{
			Source: source.Local,
		},
		Registered: make(chan struct{}),
		NetConf:    netConf,
	}
}

// start configures the local node and starts node discovery. This is called on
// agent startup to configure the local node based on the configuration options
// passed to the agent. nodeName is the name to be used in the local agent.
func (n *NodeDiscovery) StartDiscovery(nodeName string) {
	n.LocalNode.Name = nodeName
	n.LocalNode.Cluster = option.Config.ClusterName
	n.LocalNode.IPAddresses = []nodeTypes.Address{}
	n.LocalNode.IPv4AllocCIDR = node.GetIPv4AllocRange()
	n.LocalNode.IPv6AllocCIDR = node.GetIPv6AllocRange()
	n.LocalNode.ClusterID = option.Config.ClusterID
	n.LocalNode.EncryptionKey = node.GetIPsecKeyIdentity()

	if node.GetExternalIPv4() != nil {
		n.LocalNode.IPAddresses = append(n.LocalNode.IPAddresses, nodeTypes.Address{
			Type: addressing.NodeInternalIP,
			IP:   node.GetExternalIPv4(),
		})
	}

	if node.GetIPv6() != nil {
		n.LocalNode.IPAddresses = append(n.LocalNode.IPAddresses, nodeTypes.Address{
			Type: addressing.NodeInternalIP,
			IP:   node.GetIPv6(),
		})
	}

	if node.GetInternalIPv4() != nil {
		n.LocalNode.IPAddresses = append(n.LocalNode.IPAddresses, nodeTypes.Address{
			Type: addressing.NodeCiliumInternalIP,
			IP:   node.GetInternalIPv4(),
		})
	}

	if node.GetIPv6Router() != nil {
		n.LocalNode.IPAddresses = append(n.LocalNode.IPAddresses, nodeTypes.Address{
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

	if option.Config.KVStore != "" {
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

	if k8s.IsEnabled() {
		// CRD IPAM endpoint restoration depends on the completion of this
		// to avoid custom resource update conflicts.
		n.UpdateCiliumNodeResource()
	}
}

// Close shuts down the node discovery engine
func (n *NodeDiscovery) Close() {
	n.Manager.Close()
}

// UpdateCiliumNodeResource updates the CiliumNode resource representing the
// local node
func (n *NodeDiscovery) UpdateCiliumNodeResource() {
	if !option.Config.AutoCreateCiliumNodeResource {
		return
	}

	ciliumClient := k8s.CiliumClient()

	performUpdate := true
	nodeResource, err := ciliumClient.CiliumV2().CiliumNodes().Get(context.TODO(), nodeTypes.GetName(), metav1.GetOptions{})
	if err != nil {
		performUpdate = false
		nodeResource = &ciliumv2.CiliumNode{
			ObjectMeta: metav1.ObjectMeta{
				Name: nodeTypes.GetName(),
			},
		}
	}

	var (
		providerID       string
		k8sNodeAddresses []nodeTypes.Address
	)

	nodeResource.Spec.Addresses = []ciliumv2.NodeAddress{}

	// Tie the CiliumNode custom resource lifecycle to the lifecycle of the
	// Kubernetes node
	if k8sNode, err := k8s.GetNode(k8s.Client(), nodeTypes.GetName()); err != nil {
		log.WithError(err).Warning("Kubernetes node resource representing own node is not available, cannot set OwnerReference")
	} else {
		nodeResource.ObjectMeta.OwnerReferences = []metav1.OwnerReference{{
			APIVersion: "v1",
			Kind:       "Node",
			Name:       nodeTypes.GetName(),
			UID:        k8sNode.UID,
		}}
		providerID = k8sNode.Spec.ProviderID

		// Get the addresses from k8s node and add them as part of Cilium Node.
		// Cilium Node should contain all addresses from k8s.
		nodeInterface := k8s.ConvertToNode(k8sNode)
		typesNode := nodeInterface.(*k8sTypes.Node)
		k8sNodeParsed := k8s.ParseNode(typesNode, source.Unspec)
		k8sNodeAddresses = k8sNodeParsed.IPAddresses

		for _, k8sAddress := range k8sNodeAddresses {
			k8sAddressStr := k8sAddress.IP.String()
			nodeResource.Spec.Addresses = append(nodeResource.Spec.Addresses, ciliumv2.NodeAddress{
				Type: k8sAddress.Type,
				IP:   k8sAddressStr,
			})
		}
	}

	for _, address := range n.LocalNode.IPAddresses {
		ciliumNodeAddress := address.IP.String()
		var found bool
		for _, nodeResourceAddress := range nodeResource.Spec.Addresses {
			if nodeResourceAddress.IP == ciliumNodeAddress {
				found = true
				break
			}
		}
		if !found {
			nodeResource.Spec.Addresses = append(nodeResource.Spec.Addresses, ciliumv2.NodeAddress{
				Type: address.Type,
				IP:   ciliumNodeAddress,
			})
		}
	}

	switch option.Config.IPAM {
	case ipamOption.IPAMOperator:
		// We want to keep the podCIDRs untouched in this IPAM mode because
		// the operator will verify if it can assign such podCIDRs.
		// If the user was running in non-IPAM Operator mode and then switched
		// to IPAM Operator, then it is possible that the previous cluster CIDR
		// from the old IPAM mode differs from the current cluster CIDR set in
		// the operator.
		// There is a chance that the operator won't be able to allocate these
		// podCIDRs, resulting in an error in the CiliumNode status.
	default:
		nodeResource.Spec.IPAM.PodCIDRs = []string{}
		if cidr := node.GetIPv4AllocRange(); cidr != nil {
			nodeResource.Spec.IPAM.PodCIDRs = append(nodeResource.Spec.IPAM.PodCIDRs, cidr.String())
		}

		if cidr := node.GetIPv6AllocRange(); cidr != nil {
			nodeResource.Spec.IPAM.PodCIDRs = append(nodeResource.Spec.IPAM.PodCIDRs, cidr.String())
		}
	}

	nodeResource.Spec.Encryption.Key = int(node.GetIPsecKeyIdentity())

	nodeResource.Spec.HealthAddressing.IPv4 = ""
	if ip := n.LocalNode.IPv4HealthIP; ip != nil {
		nodeResource.Spec.HealthAddressing.IPv4 = ip.String()
	}

	nodeResource.Spec.HealthAddressing.IPv6 = ""
	if ip := n.LocalNode.IPv6HealthIP; ip != nil {
		nodeResource.Spec.HealthAddressing.IPv6 = ip.String()
	}

	switch option.Config.IPAM {
	case ipamOption.IPAMENI:
		// set ENI field in the node only when the ENI ipam is specified
		nodeResource.Spec.ENI = eniTypes.ENISpec{}
		instanceID, instanceType, availabilityZone, vpcID, err := metadata.GetInstanceMetadata()
		if err != nil {
			log.WithError(err).Fatal("Unable to retrieve InstanceID of own EC2 instance")
		}

		nodeResource.Spec.ENI.VpcID = vpcID
		nodeResource.Spec.ENI.FirstInterfaceIndex = getInt(defaults.ENIFirstInterfaceIndex)

		if c := n.NetConf; c != nil {
			if c.IPAM.MinAllocate != 0 {
				nodeResource.Spec.IPAM.MinAllocate = c.IPAM.MinAllocate
			} else if c.ENI.MinAllocate != 0 {
				nodeResource.Spec.IPAM.MinAllocate = c.ENI.MinAllocate
			}

			if c.IPAM.PreAllocate != 0 {
				nodeResource.Spec.IPAM.PreAllocate = c.IPAM.PreAllocate
			} else if c.ENI.PreAllocate != 0 {
				nodeResource.Spec.IPAM.PreAllocate = c.ENI.PreAllocate
			}

			if c.ENI.FirstInterfaceIndex != nil {
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

		nodeResource.Spec.InstanceID = instanceID
		nodeResource.Spec.ENI.InstanceType = instanceType
		nodeResource.Spec.ENI.AvailabilityZone = availabilityZone

	case ipamOption.IPAMAzure:
		if providerID == "" {
			log.WithError(err).Fatal("Spec.ProviderID in k8s node resource must be set for Azure IPAM")
		}
		if !strings.HasPrefix(providerID, azureTypes.ProviderPrefix) {
			log.WithError(err).Fatalf("Spec.ProviderID in k8s node resource must have prefix %s", azureTypes.ProviderPrefix)
		}
		// The Azure controller in Kubernetes creates a mix of upper
		// and lower case when filling in the ProviderID and is
		// therefore not providing the exact representation of what is
		// returned by the Azure API. Convert it to lower case for
		// consistent results.
		nodeResource.Spec.InstanceID = strings.ToLower(strings.TrimPrefix(providerID, azureTypes.ProviderPrefix))

		if c := n.NetConf; c != nil {
			if c.IPAM.MinAllocate != 0 {
				nodeResource.Spec.IPAM.MinAllocate = c.IPAM.MinAllocate
			}
			if c.IPAM.PreAllocate != 0 {
				nodeResource.Spec.IPAM.PreAllocate = c.IPAM.PreAllocate
			}
			if c.Azure.InterfaceName != "" {
				nodeResource.Spec.Azure.InterfaceName = c.Azure.InterfaceName
			}
		}
	}

	if performUpdate {
		_, err = ciliumClient.CiliumV2().CiliumNodes().Update(context.TODO(), nodeResource, metav1.UpdateOptions{})
		if err != nil {
			log.WithError(err).Fatal("Unable to update CiliumNode resource")
		}
	} else {
		if _, err = ciliumClient.CiliumV2().CiliumNodes().Create(context.TODO(), nodeResource, metav1.CreateOptions{}); err != nil {
			log.WithError(err).Fatal("Unable to create CiliumNode resource")
		} else {
			log.Info("Successfully created CiliumNode resource")
		}
	}
}
