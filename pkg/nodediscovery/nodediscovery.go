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
	"errors"
	"strings"
	"time"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/aws/eni/limits"
	eniTypes "github.com/cilium/cilium/pkg/aws/eni/types"
	"github.com/cilium/cilium/pkg/aws/metadata"
	azureTypes "github.com/cilium/cilium/pkg/azure/types"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/identity"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
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

	"github.com/sirupsen/logrus"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// AutoCIDR indicates that a CIDR should be allocated
	AutoCIDR = "auto"

	nodeDiscoverySubsys = "nodediscovery"
	maxRetryCount       = 10
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, nodeDiscoverySubsys)

// NodeDiscovery represents a node discovery action
type NodeDiscovery struct {
	Manager               *nodemanager.Manager
	LocalConfig           datapath.LocalNodeConfiguration
	Registrar             nodestore.NodeRegistrar
	LocalNode             nodeTypes.Node
	Registered            chan struct{}
	LocalStateInitialized chan struct{}
	NetConf               *cnitypes.NetConf
}

func enableLocalNodeRoute() bool {
	return option.Config.EnableLocalNodeRoute &&
		!option.Config.IsFlannelMasterDeviceSet() &&
		option.Config.IPAM != ipamOption.IPAMENI &&
		option.Config.IPAM != ipamOption.IPAMAzure
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
		Registered:            make(chan struct{}),
		LocalStateInitialized: make(chan struct{}),
		NetConf:               netConf,
	}
}

// JoinCluster passes the node name to the kvstore and updates the local configuration on response.
// This allows cluster configuration to override local configuration.
// Must be called on agent startup after IPAM is configured, but before the configuration is used.
// nodeName is the name to be used in the local agent.
func (n *NodeDiscovery) JoinCluster(nodeName string) {
	var resp *nodeTypes.Node
	maxRetryCount := 50
	retryCount := 0
	for retryCount < maxRetryCount {
		log.WithFields(
			logrus.Fields{
				logfields.Node: nodeName,
			}).Info("Joining local node to cluster")

		var err error
		if resp, err = n.Registrar.JoinCluster(nodeName); err != nil || resp == nil {
			if retryCount >= maxRetryCount {
				log.Fatalf("Unable to join cluster")
			}
			retryCount++
			log.WithError(err).Error("Unable to initialize local node. Retrying...")
			time.Sleep(time.Second)
		} else {
			break
		}
	}

	// Override local config based on the response
	option.Config.ClusterID = resp.ClusterID
	option.Config.ClusterName = resp.Cluster
	node.SetLabels(resp.Labels)
	if resp.IPv4AllocCIDR != nil {
		node.SetIPv4AllocRange(resp.IPv4AllocCIDR)
	}
	if resp.IPv6AllocCIDR != nil {
		node.SetIPv6NodeRange(resp.IPv6AllocCIDR.IPNet)
	}
	identity.SetLocalNodeID(resp.NodeIdentity)
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
	n.LocalNode.WireguardPubKey = node.GetWireguardPubKey()
	n.LocalNode.Labels = node.GetLabels()
	n.LocalNode.NodeIdentity = identity.GetLocalNodeID().Uint32()

	if node.GetK8sExternalIPv4() != nil {
		n.LocalNode.IPAddresses = append(n.LocalNode.IPAddresses, nodeTypes.Address{
			Type: addressing.NodeExternalIP,
			IP:   node.GetK8sExternalIPv4(),
		})
	}

	if node.GetIPv4() != nil {
		n.LocalNode.IPAddresses = append(n.LocalNode.IPAddresses, nodeTypes.Address{
			Type: addressing.NodeInternalIP,
			IP:   node.GetIPv4(),
		})
	}

	if node.GetIPv6() != nil {
		n.LocalNode.IPAddresses = append(n.LocalNode.IPAddresses, nodeTypes.Address{
			Type: addressing.NodeInternalIP,
			IP:   node.GetIPv6(),
		})
	}

	if node.GetInternalIPv4Router() != nil {
		n.LocalNode.IPAddresses = append(n.LocalNode.IPAddresses, nodeTypes.Address{
			Type: addressing.NodeCiliumInternalIP,
			IP:   node.GetInternalIPv4Router(),
		})
	}

	if node.GetIPv6Router() != nil {
		n.LocalNode.IPAddresses = append(n.LocalNode.IPAddresses, nodeTypes.Address{
			Type: addressing.NodeCiliumInternalIP,
			IP:   node.GetIPv6Router(),
		})
	}

	if node.GetK8sExternalIPv6() != nil {
		n.LocalNode.IPAddresses = append(n.LocalNode.IPAddresses, nodeTypes.Address{
			Type: addressing.NodeExternalIP,
			IP:   node.GetK8sExternalIPv6(),
		})
	}

	if ip := node.GetWireguardIPv4(); ip != nil {
		n.LocalNode.IPAddresses = append(n.LocalNode.IPAddresses, nodeTypes.Address{
			Type: addressing.NodeWireguardIP,
			IP:   ip,
		})
	}
	if ip := node.GetWireguardIPv6(); ip != nil {
		n.LocalNode.IPAddresses = append(n.LocalNode.IPAddresses, nodeTypes.Address{
			Type: addressing.NodeWireguardIP,
			IP:   ip,
		})
	}

	go func() {
		log.WithFields(
			logrus.Fields{
				logfields.Node: n.LocalNode,
			}).Info("Adding local node to cluster")
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

	n.Manager.NodeUpdated(n.LocalNode)
	close(n.LocalStateInitialized)

	if option.Config.KVStore != "" && !option.Config.JoinCluster {
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

	log.WithField(logfields.Node, nodeTypes.GetName()).Info("Creating or updating CiliumNode resource")

	ciliumClient := k8s.CiliumClient()

	performGet := true
	for retryCount := 0; retryCount < maxRetryCount; retryCount++ {
		var nodeResource *ciliumv2.CiliumNode
		performUpdate := true
		if performGet {
			var err error
			nodeResource, err = ciliumClient.CiliumV2().CiliumNodes().Get(context.TODO(), nodeTypes.GetName(), metav1.GetOptions{})
			if err != nil {
				performUpdate = false
				nodeResource = &ciliumv2.CiliumNode{
					ObjectMeta: metav1.ObjectMeta{
						Name: nodeTypes.GetName(),
					},
				}
			} else {
				performGet = false
			}
		}

		if err := n.mutateNodeResource(nodeResource); err != nil {
			log.WithError(err).WithField("retryCount", retryCount).Warning("Unable to mutate nodeResource")
			continue
		}

		// if we retry after this point, is due to a conflict. We will do
		// a new GET  to ensure we have the latest information before
		// updating.
		performGet = true
		if performUpdate {
			if _, err := ciliumClient.CiliumV2().CiliumNodes().Update(context.TODO(), nodeResource, metav1.UpdateOptions{}); err != nil {
				if k8serrors.IsConflict(err) {
					log.WithError(err).Warn("Unable to update CiliumNode resource, will retry")
					continue
				}
				log.WithError(err).Fatal("Unable to update CiliumNode resource")
			} else {
				return
			}
		} else {
			if _, err := ciliumClient.CiliumV2().CiliumNodes().Create(context.TODO(), nodeResource, metav1.CreateOptions{}); err != nil {
				if k8serrors.IsConflict(err) {
					log.WithError(err).Warn("Unable to create CiliumNode resource, will retry")
					continue
				}
				log.WithError(err).Fatal("Unable to create CiliumNode resource")
			} else {
				log.Info("Successfully created CiliumNode resource")
				return
			}
		}
	}
	log.Fatal("Could not create or update CiliumNode resource, despite retries")
}

func (n *NodeDiscovery) mutateNodeResource(nodeResource *ciliumv2.CiliumNode) error {
	var (
		providerID       string
		k8sNodeAddresses []nodeTypes.Address
	)

	addrs := []ciliumv2.NodeAddress{}
	if option.Config.EnableWireguard {
		// Avoid resetting allocated wireguard IPs in the CiliumNode object once
		// cilium-agent has been restarted and the CiliumNode object is created
		// from scratch.
		for _, addr := range nodeResource.Spec.Addresses {
			if addr.Type == addressing.NodeWireguardIP {
				addrs = append(addrs, addr)
			}
		}
	}
	nodeResource.Spec.Addresses = addrs

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

		nodeResource.ObjectMeta.Labels = k8sNodeParsed.Labels

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
	case ipamOption.IPAMClusterPool:
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

	if pk := n.LocalNode.WireguardPubKey; pk != "" {
		if nodeResource.ObjectMeta.Annotations == nil {
			nodeResource.ObjectMeta.Annotations = make(map[string]string)
		}
		nodeResource.ObjectMeta.Annotations[annotation.WireguardPubKey] = pk
	}

	switch option.Config.IPAM {
	case ipamOption.IPAMENI:
		// set ENI field in the node only when the ENI ipam is specified
		nodeResource.Spec.ENI = eniTypes.ENISpec{}
		instanceID, instanceType, availabilityZone, vpcID, err := metadata.GetInstanceMetadata()
		if err != nil {
			log.WithError(err).Fatal("Unable to retrieve InstanceID of own EC2 instance")
		}

		if instanceID == "" {
			return errors.New("InstanceID of own EC2 instance is empty")
		}

		// It is important to determine the interface index here because this
		// function (mutateNodeResource) will be called when the agent is first
		// coming up and is initializing the IPAM layer (CRD allocator in this
		// case). Later on, the Operator will adjust this value based on the
		// PreAllocate value, so to ensure that the agent and the Operator are
		// not conflicting with each other, we must have similar logic to
		// determine the appropriate value to place inside the resource.
		nodeResource.Spec.ENI.VpcID = vpcID
		nodeResource.Spec.ENI.FirstInterfaceIndex = determineFirstInterfaceIndex(instanceType)

		if c := n.NetConf; c != nil {
			if c.IPAM.MinAllocate != 0 {
				nodeResource.Spec.IPAM.MinAllocate = c.IPAM.MinAllocate
				// OBSOLETE: Left for backwards compatibility with <=1.7. Remove in >=1.11
				nodeResource.Spec.ENI.MinAllocate = c.IPAM.MinAllocate
			} else if c.ENI.MinAllocate != 0 {
				nodeResource.Spec.IPAM.MinAllocate = c.ENI.MinAllocate
				// OBSOLETE: Left for backwards compatibility with <=1.7. Remove in >=1.11
				nodeResource.Spec.ENI.MinAllocate = c.ENI.MinAllocate
			}

			if c.IPAM.PreAllocate != 0 {
				nodeResource.Spec.IPAM.PreAllocate = c.IPAM.PreAllocate
				// OBSOLETE: Left for backwards compatibility with <=1.7. Remove in >=1.11
				nodeResource.Spec.ENI.PreAllocate = c.IPAM.PreAllocate
			} else if c.ENI.PreAllocate != 0 {
				nodeResource.Spec.IPAM.PreAllocate = c.ENI.PreAllocate
				// OBSOLETE: Left for backwards compatibility with <=1.7. Remove in >=1.11
				nodeResource.Spec.ENI.PreAllocate = c.ENI.PreAllocate
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
		// OBSOLETE: Left for backwards compatibility with <=1.7. Remove in >=1.11
		nodeResource.Spec.ENI.InstanceID = instanceID
		nodeResource.Spec.ENI.InstanceType = instanceType
		nodeResource.Spec.ENI.AvailabilityZone = availabilityZone

	case ipamOption.IPAMAzure:
		if providerID == "" {
			log.Fatal("Spec.ProviderID in k8s node resource must be set for Azure IPAM")
		}
		if !strings.HasPrefix(providerID, azureTypes.ProviderPrefix) {
			log.Fatalf("Spec.ProviderID in k8s node resource must have prefix %s", azureTypes.ProviderPrefix)
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

	return nil
}

// determineFirstInterfaceIndex determines the appropriate default interface
// index for the ENI IPAM mode. The interface index is stored inside the
// CiliumNode resource. It specifies which device offset (ENI) to start
// assigning IPs to. It is important to seed the CiliumNode resource with the
// appropriate value, otherwise pods will fail to come up because they won't
// have an IP assigned, because the instance limits (depending on the instance
// type) have a maximum threshold. See
// Documentation/concepts/networking/ipam/eni.rst for more details on this
// value.
//
// This value is also ensured to stay in place using similar logic in
// adjustPreAllocateIfNeeded(), inside
// github.com/cilium/cilium/pkg/ipam.(*Node).syncToAPIServer().
func determineFirstInterfaceIndex(instanceType string) *int {
	if option.Config.IPAM != ipamOption.IPAMENI {
		return nil
	}

	// Fallback to default value if we determine below that the instance limits
	// do not require us to adjust the interface index.
	idx := defaults.ENIFirstInterfaceIndex

	if l, ok := limits.Get(instanceType); ok {
		max := l.Adapters * l.IPv4
		if defaults.IPAMPreAllocation > max {
			idx = 0 // Include eth0
		}
	} else {
		log.WithFields(logrus.Fields{
			"instance-type": instanceType,
		}).Warningf(
			"Unable to find limits for instance type, consider setting --%s=true on the Operator",
			operatorOption.UpdateEC2AdapterLimitViaAPI,
		)
	}

	return &idx
}
