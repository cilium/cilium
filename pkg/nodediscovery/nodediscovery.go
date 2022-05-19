// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodediscovery

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	alibabaCloudTypes "github.com/cilium/cilium/pkg/alibabacloud/eni/types"
	alibabaCloudMetadata "github.com/cilium/cilium/pkg/alibabacloud/metadata"
	"github.com/cilium/cilium/pkg/annotation"
	eniTypes "github.com/cilium/cilium/pkg/aws/eni/types"
	"github.com/cilium/cilium/pkg/aws/metadata"
	azureTypes "github.com/cilium/cilium/pkg/azure/types"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipam"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sTypes "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/lock"
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
)

const (
	// AutoCIDR indicates that a CIDR should be allocated
	AutoCIDR = "auto"

	nodeDiscoverySubsys = "nodediscovery"
	maxRetryCount       = 10
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, nodeDiscoverySubsys)

type k8sNodeGetter interface {
	GetK8sNode(ctx context.Context, nodeName string) (*corev1.Node, error)
}

// The KVStoreNodeUpdater interface is used to provide an abstraction for the
// NodeStore object logic used to update a node entry in the KV store.
type KVStoreNodeUpdater interface {
	UpdateKVNodeEntry(node *nodeTypes.Node) error
}

// NodeDiscovery represents a node discovery action
type NodeDiscovery struct {
	Manager               *nodemanager.Manager
	LocalConfig           datapath.LocalNodeConfiguration
	Registrar             nodestore.NodeRegistrar
	Registered            chan struct{}
	LocalStateInitialized chan struct{}
	NetConf               *cnitypes.NetConf
	k8sNodeGetter         k8sNodeGetter
	localNodeLock         lock.Mutex
	localNode             nodeTypes.Node
}

func enableLocalNodeRoute() bool {
	return option.Config.EnableLocalNodeRoute &&
		option.Config.IPAM != ipamOption.IPAMENI &&
		option.Config.IPAM != ipamOption.IPAMAzure &&
		option.Config.IPAM != ipamOption.IPAMAlibabaCloud
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
		localNode: nodeTypes.Node{
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
		node.SetIPv6NodeRange(resp.IPv6AllocCIDR)
	}
	identity.SetLocalNodeID(resp.NodeIdentity)
}

// start configures the local node and starts node discovery. This is called on
// agent startup to configure the local node based on the configuration options
// passed to the agent. nodeName is the name to be used in the local agent.
func (n *NodeDiscovery) StartDiscovery() {
	n.localNodeLock.Lock()
	defer n.localNodeLock.Unlock()

	n.fillLocalNode()

	go func() {
		log.WithFields(
			logrus.Fields{
				logfields.Node: n.localNode,
			}).Info("Adding local node to cluster")
		for {
			if err := n.Registrar.RegisterNode(&n.localNode, n.Manager); err != nil {
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
		case <-time.After(defaults.NodeInitTimeout):
			log.Fatalf("Unable to initialize local node due to timeout")
		}
	}()

	n.Manager.NodeUpdated(n.localNode)
	close(n.LocalStateInitialized)

	n.updateLocalNode()
}

func (n *NodeDiscovery) fillLocalNode() {
	n.localNode.Name = nodeTypes.GetName()
	n.localNode.Cluster = option.Config.ClusterName
	n.localNode.IPAddresses = []nodeTypes.Address{}
	n.localNode.IPv4AllocCIDR = node.GetIPv4AllocRange()
	n.localNode.IPv6AllocCIDR = node.GetIPv6AllocRange()
	n.localNode.IPv4HealthIP = node.GetEndpointHealthIPv4()
	n.localNode.IPv6HealthIP = node.GetEndpointHealthIPv6()
	n.localNode.ClusterID = option.Config.ClusterID
	n.localNode.EncryptionKey = node.GetIPsecKeyIdentity()
	n.localNode.WireguardPubKey = node.GetWireguardPubKey()
	n.localNode.Labels = node.GetLabels()
	n.localNode.NodeIdentity = uint32(identity.ReservedIdentityHost)

	if node.GetK8sExternalIPv4() != nil {
		n.localNode.IPAddresses = append(n.localNode.IPAddresses, nodeTypes.Address{
			Type: addressing.NodeExternalIP,
			IP:   node.GetK8sExternalIPv4(),
		})
	}

	if node.GetIPv4() != nil {
		n.localNode.IPAddresses = append(n.localNode.IPAddresses, nodeTypes.Address{
			Type: addressing.NodeInternalIP,
			IP:   node.GetIPv4(),
		})
	}

	if node.GetIPv6() != nil {
		n.localNode.IPAddresses = append(n.localNode.IPAddresses, nodeTypes.Address{
			Type: addressing.NodeInternalIP,
			IP:   node.GetIPv6(),
		})
	}

	if node.GetInternalIPv4Router() != nil {
		n.localNode.IPAddresses = append(n.localNode.IPAddresses, nodeTypes.Address{
			Type: addressing.NodeCiliumInternalIP,
			IP:   node.GetInternalIPv4Router(),
		})
	}

	if node.GetIPv6Router() != nil {
		n.localNode.IPAddresses = append(n.localNode.IPAddresses, nodeTypes.Address{
			Type: addressing.NodeCiliumInternalIP,
			IP:   node.GetIPv6Router(),
		})
	}

	if node.GetK8sExternalIPv6() != nil {
		n.localNode.IPAddresses = append(n.localNode.IPAddresses, nodeTypes.Address{
			Type: addressing.NodeExternalIP,
			IP:   node.GetK8sExternalIPv6(),
		})
	}
}

func (n *NodeDiscovery) updateLocalNode() {
	if option.Config.KVStore != "" && !option.Config.JoinCluster {
		go func() {
			<-n.Registered
			controller.NewManager().UpdateController("propagating local node change to kv-store",
				controller.ControllerParams{
					DoFunc: func(ctx context.Context) error {
						err := n.Registrar.UpdateLocalKeySync(&n.localNode)
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

// UpdateLocalNode syncs the internal localNode object with the actual state of
// the local node and publishes the corresponding updated KV store entry and/or
// CiliumNode object
func (n *NodeDiscovery) UpdateLocalNode() {
	n.localNodeLock.Lock()
	defer n.localNodeLock.Unlock()

	n.fillLocalNode()
	n.updateLocalNode()
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

	nodeResource.Spec.Addresses = []ciliumv2.NodeAddress{}

	// If we are unable to fetch the K8s Node resource and the CiliumNode does
	// not have an OwnerReference set, then somehow we are running in an
	// environment where only the CiliumNode exists. Do not proceed as this is
	// unexpected.
	//
	// Note that we can rely on the OwnerReference to be set on the CiliumNode
	// as this was added in sufficiently earlier versions of Cilium (v1.6).
	// Source:
	// https://github.com/cilium/cilium/commit/5c365f2c6d7930dcda0b8f0d5e6b826a64022a4f
	k8sNode, err := n.k8sNodeGetter.GetK8sNode(
		context.TODO(),
		nodeTypes.GetName(),
	)
	switch {
	case err != nil && k8serrors.IsNotFound(err) && len(nodeResource.ObjectMeta.OwnerReferences) == 0:
		log.WithError(err).WithField(
			logfields.NodeName, nodeTypes.GetName(),
		).Fatal(
			"Kubernetes Node resource does not exist, setting OwnerReference on " +
				"CiliumNode is impossible. This is unexpected. Please investigate " +
				"why Cilium is running on a Node that supposedly does not exist " +
				"according to Kubernetes.",
		)
	case err != nil && !k8serrors.IsNotFound(err):
		return fmt.Errorf("failed to fetch Kubernetes Node resource: %w", err)
	}

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

	for _, address := range n.localNode.IPAddresses {
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
	case ipamOption.IPAMClusterPool, ipamOption.IPAMClusterPoolV2:
		// We want to keep the podCIDRs untouched in these IPAM modes because
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
	if ip := n.localNode.IPv4HealthIP; ip != nil {
		nodeResource.Spec.HealthAddressing.IPv4 = ip.String()
	}

	nodeResource.Spec.HealthAddressing.IPv6 = ""
	if ip := n.localNode.IPv6HealthIP; ip != nil {
		nodeResource.Spec.HealthAddressing.IPv6 = ip.String()
	}

	if pk := n.localNode.WireguardPubKey; pk != "" {
		if nodeResource.ObjectMeta.Annotations == nil {
			nodeResource.ObjectMeta.Annotations = make(map[string]string)
		}
		nodeResource.ObjectMeta.Annotations[annotation.WireguardPubKey] = pk
	}

	switch option.Config.IPAM {
	case ipamOption.IPAMClusterPoolV2:
		if c := n.NetConf; c != nil {
			nodeResource.Spec.IPAM.PodCIDRAllocationThreshold = c.IPAM.PodCIDRAllocationThreshold
			nodeResource.Spec.IPAM.PodCIDRReleaseThreshold = c.IPAM.PodCIDRReleaseThreshold
		}
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
		// function (mutateNodeResource()) will be called when the agent is
		// first coming up and is initializing the IPAM layer (CRD allocator in
		// this case). Later on, the Operator will adjust this value based on
		// the PreAllocate value, so to ensure that the agent and the Operator
		// are not conflicting with each other, we must have similar logic to
		// determine the appropriate value to place inside the resource.
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

			if len(c.ENI.SubnetIDs) > 0 {
				nodeResource.Spec.ENI.SubnetIDs = c.ENI.SubnetIDs
			}

			if len(c.ENI.SubnetTags) > 0 {
				nodeResource.Spec.ENI.SubnetTags = c.ENI.SubnetTags
			}

			if c.ENI.VpcID != "" {
				nodeResource.Spec.ENI.VpcID = c.ENI.VpcID
			}

			if len(c.ENI.ExcludeInterfaceTags) > 0 {
				nodeResource.Spec.ENI.ExcludeInterfaceTags = c.ENI.ExcludeInterfaceTags
			}

			nodeResource.Spec.ENI.DeleteOnTermination = c.ENI.DeleteOnTermination
		}

		nodeResource.Spec.InstanceID = instanceID
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

	case ipamOption.IPAMAlibabaCloud:
		nodeResource.Spec.AlibabaCloud = alibabaCloudTypes.Spec{}

		instanceID, err := alibabaCloudMetadata.GetInstanceID(context.TODO())
		if err != nil {
			log.WithError(err).Fatal("Unable to retrieve InstanceID of own ECS instance")
		}

		if instanceID == "" {
			return errors.New("InstanceID of own ECS instance is empty")
		}

		instanceType, err := alibabaCloudMetadata.GetInstanceType(context.TODO())
		if err != nil {
			log.WithError(err).Fatal("Unable to retrieve InstanceType of own ECS instance")
		}
		vpcID, err := alibabaCloudMetadata.GetVPCID(context.TODO())
		if err != nil {
			log.WithError(err).Fatal("Unable to retrieve VPC ID of own ECS instance")
		}
		vpcCidrBlock, err := alibabaCloudMetadata.GetVPCCIDRBlock(context.TODO())
		if err != nil {
			log.WithError(err).Fatal("Unable to retrieve VPC CIDR block of own ECS instance")
		}
		zoneID, err := alibabaCloudMetadata.GetZoneID(context.TODO())
		if err != nil {
			log.WithError(err).Fatal("Unable to retrieve Zone ID of own ECS instance")
		}
		nodeResource.Spec.InstanceID = instanceID
		nodeResource.Spec.AlibabaCloud.InstanceType = instanceType
		nodeResource.Spec.AlibabaCloud.VPCID = vpcID
		nodeResource.Spec.AlibabaCloud.CIDRBlock = vpcCidrBlock
		nodeResource.Spec.AlibabaCloud.AvailabilityZone = zoneID

		if c := n.NetConf; c != nil {
			if c.AlibabaCloud.VPCID != "" {
				nodeResource.Spec.AlibabaCloud.VPCID = c.AlibabaCloud.VPCID
			}
			if c.AlibabaCloud.CIDRBlock != "" {
				nodeResource.Spec.AlibabaCloud.CIDRBlock = c.AlibabaCloud.CIDRBlock
			}

			if len(c.AlibabaCloud.VSwitches) > 0 {
				nodeResource.Spec.AlibabaCloud.VSwitches = c.AlibabaCloud.VSwitches
			}

			if len(c.AlibabaCloud.VSwitchTags) > 0 {
				nodeResource.Spec.AlibabaCloud.VSwitchTags = c.AlibabaCloud.VSwitchTags
			}

			if len(c.AlibabaCloud.SecurityGroups) > 0 {
				nodeResource.Spec.AlibabaCloud.SecurityGroups = c.AlibabaCloud.SecurityGroups
			}

			if len(c.AlibabaCloud.SecurityGroupTags) > 0 {
				nodeResource.Spec.AlibabaCloud.SecurityGroupTags = c.AlibabaCloud.SecurityGroupTags
			}

			if c.IPAM.PreAllocate != 0 {
				nodeResource.Spec.IPAM.PreAllocate = c.IPAM.PreAllocate
			}
		}
	}

	return nil
}

func (n *NodeDiscovery) RegisterK8sNodeGetter(k8sNodeGetter k8sNodeGetter) {
	n.k8sNodeGetter = k8sNodeGetter
}

// LocalAllocCIDRsUpdated informs the agent that the local allocation CIDRs have
// changed. This will inform the datapath node manager to update the local node
// routes accordingly.
// The first CIDR in ipv[46]AllocCIDRs is presumed to be the primary CIDR: This
// CIDR remains assigned to the local node and may not be switched out or be
// removed.
func (n *NodeDiscovery) LocalAllocCIDRsUpdated(ipv4AllocCIDRs, ipv6AllocCIDRs []*cidr.CIDR) {
	n.localNodeLock.Lock()
	defer n.localNodeLock.Unlock()

	if option.Config.EnableIPv4 && len(ipv4AllocCIDRs) > 0 {
		ipv4PrimaryCIDR, ipv4SecondaryCIDRs := splitAllocCIDRs(ipv4AllocCIDRs)
		validatePrimaryCIDR(n.localNode.IPv4AllocCIDR, ipv4PrimaryCIDR, ipam.IPv4)
		n.localNode.IPv4AllocCIDR = ipv4PrimaryCIDR
		n.localNode.IPv4SecondaryAllocCIDRs = ipv4SecondaryCIDRs
	}

	if option.Config.EnableIPv6 && len(ipv6AllocCIDRs) > 0 {
		ipv6PrimaryCIDR, ipv6SecondaryCIDRs := splitAllocCIDRs(ipv6AllocCIDRs)
		validatePrimaryCIDR(n.localNode.IPv6AllocCIDR, ipv6PrimaryCIDR, ipam.IPv6)
		n.localNode.IPv6AllocCIDR = ipv6PrimaryCIDR
		n.localNode.IPv6SecondaryAllocCIDRs = ipv6SecondaryCIDRs
	}

	n.Manager.NodeUpdated(n.localNode)
}

func splitAllocCIDRs(allocCIDRs []*cidr.CIDR) (primaryCIDR *cidr.CIDR, secondaryCIDRS []*cidr.CIDR) {
	secondaryCIDRS = make([]*cidr.CIDR, 0, len(allocCIDRs)-1)
	for i, allocCIDR := range allocCIDRs {
		if i == 0 {
			primaryCIDR = allocCIDR
		} else {
			secondaryCIDRS = append(secondaryCIDRS, allocCIDR)
		}
	}

	return primaryCIDR, secondaryCIDRS
}

func validatePrimaryCIDR(oldCIDR, newCIDR *cidr.CIDR, family ipam.Family) {
	if oldCIDR != nil && !oldCIDR.Equal(newCIDR) {
		newCIDRStr := "<nil>"
		if newCIDR != nil {
			newCIDRStr = newCIDR.String()
		}

		log.WithFields(logrus.Fields{
			logfields.OldCIDR: oldCIDR.String(),
			logfields.NewCIDR: newCIDRStr,
			logfields.Family:  family,
		}).Warn("Detected change of primary pod allocation CIDR. Agent restart required.")
	}
}

func getInt(i int) *int {
	return &i
}

func (nodeDiscovery *NodeDiscovery) UpdateKVNodeEntry(node *nodeTypes.Node) error {
	if nodeDiscovery.Registrar.SharedStore == nil {
		return nil
	}

	if err := nodeDiscovery.Registrar.UpdateLocalKeySync(node); err != nil {
		return fmt.Errorf("failed to update KV node store entry: %w", err)
	}

	if err := nodeDiscovery.mutateNodeResource(node.ToCiliumNode()); err != nil {
		return fmt.Errorf("failed to mutate node resource: %w", err)
	}

	return nil
}
