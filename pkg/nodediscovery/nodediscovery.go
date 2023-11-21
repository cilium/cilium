// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodediscovery

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	alibabaCloudTypes "github.com/cilium/cilium/pkg/alibabacloud/eni/types"
	alibabaCloudMetadata "github.com/cilium/cilium/pkg/alibabacloud/metadata"
	eniTypes "github.com/cilium/cilium/pkg/aws/eni/types"
	"github.com/cilium/cilium/pkg/aws/metadata"
	azureTypes "github.com/cilium/cilium/pkg/azure/types"
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/controller"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/identity"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/mtu"
	"github.com/cilium/cilium/pkg/node"
	nodemanager "github.com/cilium/cilium/pkg/node/manager"
	nodestore "github.com/cilium/cilium/pkg/node/store"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/stream"
	"github.com/cilium/cilium/pkg/time"
	cnitypes "github.com/cilium/cilium/plugins/cilium-cni/types"
)

const (
	// AutoCIDR indicates that a CIDR should be allocated
	AutoCIDR = "auto"

	nodeDiscoverySubsys = "nodediscovery"
	maxRetryCount       = 10
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, nodeDiscoverySubsys)

	localNodeToKVStoreControllerGroup = controller.NewGroup("local-node-to-kv-store")
)

type k8sGetters interface {
	GetK8sNode(ctx context.Context, nodeName string) (*slim_corev1.Node, error)
	GetCiliumNode(ctx context.Context, nodeName string) (*ciliumv2.CiliumNode, error)
}

type GetNodeAddresses interface {
	GetNodeAddresses() []nodeTypes.Address
}

// NodeDiscovery represents a node discovery action
type NodeDiscovery struct {
	Manager               nodemanager.NodeManager
	LocalConfig           datapath.LocalNodeConfiguration
	Registrar             nodestore.NodeRegistrar
	Registered            chan struct{}
	localStateInitialized chan struct{}
	NetConf               *cnitypes.NetConf
	k8sGetters            k8sGetters
	localNodeStore        *node.LocalNodeStore
	clientset             client.Clientset
	ctrlmgr               *controller.Manager
}

func enableLocalNodeRoute() bool {
	return option.Config.EnableLocalNodeRoute &&
		option.Config.IPAM != ipamOption.IPAMENI &&
		option.Config.IPAM != ipamOption.IPAMAzure &&
		option.Config.IPAM != ipamOption.IPAMAlibabaCloud
}

// NewNodeDiscovery returns a pointer to new node discovery object
func NewNodeDiscovery(manager nodemanager.NodeManager, clientset client.Clientset, lns *node.LocalNodeStore, mtu mtu.MTU, netConf *cnitypes.NetConf) *NodeDiscovery {
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
			MtuConfig:               mtu,
			EnableIPv4:              option.Config.EnableIPv4,
			EnableIPv6:              option.Config.EnableIPv6,
			EnableEncapsulation:     option.Config.TunnelingEnabled(),
			EnableAutoDirectRouting: option.Config.EnableAutoDirectRouting,
			EnableLocalNodeRoute:    enableLocalNodeRoute(),
			AuxiliaryPrefixes:       auxPrefixes,
			EnableIPSec:             option.Config.EnableIPSec,
			EncryptNode:             option.Config.EncryptNode,
			IPv4PodSubnets:          option.Config.IPv4PodSubnets,
			IPv6PodSubnets:          option.Config.IPv6PodSubnets,
		},
		localNodeStore:        lns,
		Registered:            make(chan struct{}),
		localStateInitialized: make(chan struct{}),
		NetConf:               netConf,
		clientset:             clientset,
		ctrlmgr:               controller.NewManager(),
	}
}

// JoinCluster passes the node name to the kvstore and updates the local configuration on response.
// This allows cluster configuration to override local configuration.
// Must be called on agent startup after IPAM is configured, but before the configuration is used.
// nodeName is the name to be used in the local agent.
func (n *NodeDiscovery) JoinCluster(nodeName string) error {
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

	if option.Config.ClusterID != resp.ClusterID {
		return fmt.Errorf("remote ClusterID (%d) does not match the locally configured one (%d)", resp.ClusterID, option.Config.ClusterID)
	}

	if option.Config.ClusterName != resp.Cluster {
		return fmt.Errorf("remote ClusterName (%s) does not match the locally configured one (%s)", resp.Cluster, option.Config.ClusterName)
	}

	node.SetLabels(resp.Labels)
	if resp.IPv4AllocCIDR != nil {
		node.SetIPv4AllocRange(resp.IPv4AllocCIDR)
	}
	if resp.IPv6AllocCIDR != nil {
		node.SetIPv6NodeRange(resp.IPv6AllocCIDR)
	}
	identity.SetLocalNodeID(resp.NodeIdentity)

	return nil
}

// start configures the local node and starts node discovery. This is called on
// agent startup to configure the local node based on the configuration options
// passed to the agent. nodeName is the name to be used in the local agent.
func (n *NodeDiscovery) StartDiscovery() {
	// Start observing local node changes, so that we keep the corresponding CiliumNode
	// and kvstore representations in sync. The first update is performed synchronously
	// so that they are guaranteed to exist when StartDiscovery returns.
	updates := stream.ToChannel(context.Background(),
		// Coalescence events that are emitted almost at the same time, to prevent
		// consecutive updates from triggering multiple CiliumNode/kvstore updates.
		stream.Debounce(n.localNodeStore, 250*time.Millisecond))
	localNode := <-updates

	go func() {
		log.WithFields(
			logrus.Fields{
				logfields.Node: localNode.Name,
			}).Info("Adding local node to cluster")
		for {
			if err := n.Registrar.RegisterNode(&localNode.Node, n.Manager); err != nil {
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

	n.Manager.NodeUpdated(localNode.Node)
	close(n.localStateInitialized)

	n.updateLocalNode(&localNode)

	go func() {
		// Propagate all updates to the CiliumNode and kvstore representations.
		for ln := range updates {
			n.updateLocalNode(&ln)
		}
	}()
}

// WaitForLocalNodeInit blocks until StartDiscovery() has been called.  This is used to block until
// Node's local IP addresses have been allocated, see https://github.com/cilium/cilium/pull/14299
// and https://github.com/cilium/cilium/pull/14670.
func (n *NodeDiscovery) WaitForLocalNodeInit() {
	<-n.localStateInitialized
}

func (n *NodeDiscovery) NodeDeleted(node nodeTypes.Node) {
	n.Manager.NodeDeleted(node)
}

func (n *NodeDiscovery) NodeUpdated(node nodeTypes.Node) {
	n.Manager.NodeUpdated(node)
}

func (n *NodeDiscovery) ClusterSizeDependantInterval(baseInterval time.Duration) time.Duration {
	return n.Manager.ClusterSizeDependantInterval(baseInterval)
}

func (n *NodeDiscovery) updateLocalNode(ln *node.LocalNode) {
	if option.Config.KVStore != "" && !option.Config.JoinCluster {
		n.ctrlmgr.UpdateController(
			"propagating local node change to kv-store",
			controller.ControllerParams{
				Group:                localNodeToKVStoreControllerGroup,
				CancelDoFuncOnUpdate: true,
				DoFunc: func(ctx context.Context) error {
					select {
					case <-n.Registered:
					case <-ctx.Done():
						return nil
					}

					err := n.Registrar.UpdateLocalKeySync(&ln.Node)
					if err != nil {
						log.WithError(err).Error("Unable to propagate local node change to kvstore")
					}
					return err
				},
			})
	}

	if n.clientset.IsEnabled() {
		// CRD IPAM endpoint restoration depends on the completion of this
		// to avoid custom resource update conflicts.
		n.updateCiliumNodeResource(ln)
	}
}

// UpdateCiliumNodeResource updates the CiliumNode resource representing the
// local node. This function can be safely executed only before starting the
// discovery logic through StartDiscovery(), as otherwise possibly racing
// against concurrent updates triggered by the LocalNodeStore observer.
func (n *NodeDiscovery) UpdateCiliumNodeResource() {
	// UpdateCiliumNodeResource is executed by the daemon start hook, and
	// at that point we are guaranteed that the local node has already
	// been initialized, and this Get() operation returns immediately.
	ln, err := n.localNodeStore.Get(context.Background())
	if err != nil {
		log.Fatal("Could not retrieve the local node object")
	}

	n.updateCiliumNodeResource(&ln)
}

func (n *NodeDiscovery) updateCiliumNodeResource(ln *node.LocalNode) {
	if !option.Config.AutoCreateCiliumNodeResource {
		return
	}

	log.WithField(logfields.Node, nodeTypes.GetName()).Info("Creating or updating CiliumNode resource")

	performGet := true
	var nodeResource *ciliumv2.CiliumNode
	for retryCount := 0; retryCount < maxRetryCount; retryCount++ {
		performUpdate := true
		if performGet {
			var err error
			nodeResource, err = n.k8sGetters.GetCiliumNode(context.TODO(), nodeTypes.GetName())
			if err != nil {
				log.WithError(err).Warning("Unable to get node resource")
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

		if err := n.mutateNodeResource(nodeResource, ln); err != nil {
			log.WithError(err).WithField("retryCount", retryCount).Warning("Unable to mutate nodeResource")
			continue
		}

		// if we retry after this point, is due to a conflict. We will do
		// a new GET  to ensure we have the latest information before
		// updating.
		performGet = true
		if performUpdate {
			if _, err := n.clientset.CiliumV2().CiliumNodes().Update(context.TODO(), nodeResource, metav1.UpdateOptions{}); err != nil {
				if k8serrors.IsConflict(err) {
					log.WithError(err).Warn("Unable to update CiliumNode resource, will retry")
					continue
				}
				log.WithError(err).Fatal("Unable to update CiliumNode resource")
			} else {
				return
			}
		} else {
			if _, err := n.clientset.CiliumV2().CiliumNodes().Create(context.TODO(), nodeResource, metav1.CreateOptions{}); err != nil {
				if k8serrors.IsConflict(err) || k8serrors.IsAlreadyExists(err) {
					log.WithError(err).Warn("Unable to create CiliumNode resource, will retry")
					// Backoff before retrying
					time.Sleep(500 * time.Millisecond)
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

func (n *NodeDiscovery) mutateNodeResource(nodeResource *ciliumv2.CiliumNode, ln *node.LocalNode) error {
	var (
		providerID string
	)

	// If we are unable to fetch the K8s Node resource and the CiliumNode does
	// not have an OwnerReference set, then somehow we are running in an
	// environment where only the CiliumNode exists. Do not proceed as this is
	// unexpected.
	//
	// Note that we can rely on the OwnerReference to be set on the CiliumNode
	// as this was added in sufficiently earlier versions of Cilium (v1.6).
	// Source:
	// https://github.com/cilium/cilium/commit/5c365f2c6d7930dcda0b8f0d5e6b826a64022a4f
	slimNode, err := n.k8sGetters.GetK8sNode(
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
		UID:        slimNode.UID,
	}}
	providerID = slimNode.Spec.ProviderID

	nodeResource.ObjectMeta.Labels = ln.Labels
	nodeResource.ObjectMeta.Annotations = ln.Annotations

	nodeResource.Spec.Addresses = []ciliumv2.NodeAddress{}
	for _, address := range ln.IPAddresses {
		ip := address.IP.String()
		nodeResource.Spec.Addresses = append(nodeResource.Spec.Addresses, ciliumv2.NodeAddress{
			Type: address.Type,
			IP:   ip,
		})
	}

	if option.Config.IPAM == ipamOption.IPAMKubernetes {
		// We only want to copy the PodCIDR from the Kubernetes Node resource to
		// the CiliumNode resource in IPAM Kubernetes mode. In other PodCIDR
		// based IPAM modes (such as ClusterPool or MultiPool), the operator
		// will set the PodCIDRs of the CiliumNode and those might be different
		// from the ones assigned by Kubernetes.
		// For non-podCIDR based IPAM modes (e.g. ENI, Azure, AlibabaCloud), there
		// is no such thing as a podCIDR to begin with. In those cases, the
		// IPv4/IPv6AllocRange is auto-generated and otherwise unused, so it does not
		// make sense to copy it into the CiliumNode it either.
		nodeResource.Spec.IPAM.PodCIDRs = []string{}
		if cidr := ln.IPv4AllocCIDR; cidr != nil {
			nodeResource.Spec.IPAM.PodCIDRs = append(nodeResource.Spec.IPAM.PodCIDRs, cidr.String())
		}

		if cidr := ln.IPv6AllocCIDR; cidr != nil {
			nodeResource.Spec.IPAM.PodCIDRs = append(nodeResource.Spec.IPAM.PodCIDRs, cidr.String())
		}
	}

	if option.Config.EnableIPSec || (option.Config.EnableWireguard && option.Config.EncryptNode && !ln.OptOutNodeEncryption) {
		nodeResource.Spec.Encryption.Key = int(ln.EncryptionKey)
	} else {
		nodeResource.Spec.Encryption.Key = 0
	}

	nodeResource.Spec.HealthAddressing.IPv4 = ""
	if ip := ln.IPv4HealthIP; ip != nil {
		nodeResource.Spec.HealthAddressing.IPv4 = ip.String()
	}

	nodeResource.Spec.HealthAddressing.IPv6 = ""
	if ip := ln.IPv6HealthIP; ip != nil {
		nodeResource.Spec.HealthAddressing.IPv6 = ip.String()
	}

	nodeResource.Spec.IngressAddressing.IPV4 = ""
	if ip := ln.IPv4IngressIP; ip != nil {
		nodeResource.Spec.IngressAddressing.IPV4 = ip.String()
	}

	nodeResource.Spec.IngressAddressing.IPV6 = ""
	if ip := ln.IPv6IngressIP; ip != nil {
		nodeResource.Spec.IngressAddressing.IPV6 = ip.String()
	}

	switch option.Config.IPAM {
	case ipamOption.IPAMENI:
		// set ENI field in the node only when the ENI ipam is specified
		nodeResource.Spec.ENI = eniTypes.ENISpec{}
		instanceID, instanceType, availabilityZone, vpcID, subnetID, err := metadata.GetInstanceMetadata()
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
		nodeResource.Spec.ENI.UsePrimaryAddress = getBool(defaults.UseENIPrimaryAddress)
		nodeResource.Spec.ENI.DisablePrefixDelegation = getBool(defaults.ENIDisableNodeLevelPD)

		if c := n.NetConf; c != nil {
			if c.IPAM.MinAllocate != 0 {
				nodeResource.Spec.IPAM.MinAllocate = c.IPAM.MinAllocate
			}

			if c.IPAM.PreAllocate != 0 {
				nodeResource.Spec.IPAM.PreAllocate = c.IPAM.PreAllocate
			}

			if c.ENI.FirstInterfaceIndex != nil {
				nodeResource.Spec.ENI.FirstInterfaceIndex = c.ENI.FirstInterfaceIndex
			}

			if len(c.ENI.SecurityGroups) > 0 {
				nodeResource.Spec.ENI.SecurityGroups = c.ENI.SecurityGroups
			}

			if len(c.ENI.SecurityGroupTags) > 0 {
				nodeResource.Spec.ENI.SecurityGroupTags = c.ENI.SecurityGroupTags
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

			if c.ENI.UsePrimaryAddress != nil {
				nodeResource.Spec.ENI.UsePrimaryAddress = c.ENI.UsePrimaryAddress
			}

			if c.ENI.DisablePrefixDelegation != nil {
				nodeResource.Spec.ENI.DisablePrefixDelegation = c.ENI.DisablePrefixDelegation
			}

			nodeResource.Spec.ENI.DeleteOnTermination = c.ENI.DeleteOnTermination
		}

		nodeResource.Spec.InstanceID = instanceID
		nodeResource.Spec.ENI.InstanceType = instanceType
		nodeResource.Spec.ENI.AvailabilityZone = availabilityZone
		nodeResource.Spec.ENI.NodeSubnetID = subnetID

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

func (n *NodeDiscovery) RegisterK8sGetters(k8sGetters k8sGetters) {
	n.k8sGetters = k8sGetters
}

func getInt(i int) *int {
	return &i
}

func getBool(b bool) *bool {
	return &b
}
