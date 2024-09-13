// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodediscovery

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/cilium/stream"
	"github.com/sirupsen/logrus"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/net"

	"github.com/cilium/cilium/daemon/cmd/cni"
	alibabaCloudTypes "github.com/cilium/cilium/pkg/alibabacloud/eni/types"
	alibabaCloudMetadata "github.com/cilium/cilium/pkg/alibabacloud/metadata"
	eniTypes "github.com/cilium/cilium/pkg/aws/eni/types"
	"github.com/cilium/cilium/pkg/aws/metadata"
	azureTypes "github.com/cilium/cilium/pkg/azure/types"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/identity"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/watchers"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	nodeAddressing "github.com/cilium/cilium/pkg/node/addressing"
	nodemanager "github.com/cilium/cilium/pkg/node/manager"
	nodestore "github.com/cilium/cilium/pkg/node/store"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

const (
	nodeDiscoverySubsys = "nodediscovery"
	maxRetryCount       = 10
	backoffDuration     = 500 * time.Millisecond
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, nodeDiscoverySubsys)

	localNodeToKVStoreControllerGroup = controller.NewGroup("local-node-to-kv-store")
)

type k8sGetters interface {
	GetCiliumNode(ctx context.Context, nodeName string) (*ciliumv2.CiliumNode, error)
}

type GetNodeAddresses interface {
	GetNodeAddresses() []nodeTypes.Address
}

// NodeDiscovery represents a node discovery action
type NodeDiscovery struct {
	Manager               nodemanager.NodeManager
	Registrar             nodestore.NodeRegistrar
	Registered            chan struct{}
	localStateInitialized chan struct{}
	cniConfigManager      cni.CNIConfigManager
	k8sGetters            k8sGetters
	localNodeStore        *node.LocalNodeStore
	clientset             client.Clientset
	ctrlmgr               *controller.Manager
}

// NewNodeDiscovery returns a pointer to new node discovery object
func NewNodeDiscovery(
	manager nodemanager.NodeManager,
	clientset client.Clientset,
	lns *node.LocalNodeStore,
	cniConfigManager cni.CNIConfigManager,
	k8sNodeWatcher *watchers.K8sCiliumNodeWatcher,
) *NodeDiscovery {
	return &NodeDiscovery{
		Manager:               manager,
		localNodeStore:        lns,
		Registered:            make(chan struct{}),
		localStateInitialized: make(chan struct{}),
		cniConfigManager:      cniConfigManager,
		clientset:             clientset,
		ctrlmgr:               controller.NewManager(),
		k8sGetters:            k8sNodeWatcher,
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

	n.localNodeStore.Update(func(ln *node.LocalNode) {
		ln.Labels = maps.Clone(ln.Labels)
		maps.Copy(ln.Labels, resp.Labels)

		if resp.IPv4AllocCIDR != nil {
			ln.IPv4AllocCIDR = resp.IPv4AllocCIDR
		}
		if resp.IPv6AllocCIDR != nil {
			ln.IPv6AllocCIDR = resp.IPv6AllocCIDR
		}

		ln.NodeIdentity = resp.NodeIdentity
	})

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
			// We want to propagate a local node update back into the Manager.
			// This is particularly helpful when an IPSec key rotation occurs
			// and the manager needs to evaluate the local node's EncryptionKey
			// field.
			n.Manager.NodeUpdated(ln.Node)
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
				if retryCount == maxRetryCount {
					log.WithError(err).Warningf("Unable to get CiliumNode resource after %d retries", maxRetryCount)
				}
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
					// Backoff before retrying
					time.Sleep(backoffDuration)
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
					time.Sleep(backoffDuration)
					continue
				}
				log.WithError(err).Fatal("Unable to create CiliumNode resource")
			} else {
				log.Info("Successfully created CiliumNode resource")
				return
			}
		}
	}
	log.Fatalf("Could not create or update CiliumNode resource, despite %d retries", maxRetryCount)
}

func (n *NodeDiscovery) mutateNodeResource(nodeResource *ciliumv2.CiliumNode, ln *node.LocalNode) error {
	nodeResource.ObjectMeta.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: "v1",
		Kind:       "Node",
		Name:       ln.Name,
		UID:        ln.UID,
	}}

	nodeResource.ObjectMeta.Labels = ln.Labels
	nodeResource.ObjectMeta.Annotations = ln.Annotations

	// This function can be called before we have restored the CiliumInternalIP.
	// In that case, we do not want to remove the old CiliumInternalIP, as this
	// would lead to the IP address flapping. Therefore, this code preserves any
	// CiliumInternalIP if (and only if) the local node store does not yet
	// include the restored CiliumInternalIP.
	nodeResource.Spec.Addresses = slices.DeleteFunc(nodeResource.Spec.Addresses, func(address ciliumv2.NodeAddress) bool {
		if address.Type == nodeAddressing.NodeCiliumInternalIP {
			// Only delete a CiliumInternalIP if
			// a) its IP family is disabled,
			// and/or
			// b) the LocalNode store contains an IP address which we can use instead
			switch net.IPFamilyOfString(address.IP) {
			case net.IPv4:
				return !option.Config.EnableIPv4 || ln.GetCiliumInternalIP(false) != nil
			case net.IPv6:
				return !option.Config.EnableIPv6 || ln.GetCiliumInternalIP(true) != nil
			}
		}

		return true // delete all other node addresses
	})

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

	nodeResource.Spec.Encryption.Key = int(ln.EncryptionKey)

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

	nodeResource.Spec.BootID = ln.BootID

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

		if c := n.cniConfigManager.GetCustomNetConf(); c != nil {
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
		if ln.ProviderID == "" {
			log.Fatal("Spec.ProviderID in k8s node resource must be set for Azure IPAM")
		}
		if !strings.HasPrefix(ln.ProviderID, azureTypes.ProviderPrefix) {
			log.Fatalf("Spec.ProviderID in k8s node resource must have prefix %s", azureTypes.ProviderPrefix)
		}
		// The Azure controller in Kubernetes creates a mix of upper
		// and lower case when filling in the ProviderID and is
		// therefore not providing the exact representation of what is
		// returned by the Azure API. Convert it to lower case for
		// consistent results.
		nodeResource.Spec.InstanceID = strings.ToLower(strings.TrimPrefix(ln.ProviderID, azureTypes.ProviderPrefix))

		if c := n.cniConfigManager.GetCustomNetConf(); c != nil {
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

		if c := n.cniConfigManager.GetCustomNetConf(); c != nil {
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

func getInt(i int) *int {
	return &i
}

func getBool(b bool) *bool {
	return &b
}
