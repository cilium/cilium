// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package podcidr

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/ipam/allocator/clusterpool/cidralloc"

	"github.com/sirupsen/logrus"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/controller"
	ipPkg "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipam"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/revert"
	"github.com/cilium/cilium/pkg/trigger"
)

type allocatorType string

const (
	v4AllocatorType = "IPv4"
	v6AllocatorType = "IPv6"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "pod-cidr")

// ErrAllocatorNotFound is an error that should be used in case the node tries
// to allocate a CIDR for an allocator that does not exist.
type ErrAllocatorNotFound struct {
	cidr          []*net.IPNet
	allocatorType allocatorType
}

// Error returns the human-readable error for the ErrAllocatorNotFound
func (e *ErrAllocatorNotFound) Error() string {
	cidrStr := ipNetString(e.cidr)
	return fmt.Sprintf("unable to allocate CIDR %s since allocator for %s addresses does not exist", cidrStr, e.allocatorType)
}

// ErrAllocatorFull ...
type ErrAllocatorFull struct{}

// Error returns the human-readable error for the ErrAllocatorFull
func (e *ErrAllocatorFull) Error() string {
	return "allocator full"
}

// ErrCIDRAllocated is an error that should be used when the requested CIDR
// is already allocated.
type ErrCIDRAllocated struct {
	cidr *net.IPNet
}

// Error returns the human-readable error for the ErrAllocatorNotFound
func (e *ErrCIDRAllocated) Error() string {
	return fmt.Sprintf("requested CIDR (%s) is already allocated", e.cidr)
}

// ErrNoAllocators is an error that returned if no allocators are available to
// allocate a CIDR. This can often be a configuration problem.
type ErrNoAllocators struct {
	// name is the name of the node.
	name string
	// v4 and v6 are strings retrieved from getCIDRAllocatorsInfo() for v4 and
	// v6 CIDRs respectively.
	v4, v6 string
}

// Error returns the human-readable error for the ErrNoAllocators.
func (e ErrNoAllocators) Error() string {
	return fmt.Sprintf(
		"Unable to allocate node CIDR for node %s. IPAMInfo: {IPv4: %s, IPv6: %s}. "+
			"Please check that your configuration is correct.",
		e.name,
		e.v4,
		e.v6,
	)
}

// parsePodCIDRs will return the v4 and v6 CIDRs found in the podCIDRs.
// Returns an error in case one of the CIDRs are not valid.
func parsePodCIDRs(podCIDRs []string) (*nodeCIDRs, error) {
	var cidrs nodeCIDRs
	for _, podCIDR := range podCIDRs {
		ip, ipNet, err := net.ParseCIDR(podCIDR)
		if err != nil {
			return nil, err
		}
		if ipPkg.IsIPv4(ip) {
			cidrs.v4PodCIDRs = append(cidrs.v4PodCIDRs, ipNet)
		} else {
			cidrs.v6PodCIDRs = append(cidrs.v6PodCIDRs, ipNet)
		}
	}
	return &cidrs, nil
}

// nodeCIDRs is a wrapper that contains all the podCIDRs a node can have.
type nodeCIDRs struct {
	v4PodCIDRs, v6PodCIDRs []*net.IPNet
}

func ipNetString(ipNets []*net.IPNet) []string {
	cidrs := make([]string, 0, len(ipNets))
	for _, ipNet := range ipNets {
		cidrs = append(cidrs, ipNet.String())
	}
	return cidrs
}

func (s *nodeCIDRs) String() string {
	cidrs := make([]string, 0, len(s.v4PodCIDRs)+len(s.v6PodCIDRs))
	cidrs = append(cidrs, ipNetString(s.v4PodCIDRs)...)
	cidrs = append(cidrs, ipNetString(s.v6PodCIDRs)...)
	return strings.Join(cidrs, ", ")
}

type k8sOp int

const (
	k8sOpCreate k8sOp = iota
	k8sOpDelete
	k8sOpUpdate
	k8sOpUpdateStatus
)

// ciliumNodeK8sOp is a wrapper with the operation that should be performed
// in kubernetes.
type ciliumNodeK8sOp struct {
	ciliumNode *v2.CiliumNode
	op         k8sOp
}

var updateK8sInterval = 15 * time.Second

// NodesPodCIDRManager will be used to manage podCIDRs for the nodes in the
// cluster.
type NodesPodCIDRManager struct {
	k8sReSyncController *controller.Manager
	k8sReSync           *trigger.Trigger

	// Lock protects all fields below
	lock.Mutex
	// canAllocatePodCIDRs is set to true once the NodesPodCIDRManager can allocate
	// podCIDRs for nodes that don't have pod CIDRs allocated to them.
	canAllocatePodCIDRs bool
	// We don't want CiliumNodes that don't have podCIDRs to be
	// allocated with a podCIDR already being used by another node.
	// For this reason we will call Resync after all CiliumNodes are
	// synced with the operator to signalize the node manager, since it
	// knows all podCIDRs that are currently set in the cluster, that
	// it can allocate podCIDRs for the nodes that don't have a podCIDR
	// set. This means that we will keep a map of the nodes that want to receive
	// a podCIDR and once 'canAllocatePodCIDRs' is set to true we will use this
	// map to allocate podCIDRs for the missing nodes.
	nodesToAllocate map[string]*v2.CiliumNode
	// v4CIDRAllocators contains the CIDRs for IPv4 addresses
	v4CIDRAllocators []cidralloc.CIDRAllocator
	// v6CIDRAllocators contains the CIDRs for IPv6 addresses
	v6CIDRAllocators []cidralloc.CIDRAllocator
	// nodes maps a node name to the CIDRs allocated for that node
	nodes map[string]*nodeCIDRs
	// maps a node name to the operation that needs to be performed in
	// kubernetes.
	ciliumNodesToK8s map[string]*ciliumNodeK8sOp
}

// NewNodesPodCIDRManager will create a node podCIDR manager.
// Both v4Allocators and v6Allocators can be nil, but not at the same time.
// nodeGetter will be used to populate synced node status / spec with
// kubernetes.
func NewNodesPodCIDRManager(
	v4Allocators, v6Allocators []cidralloc.CIDRAllocator,
	nodeGetter ipam.CiliumNodeGetterUpdater,
	triggerMetrics trigger.MetricsObserver) *NodesPodCIDRManager {

	n := &NodesPodCIDRManager{
		nodesToAllocate:     map[string]*v2.CiliumNode{},
		v4CIDRAllocators:    v4Allocators,
		v6CIDRAllocators:    v6Allocators,
		nodes:               map[string]*nodeCIDRs{},
		ciliumNodesToK8s:    map[string]*ciliumNodeK8sOp{},
		k8sReSyncController: controller.NewManager(),
	}

	// Have a trigger so that multiple calls, within a second, to sync with k8s
	// will result as it was a single call being made.
	t, err := trigger.NewTrigger(trigger.Parameters{
		MinInterval: time.Second,
		TriggerFunc: func([]string) {
			// Trigger execute UpdateController multiple times so that we
			// keep retrying the sync against k8s in case of failure.
			n.k8sReSyncController.UpdateController("update-cilium-nodes-pod-cidr",
				controller.ControllerParams{
					DoFunc: func(context.Context) error {
						n.Mutex.Lock()
						defer n.Mutex.Unlock()
						return syncToK8s(nodeGetter, n.ciliumNodesToK8s)
					},
					RunInterval: updateK8sInterval,
				},
			)
		},
		MetricsObserver: triggerMetrics,
		Name:            "update-cilium-nodes-pod-cidr",
	})
	if err != nil {
		// None of the parameters set in the NewTrigger are from the user so we
		// can panic here.
		panic(err)
	}

	n.k8sReSync = t

	return n
}

// syncToK8s will sync all nodes present in the ciliumNodesToK8s into kubernetes
// In case any of the nodes failed to be synced with kubernetes the returned
// error is for one of those nodes. Remaining nodes will still be synced with
// kubernetes.
func syncToK8s(nodeGetterUpdater ipam.CiliumNodeGetterUpdater, ciliumNodesToK8s map[string]*ciliumNodeK8sOp) (retErr error) {
	for nodeName, nodeToK8s := range ciliumNodesToK8s {
		var (
			err, err2     error
			newCiliumNode *v2.CiliumNode
			log           = log.WithFields(logrus.Fields{
				"node-name": nodeName,
			})
		)
		switch nodeToK8s.op {
		case k8sOpCreate:
			// Try creating the node
			_, err = nodeGetterUpdater.Create(nodeToK8s.ciliumNode)
		case k8sOpUpdate:
			var updatedNode *v2.CiliumNode
			updatedNode, err = nodeGetterUpdater.Update(nil, nodeToK8s.ciliumNode)
			log.WithError(err).Debug("Updated Node")
			if err != nil {
				if k8sErrors.IsNotFound(err) {
					// In case the node was not found we should not try to re-create
					// it because the operator will receive the delete node event
					// from k8s and will be eventually deleted from the list of
					// nodes that need to be re-synced with k8s.
					err = nil
				}
				break
			}
			// Store the error status so that we can update it with the update
			// status function.
			updatedNode.Status.IPAM.OperatorStatus.Error = nodeToK8s.ciliumNode.Status.IPAM.OperatorStatus.Error
			nodeToK8s.ciliumNode = updatedNode
			fallthrough
		case k8sOpUpdateStatus:
			_, err = nodeGetterUpdater.UpdateStatus(nil, nodeToK8s.ciliumNode)
			log.WithError(err).Debug("UpdatedStatus Node")
			switch {
			case k8sErrors.IsNotFound(err):
				// In case the node was not found we should not try to re-create
				// it because the operator will receive the delete node event
				// from k8s and will be eventually deleted from the list of
				// nodes that need to be re-synced with k8s.
				err = nil
			}
		case k8sOpDelete:
			// There's no reason to handle a delete operation when we've
			// already received the delete event for the resource anyway. We'll
			// fetch it in case it still exists in k8s and warn if we find it.
			_, err = nodeGetterUpdater.Get(nodeName)
			if err != nil && k8sErrors.IsNotFound(err) {
				// This is not an error because we expect the resource to
				// already be deleted from k8s.
				err = nil
			} else {
				log.WithError(err).Warn("Received a CiliumNode delete event, but the resource may not have been deleted (see error).")
			}
		}
		switch {
		// If there was a conflict this function will return an error
		// and we will fetch the latest version of the cilium node
		// so the next time we will need to perform an update.
		case k8sErrors.IsAlreadyExists(err) || k8sErrors.IsConflict(err):
			retErr = err
			newCiliumNode, err2 = nodeGetterUpdater.Get(nodeToK8s.ciliumNode.GetName())
			if err2 == nil {
				newCiliumNode.Spec.IPAM.PodCIDRs = nodeToK8s.ciliumNode.Spec.IPAM.PodCIDRs
				if len(newCiliumNode.OwnerReferences) == 0 {
					newCiliumNode.OwnerReferences = nodeToK8s.ciliumNode.GetOwnerReferences()
				}
				newCiliumNode.Status.IPAM.OperatorStatus.Error = nodeToK8s.ciliumNode.Status.IPAM.OperatorStatus.Error
				nodeToK8s.ciliumNode = newCiliumNode
				ciliumNodesToK8s[nodeName] = nodeToK8s
				if nodeToK8s.op == k8sOpCreate {
					// We only perform an update if we were able to successfully
					// retrieve the node. The operator is listening for cilium node
					// events. In case the node was deleted, which could be a reason
					// for why the Get returned an error, the operator will then
					// remove the cilium node from the allocated nodes.
					nodeToK8s.op = k8sOpUpdate
				}
			}
		case err == nil:
			delete(ciliumNodesToK8s, nodeName)
		default:
			retErr = err
		}
	}
	return
}

// Create will re-allocate the node podCIDRs. In case the node already has
// podCIDRs allocated, the podCIDR allocator will try to allocate those CIDRs
// internally. In case the node does not have any podCIDR set, its allocation
// will only happen once n.Resync has been called at least one time.
// In case the CIDRs were able to be allocated, the CiliumNode will have its
// podCIDRs fields set with the allocated CIDRs.
// In case the CIDRs were unable to be allocated, this function will return
// true and the node will have its status updated into kubernetes with the
// error message by the NodesPodCIDRManager.
func (n *NodesPodCIDRManager) Create(node *v2.CiliumNode) bool {
	return n.Update(node)
}

// Update will re-allocate the node podCIDRs. In case the node already has
// podCIDRs allocated, the podCIDR allocator will try to allocate those CIDRs.
// In case the CIDRs were able to be allocated, the CiliumNode will have its
// podCIDRs fields set with the allocated CIDRs.
// In case the CIDRs were unable to be allocated, this function will return
// true and the node will have its status updated into kubernetes with the
// error message by the NodesPodCIDRManager.
func (n *NodesPodCIDRManager) Update(node *v2.CiliumNode) bool {
	n.Mutex.Lock()
	defer n.Mutex.Unlock()
	return n.update(node)
}

// Needs n.Mutex to be held.
func (n *NodesPodCIDRManager) update(node *v2.CiliumNode) bool {
	var (
		updateStatus, updateSpec bool
		cn                       *v2.CiliumNode
		err                      error
	)
	if option.Config.IPAMMode() == ipamOption.IPAMClusterPoolV2 {
		cn, updateSpec, updateStatus, err = n.allocateNodeV2(node)
		if err != nil {
			return false
		}
	} else {
		// FIXME: This code block falls back to the old behavior of clusterpool,
		// where we only assign one pod CIDR for IPv4 and IPv6. Once v2 becomes
		// fully backwards compatible with v1, we can remove this else block.
		var allocated bool
		cn, allocated, updateStatus, err = n.allocateNode(node)
		if err != nil {
			return false
		}
		// if allocated is false it means that we were unable to allocate
		// a CIDR so we need to update the status of the node into k8s.
		updateStatus = !allocated && updateStatus
		// ClusterPool v1 never updates both the spec and the status
		updateSpec = !updateStatus
	}
	if cn == nil {
		// no-op
		return true
	}
	if updateStatus {
		// the n.syncNode will never fail because it's only adding elements to a
		// map.
		// NodesPodCIDRManager will later on sync the node into k8s by the
		// controller defined, which keeps retrying to create the node in k8s
		// until it succeeds.

		// If the resource version is != "" it means the object already exists
		// in kubernetes so we should perform an update status instead of a create.
		if cn.GetResourceVersion() != "" {
			n.syncNode(k8sOpUpdateStatus, cn)
		} else {
			n.syncNode(k8sOpCreate, cn)
		}
	}
	if updateSpec {
		// If the resource version is != "" it means the object already exists
		// in kubernetes so we should perform an update instead of a create.
		if cn.GetResourceVersion() != "" {
			n.syncNode(k8sOpUpdate, cn)
		} else {
			n.syncNode(k8sOpCreate, cn)
		}
	}
	return true
}

// Delete deletes the node from the allocator and releases the associated
// CIDRs of that node.
func (n *NodesPodCIDRManager) Delete(node *v2.CiliumNode) {
	n.Mutex.Lock()
	defer n.Mutex.Unlock()
	if !n.canAllocatePodCIDRs {
		delete(n.nodesToAllocate, node.Name)
	}

	found := n.releaseIPNets(node.Name)
	if !found {
		return
	}
	// Mark the node to be deleted in k8s.
	n.ciliumNodesToK8s[node.Name] = &ciliumNodeK8sOp{
		op: k8sOpDelete,
	}
	n.k8sReSync.Trigger()
	return
}

// Resync resyncs the nodes with k8s.
func (n *NodesPodCIDRManager) Resync(context.Context, time.Time) {
	n.Mutex.Lock()
	if !n.canAllocatePodCIDRs {
		n.canAllocatePodCIDRs = true
		// Iterate over all nodes that we have kept stored up until Resync
		// is called as now we are allowed to allocate podCIDRs for nodes
		// without any podCIDR.
		for _, cn := range n.nodesToAllocate {
			n.update(cn)
		}
		n.nodesToAllocate = nil
	}
	n.Mutex.Unlock()

	n.k8sReSync.Trigger()
}

// AllocateNode allocates the podCIDRs for the given node. Returns a DeepCopied
// node with the podCIDRs allocated. In case there weren't CIDRs allocated
// the returned node will be nil.
// If allocated returns false, it means an update of CiliumNode Status should
// be performed into kubernetes as an error have happened while trying to
// allocate a CIDR for this node.
// Needs n.Mutex to be held.
func (n *NodesPodCIDRManager) allocateNode(node *v2.CiliumNode) (cn *v2.CiliumNode, allocated, updateStatus bool, err error) {
	var cidrs *nodeCIDRs

	log = log.WithFields(logrus.Fields{
		"node-name": node.Name,
	})

	defer func() {
		// Overwrite err value if we want to update the status of the
		// cilium node into kubernetes.
		if err != nil && updateStatus {
			cn = node.DeepCopy()
			cn.Status.IPAM.OperatorStatus.Error = err.Error()
			err = nil
			allocated = false
		}
	}()

	if len(node.Spec.IPAM.PodCIDRs) == 0 {
		// If we can't allocate podCIDRs for now we should store the node
		// temporarily until n.reSync is called.
		if !n.canAllocatePodCIDRs {
			log.Debug("Postponing CIDR allocation")
			n.nodesToAllocate[node.GetName()] = node
			return nil, false, false, nil
		}

		// Allocate the next free CIDRs
		cidrs, allocated, err = n.allocateNext(node.GetName())
		if err != nil {
			// We want to log this error in cilium node
			updateStatus = true
			return
		}

		log.WithFields(logrus.Fields{
			"cidrs":     cidrs.String(),
			"allocated": allocated,
		}).Debug("Allocated new CIDRs")
	} else {
		cidrs, err = parsePodCIDRs(node.Spec.IPAM.PodCIDRs)
		if err != nil {
			// We want to log this error in cilium node
			updateStatus = true
			return
		}
		// Try to allocate the podCIDRs in the node, if there was a need
		// for new CIDRs to be allocated the allocated returned value will be
		// set to true.
		cidrs, allocated, err = n.reuseIPNets(node.Name, cidrs.v4PodCIDRs, cidrs.v6PodCIDRs)
		if err != nil {
			// We want to log this error in cilium node
			updateStatus = true
			return
		}
		log.WithFields(logrus.Fields{
			"cidrs":                 cidrs.String(),
			"allocated":             allocated,
			"n.canAllocatePodCIDRs": n.canAllocatePodCIDRs,
		}).Debug("Allocated existing CIDRs")
		if !allocated {
			// If we can't allocate podCIDRs for now we should store the node
			// temporarily until n.reSync is called.
			if !n.canAllocatePodCIDRs {
				n.nodesToAllocate[node.GetName()] = node
				return nil, false, false, nil
			}

			// no-op but still update the status to clear out a potential
			// existing error.
			if node.Status.IPAM.OperatorStatus.Error != "" {
				cn = node.DeepCopy()
				cn.Status.IPAM.OperatorStatus.Error = ""
				updateStatus = true
				return cn, false, updateStatus, nil
			}
			return nil, false, updateStatus, nil
		}
	}

	cn = node.DeepCopy()

	cn.Spec.IPAM.PodCIDRs = make([]string, 0, len(cidrs.v4PodCIDRs)+len(cidrs.v6PodCIDRs))

	for _, v4CIDR := range cidrs.v4PodCIDRs {
		cn.Spec.IPAM.PodCIDRs = append(cn.Spec.IPAM.PodCIDRs, v4CIDR.String())
	}
	for _, v6CIDR := range cidrs.v6PodCIDRs {
		cn.Spec.IPAM.PodCIDRs = append(cn.Spec.IPAM.PodCIDRs, v6CIDR.String())
	}

	cn.Status.IPAM.OperatorStatus.Error = ""

	// UpdateStatus is explicitly set to false here because we want to update
	// the entire node, not the status.
	return cn, allocated, false, nil
}

// syncNode adds the given node to the map of nodes that need to be synchronized
// with kubernetes and triggers a new resync.
// Needs n.Mutex to be held.
func (n *NodesPodCIDRManager) syncNode(op k8sOp, ciliumNode *v2.CiliumNode) {
	n.ciliumNodesToK8s[ciliumNode.GetName()] = &ciliumNodeK8sOp{
		ciliumNode: ciliumNode,
		op:         op,
	}
	n.k8sReSync.Trigger()
}

// releaseIPNets release the CIDRs allocated for this node.
// Returns true if the node was found in the allocator, false otherwise.
// Needs n.Mutex to be held.
func (n *NodesPodCIDRManager) releaseIPNets(nodeName string) bool {
	cidrs, ok := n.nodes[nodeName]
	if !ok {
		return false
	}

	delete(n.nodes, nodeName)

	log = log.WithFields(logrus.Fields{
		"node-name": nodeName,
	})

	releaseCIDRs(n.v4CIDRAllocators, cidrs.v4PodCIDRs)
	releaseCIDRs(n.v6CIDRAllocators, cidrs.v6PodCIDRs)

	return true
}

func releaseCIDRs(cidrAllocators []cidralloc.CIDRAllocator, cidrsToRelease []*net.IPNet) {
	if len(cidrAllocators) == 0 {
		return
	}
	for _, ipNet := range cidrsToRelease {
		for _, clusterCIDR := range cidrAllocators {
			if !clusterCIDR.InRange(ipNet) {
				continue
			}
			err := clusterCIDR.Release(ipNet)
			log = log.WithFields(logrus.Fields{
				"cidr": ipNet.String(),
			})
			if err != nil {
				log.WithError(err).Error("failed to release cidr")
				continue
			}
			log.Info("node released cidrs")
			break
		}
	}
}

// reuseIPNets allows the node to allocate new CIDRs.
// The return value 'allocated' is set to false in case none of the CIDRs were
// re-allocated.
// All allocated CIDRs will be returned as 'newNodeCIDRs'.
// In case an error is returned no CIDRs were allocated.
// Needs n.Mutex to be held.
func (n *NodesPodCIDRManager) reuseIPNets(
	nodeName string, v4CIDR, v6CIDR []*net.IPNet,
) (
	newNodeCIDRs *nodeCIDRs, allocated bool, err error,
) {
	log = log.WithFields(logrus.Fields{
		"node-name": nodeName,
	})
	if len(n.v4CIDRAllocators) == 0 && len(v4CIDR) != 0 {
		return nil, false, &ErrAllocatorNotFound{
			cidr:          v4CIDR,
			allocatorType: v4AllocatorType,
		}
	}
	if len(n.v6CIDRAllocators) == 0 && len(v6CIDR) != 0 {
		return nil, false, &ErrAllocatorNotFound{
			cidr:          v6CIDR,
			allocatorType: v6AllocatorType,
		}
	}

	var canAllocateIPv4PodCIDRs, canAllocateIPv6PodCIDRs bool
	oldNodeCIDRs, nodeHasCIDRs := n.nodes[nodeName]
	if nodeHasCIDRs {
		hasV4CIDR := len(oldNodeCIDRs.v4PodCIDRs) != 0
		hasV6CIDR := len(oldNodeCIDRs.v6PodCIDRs) != 0

		// Check if there are allocators set for the requested CIDR to be
		// allocated or if the node is trying to change its podCIDRs
		if hasV4CIDR {
			if len(n.v4CIDRAllocators) == 0 {
				return nil, false, &ErrAllocatorNotFound{
					cidr:          oldNodeCIDRs.v4PodCIDRs,
					allocatorType: v4AllocatorType,
				}
			}
			if !cidr.ContainsAll(oldNodeCIDRs.v4PodCIDRs, v4CIDR) {
				cidrStr := ipNetString(oldNodeCIDRs.v4PodCIDRs)
				err := fmt.Errorf("node has CIDRs allocated (%s) that conflict with requested CIDRs %s", cidrStr, v4CIDR)
				return nil, false, err
			}
		}
		if hasV6CIDR {
			if len(n.v6CIDRAllocators) == 0 {
				return nil, false, &ErrAllocatorNotFound{
					cidr:          oldNodeCIDRs.v6PodCIDRs,
					allocatorType: v6AllocatorType,
				}
			}
			if !cidr.ContainsAll(oldNodeCIDRs.v6PodCIDRs, v6CIDR) {
				cidrStr := ipNetString(oldNodeCIDRs.v6PodCIDRs)
				err := fmt.Errorf("node has CIDRs allocated (%s) that conflict with requested CIDRs %s", cidrStr, v6CIDR)
				return nil, false, err
			}
		}
		// We are only allowed to allocate new CIDRs if the node already has
		// CIDRs in its spec. If it does not have it, the CIDRs will be
		// allocated the next time
		canAllocateIPv4PodCIDRs = !hasV4CIDR && n.canAllocatePodCIDRs
		canAllocateIPv6PodCIDRs = !hasV6CIDR && n.canAllocatePodCIDRs
	} else {
		canAllocateIPv4PodCIDRs = true
		canAllocateIPv6PodCIDRs = true
		oldNodeCIDRs = &nodeCIDRs{}
	}

	var (
		revertStack revert.RevertStack
		revertFunc  revert.RevertFunc
	)

	defer func() {
		// Revert any operation made so far in case any of them failed.
		if err != nil {
			allocated = false
			revertStack.Revert()
		}
	}()

	// The node might want to allocate a new IPv4 podCIDR but it already
	// has a IPv6 podCIDR. We will only allocate new podCIDRs if
	// canAllocateIPv4PodCIDRs is set to true. It's fine that we don't allocate
	// it now since this node will be put into the map of nodes that require
	// to be allocated in the future.
	if canAllocateIPv4PodCIDRs && len(n.v4CIDRAllocators) != 0 {
		if len(v4CIDR) != 0 {
			revertFunc, err = allocateIPNet(v4AllocatorType, n.v4CIDRAllocators, v4CIDR)
		} else {
			// If the node does not have an IP address assigned to it, we need
			// to allocate it because we have allocators available.
			var newv4CIDR *net.IPNet
			revertFunc, newv4CIDR, err = allocateFirstFreeCIDR(n.v4CIDRAllocators)
			v4CIDR = append(v4CIDR, newv4CIDR)
		}
		if err != nil {
			return
		}
		revertStack.Push(revertFunc)
		oldNodeCIDRs.v4PodCIDRs = v4CIDR
		log.Debugf("Allocated v4CIDR %s", v4CIDR)
		allocated = true
	}

	// The node might want to allocate a new IPv6 podCIDR but it already
	// has a IPv4 podCIDR. We will only allocate new podCIDRs if
	// canAllocateIPv6PodCIDRs is set to true. It's fine that we don't allocate
	// it now since this node will be put into the map of nodes that require
	// to be allocated in the future.
	if canAllocateIPv6PodCIDRs && len(n.v6CIDRAllocators) != 0 {
		if len(v6CIDR) != 0 {
			revertFunc, err = allocateIPNet(v6AllocatorType, n.v6CIDRAllocators, v6CIDR)
		} else {
			// If the node does not have an IP address assigned to it, we need
			// to allocate it because we have allocators available.
			var newv6CIDR *net.IPNet
			revertFunc, newv6CIDR, err = allocateFirstFreeCIDR(n.v6CIDRAllocators)
			v6CIDR = append(v6CIDR, newv6CIDR)
		}
		if err != nil {
			return
		}
		revertStack.Push(revertFunc)
		oldNodeCIDRs.v6PodCIDRs = v6CIDR
		log.Debugf("Allocated v6CIDR %s", v6CIDR)
		allocated = true
	}

	// Only add the node to the list of nodes allocated if there wasn't
	// an error allocating the CIDR
	n.nodes[nodeName] = oldNodeCIDRs

	return oldNodeCIDRs, allocated, nil
}

// allocateIPNet allocates the `newCidr` in the cidrSet allocator. If the
// the `newCIDR` is already allocated an error is returned.
// In case the function returns successfully, it's up to the caller to execute
// the revert function provided to revert all state made. If the function
// returns an error the caller of this function can assume no state was
// modified to the given cidrSets.
// allocateIPNet iterates over cidrSet so a mutex must be held when calling
// this function.
func allocateIPNet(allType allocatorType, cidrSets []cidralloc.CIDRAllocator, newCidrs []*net.IPNet) (revertFunc revert.RevertFunc, err error) {
	if len(cidrSets) == 0 {
		// Return an error if the node tries to allocate a CIDR and
		// we don't have a CIDR set for this CIDR type.
		return nil, &ErrAllocatorNotFound{
			cidr:          newCidrs,
			allocatorType: allType,
		}
	}

	var revertStack revert.RevertStack
	defer func() {
		if err != nil {
			// In case of an error revert all operations made up to this point
			revertStack.Revert()
		}
	}()

	// Allocate newCIDR if it is in the range of any of the allocators
	// available. 'err' will keep the error that should be returned at the end
	// of the loop iterations.
	for _, newCIDR := range newCidrs {
		var isAllocated bool
		for _, cidrSet := range cidrSets {
			// Do not even try to allocate if the cidrSet is full or if the
			// newCIDR does not belong to the cidrSet.
			if !cidrSet.InRange(newCIDR) {
				err = fmt.Errorf("allocator not configured for the requested CIDR %s", newCIDR)
				continue
			}
			if cidrSet.IsFull() {
				// We don't allow overlapping CIDRs so this will return
				// immediately.
				err = fmt.Errorf("allocator %s full", cidrSet)
				return nil, err
			}
			isAllocated, err = cidrSet.IsAllocated(newCIDR)
			if err != nil {
				return nil, err
			}
			if isAllocated {
				return nil, &ErrCIDRAllocated{
					cidr: newCIDR,
				}
			}
			// Try to allocate this new CIDR
			err = cidrSet.Occupy(newCIDR)
			if err != nil {
				return nil, err
			}
			revertStack.Push(func() error {
				// In case of a follow up error release this new allocated CIDR.
				return cidrSet.Release(newCIDR)
			})
			break
		}
		// If we were unable to occupy the CIDRs on any allocators then return
		// immediately as one of the CIDR allocators should be have been able
		// to allocate this new CIDR. 'err' is set with the appropriate error.
		if err != nil {
			return
		}
	}

	return revertStack.Revert, nil
}

// allocateNext returns the next v4 and / or v6 CIDR available in the CIDR
// allocator. The CIDRs are only allocated if the respective CIDR allocators
// are available. If the node had a CIDR previously allocated the same CIDR
// allocated to that node is returned.
// The return value 'allocated' is set to false in case none of the CIDRs were
// re-allocated, for example in the case the node had already allocated CIDRs.
// In case an error is returned no CIDRs were allocated.
// Needs n.Mutex to be held.
func (n *NodesPodCIDRManager) allocateNext(nodeName string) (*nodeCIDRs, bool, error) {
	// If this node had already allocated CIDRs then returned the already
	// allocated CIDRs
	if cidrs, ok := n.nodes[nodeName]; ok {
		return cidrs, false, nil
	}

	var (
		err         error
		revertStack revert.RevertStack
		revertFunc  revert.RevertFunc
	)

	defer func() {
		// Revert any operation made so far in case any of them failed.
		if err != nil {
			revertStack.Revert()
		}
	}()

	var (
		cidrs          nodeCIDRs
		v4CIDR, v6CIDR *net.IPNet
	)

	// Only allocate a v4 CIDR if the v4CIDR allocator is available
	if len(n.v4CIDRAllocators) != 0 {
		revertFunc, v4CIDR, err = allocateFirstFreeCIDR(n.v4CIDRAllocators)
		if err != nil {
			return nil, false, err
		}

		log.WithField("CIDR", v4CIDR).Debug("v4 allocated CIDR")
		cidrs.v4PodCIDRs = []*net.IPNet{v4CIDR}

		revertStack.Push(revertFunc)
	}
	if len(n.v6CIDRAllocators) != 0 {
		revertFunc, v6CIDR, err = allocateFirstFreeCIDR(n.v6CIDRAllocators)
		if err != nil {
			return nil, false, err
		}

		log.WithField("CIDR", v6CIDR).Debug("v6 allocated CIDR")
		cidrs.v6PodCIDRs = []*net.IPNet{v6CIDR}

		revertStack.Push(revertFunc)
	}

	if cidrs.v4PodCIDRs == nil && cidrs.v6PodCIDRs == nil {
		return nil, false, ErrNoAllocators{
			name: nodeName,
			v4:   getCIDRAllocatorsInfo(n.v4CIDRAllocators, v4AllocatorType),
			v6:   getCIDRAllocatorsInfo(n.v6CIDRAllocators, v6AllocatorType),
		}
	}

	n.nodes[nodeName] = &cidrs

	return &cidrs, true, nil
}

func getCIDRAllocatorsInfo(cidrAllocators []cidralloc.CIDRAllocator, netTypes string) string {
	var sb strings.Builder
	sb.WriteByte('[')
	for i, cidrAllocator := range cidrAllocators {
		if i > 0 {
			sb.WriteString(", ")
		}
		sb.WriteString(cidrAllocator.String())
	}
	sb.WriteByte(']')
	return sb.String()
}

// allocateFirstFreeCIDR allocates the first CIDR available from the slice of
// cidrAllocators.
func allocateFirstFreeCIDR(cidrAllocators []cidralloc.CIDRAllocator) (revertFunc revert.RevertFunc, cidr *net.IPNet, err error) {
	var (
		firstFreeAllocator *cidralloc.CIDRAllocator
		revertStack        revert.RevertStack
	)
	for _, cidrAllocator := range cidrAllocators {
		// Allocate from the first allocator that still has free CIDRs
		if !cidrAllocator.IsFull() {
			firstFreeAllocator = &cidrAllocator
			break
		}
	}
	if firstFreeAllocator == nil {
		return nil, nil, &ErrAllocatorFull{}
	}
	cidr, err = (*firstFreeAllocator).AllocateNext()
	if err != nil {
		return nil, nil, err
	}
	revertStack.Push(func() error {
		return (*firstFreeAllocator).Release(cidr)
	})
	return revertStack.Revert, cidr, err
}
