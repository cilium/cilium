// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"go.uber.org/multierr"
	"golang.org/x/sys/unix"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/client"
	"github.com/cilium/cilium/pkg/k8s/watchers/subscriber"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/trigger"
)

const (
	clusterPoolStatusControllerName = "sync-clusterpool-status"
	clusterPoolStatusTriggerName    = "sync-clusterpool-status-trigger"
)

// containsCIDR checks if the outer IPNet contains the inner IPNet
func containsCIDR(outer, inner *net.IPNet) bool {
	outerMask, _ := outer.Mask.Size()
	innerMask, _ := inner.Mask.Size()
	return outerMask <= innerMask && outer.Contains(inner.IP)
}

// cleanupUnreachableRoutes remove all unreachable routes for the given pod CIDR.
// This is only needed if EnableUnreachableRoutes has been set.
func cleanupUnreachableRoutes(podCIDR string) error {
	_, removedCIDR, err := net.ParseCIDR(podCIDR)
	if err != nil {
		return err
	}

	var family int
	switch podCIDRFamily(podCIDR) {
	case IPv4:
		family = netlink.FAMILY_V4
	case IPv6:
		family = netlink.FAMILY_V6
	default:
		return errors.New("unknown pod cidr family")
	}

	routes, err := netlink.RouteListFiltered(family, &netlink.Route{
		Table: unix.RT_TABLE_MAIN,
		Type:  unix.RTN_UNREACHABLE,
	}, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_TYPE)
	if err != nil {
		return fmt.Errorf("failed to fetch unreachable routes: %w", err)
	}

	var deleteErr error
	for _, route := range routes {
		if !containsCIDR(removedCIDR, route.Dst) {
			continue
		}

		err = netlink.RouteDel(&route)
		if err != nil && !errors.Is(err, unix.ESRCH) {
			// We ignore ESRCH, as it means the entry was already deleted
			err = fmt.Errorf("failed to delete unreachable route for %s: %w", route.Dst.String(), err)
			deleteErr = multierr.Append(deleteErr, err)
		}
	}

	return deleteErr
}

func podCIDRFamily(podCIDR string) Family {
	if strings.Contains(podCIDR, ":") {
		return IPv6
	}
	return IPv4
}

type nodeUpdater interface {
	Update(ctx context.Context, ciliumNode *ciliumv2.CiliumNode, opts metav1.UpdateOptions) (*ciliumv2.CiliumNode, error)
	UpdateStatus(ctx context.Context, ciliumNode *ciliumv2.CiliumNode, opts metav1.UpdateOptions) (*ciliumv2.CiliumNode, error)
}

type nodeWatcher interface {
	RegisterCiliumNodeSubscriber(s subscriber.CiliumNode)
}

type crdWatcher struct {
	mutex *lock.Mutex
	conf  Configuration
	owner Owner

	ipv4Pool        *podCIDRPool
	ipv6Pool        *podCIDRPool
	ipv4PoolUpdated *sync.Cond
	ipv6PoolUpdated *sync.Cond

	node *ciliumv2.CiliumNode

	controller  *controller.Manager
	k8sUpdater  *trigger.Trigger
	nodeUpdater nodeUpdater

	finishedRestore bool
}

var crdWatcherInit sync.Once
var sharedCRDWatcher *crdWatcher

func newCRDWatcher(conf Configuration, nodeWatcher nodeWatcher, owner Owner, nodeUpdater nodeUpdater) *crdWatcher {
	k8sController := controller.NewManager()
	k8sUpdater, err := trigger.NewTrigger(trigger.Parameters{
		MinInterval: 15 * time.Second,
		TriggerFunc: func(reasons []string) {
			// this is a no-op before controller is instantiated in restoreFinished
			k8sController.TriggerController(clusterPoolStatusControllerName)
		},
		Name: clusterPoolStatusTriggerName,
	})
	if err != nil {
		log.WithError(err).Fatal("Unable to initialize CiliumNode synchronization trigger")
	}

	mutex := &lock.Mutex{}
	c := &crdWatcher{
		mutex:           mutex,
		owner:           owner,
		conf:            conf,
		ipv4Pool:        nil,
		ipv6Pool:        nil,
		ipv4PoolUpdated: sync.NewCond(mutex),
		ipv6PoolUpdated: sync.NewCond(mutex),
		node:            nil,
		controller:      k8sController,
		k8sUpdater:      k8sUpdater,
		nodeUpdater:     nodeUpdater,
		finishedRestore: false,
	}

	// Subscribe to CiliumNode updates
	nodeWatcher.RegisterCiliumNodeSubscriber(c)
	owner.UpdateCiliumNodeResource()

	return c
}

func (c *crdWatcher) localNodeUpdated(newNode *ciliumv2.CiliumNode) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// initialize pod CIDR pools from existing or new CiliumNode CRD
	if c.node == nil {
		var releasedIPv4PodCIDRs, releasedIPv6PodCIDRs []string
		for podCIDR, s := range newNode.Status.IPAM.PodCIDRs {
			if s.Status == types.PodCIDRStatusReleased {
				switch podCIDRFamily(podCIDR) {
				case IPv4:
					releasedIPv4PodCIDRs = append(releasedIPv4PodCIDRs, podCIDR)
				case IPv6:
					releasedIPv6PodCIDRs = append(releasedIPv6PodCIDRs, podCIDR)
				}
			}
		}

		if c.conf.IPv4Enabled() {
			c.ipv4Pool = newPodCIDRPool(releasedIPv4PodCIDRs)
		}
		if c.conf.IPv6Enabled() {
			c.ipv6Pool = newPodCIDRPool(releasedIPv6PodCIDRs)
		}
	}

	// updatePool requires that the order of pod CIDRs is maintained
	var ipv4PodCIDRs, ipv6PodCIDRs []string
	for _, podCIDR := range newNode.Spec.IPAM.PodCIDRs {
		switch podCIDRFamily(podCIDR) {
		case IPv4:
			ipv4PodCIDRs = append(ipv4PodCIDRs, podCIDR)
		case IPv6:
			ipv6PodCIDRs = append(ipv6PodCIDRs, podCIDR)
		}
	}

	if c.conf.IPv4Enabled() {
		c.ipv4Pool.updatePool(ipv4PodCIDRs)
		c.ipv4PoolUpdated.Broadcast()
	}
	if c.conf.IPv6Enabled() {
		c.ipv6Pool.updatePool(ipv6PodCIDRs)
		c.ipv6PoolUpdated.Broadcast()
	}

	// TODO(gandro): Move this parsing into updatePool
	var (
		ipv4AllocCIDRs = make([]*cidr.CIDR, 0, len(ipv4PodCIDRs))
		ipv6AllocCIDRs = make([]*cidr.CIDR, 0, len(ipv6PodCIDRs))
	)
	if c.conf.IPv4Enabled() {
		for _, podCIDR := range ipv4PodCIDRs {
			if allocCIDR, err := cidr.ParseCIDR(podCIDR); err == nil {
				ipv4AllocCIDRs = append(ipv4AllocCIDRs, allocCIDR)
			}
		}
	}
	if c.conf.IPv6Enabled() {
		for _, podCIDR := range ipv6PodCIDRs {
			if allocCIDR, err := cidr.ParseCIDR(podCIDR); err == nil {
				ipv6AllocCIDRs = append(ipv6AllocCIDRs, allocCIDR)
			}
		}
	}

	// This updates the local node routes
	c.owner.LocalAllocCIDRsUpdated(ipv4AllocCIDRs, ipv6AllocCIDRs)

	c.node = newNode
}

func (c *crdWatcher) OnAddCiliumNode(node *ciliumv2.CiliumNode, swg *lock.StoppableWaitGroup) error {
	if k8s.IsLocalCiliumNode(node) {
		c.localNodeUpdated(node)
	}

	return nil
}

func (c *crdWatcher) OnUpdateCiliumNode(oldNode, newNode *ciliumv2.CiliumNode, swg *lock.StoppableWaitGroup) error {
	if k8s.IsLocalCiliumNode(newNode) {
		c.localNodeUpdated(newNode)
	}

	return nil
}

func (c *crdWatcher) OnDeleteCiliumNode(node *ciliumv2.CiliumNode, swg *lock.StoppableWaitGroup) error {
	if k8s.IsLocalCiliumNode(node) {
		log.WithField(logfields.Node, node).Warning("Local CiliumNode deleted. IPAM will continue on last seen version")
	}

	return nil
}

func (c *crdWatcher) updateCiliumNodeStatus(ctx context.Context) error {
	var ipv4Pool, ipv6Pool *podCIDRPool
	c.mutex.Lock()
	node := c.node.DeepCopy()
	ipv4Pool = c.ipv4Pool
	ipv6Pool = c.ipv6Pool
	c.mutex.Unlock()

	if node == nil {
		return nil // waiting on localNodeUpdated to be invoked first
	}

	allocationThreshold := node.Spec.IPAM.PodCIDRAllocationThreshold
	releaseThreshold := node.Spec.IPAM.PodCIDRReleaseThreshold

	oldStatus := node.Status.IPAM.DeepCopy()
	node.Status.IPAM.PodCIDRs = types.PodCIDRMap{}
	if ipv4Pool != nil {
		for podCIDR, status := range c.ipv4Pool.clusterPoolV2Beta1Status(allocationThreshold, releaseThreshold) {
			node.Status.IPAM.PodCIDRs[podCIDR] = status
		}
	}
	if ipv6Pool != nil {
		for podCIDR, status := range c.ipv6Pool.clusterPoolV2Beta1Status(allocationThreshold, releaseThreshold) {
			node.Status.IPAM.PodCIDRs[podCIDR] = status
		}
	}

	if oldStatus.DeepEqual(&node.Status.IPAM) {
		return nil // no need to update
	}

	_, err := c.nodeUpdater.UpdateStatus(ctx, node, metav1.UpdateOptions{})
	return err
}

// restoreFinished must be called once all endpoints have been restored. This
// ensures that all previously allocated IPs have now been re-allocated and
// therefore the CIRD status can be synced with upstream. If we synced with
// upstream before we finished restoration, we would prematurely release CIDRs.
func (c *crdWatcher) restoreFinished() {
	c.mutex.Lock()
	defer c.mutex.Unlock()
	if c.finishedRestore {
		return
	}

	// creating a new controller will execute DoFunc immediately
	c.controller.UpdateController(clusterPoolStatusControllerName, controller.ControllerParams{
		DoFunc: c.updateCiliumNodeStatus,
	})
	c.finishedRestore = true
}

func (c *crdWatcher) triggerWithReason(reason string) {
	c.k8sUpdater.TriggerWithReason(reason)
}

func (c *crdWatcher) waitForPool(family Family) <-chan *podCIDRPool {
	ch := make(chan *podCIDRPool)
	go func() {
		var pool *podCIDRPool
		c.mutex.Lock()
		switch family {
		case IPv4:
			if c.conf.IPv4Enabled() {
				for c.ipv4Pool == nil || !c.ipv4Pool.hasAvailableIPs() {
					c.ipv4PoolUpdated.Wait()
				}
				pool = c.ipv4Pool
			}
		case IPv6:
			if c.conf.IPv6Enabled() {
				for c.ipv6Pool == nil || !c.ipv6Pool.hasAvailableIPs() {
					c.ipv6PoolUpdated.Wait()
				}
				pool = c.ipv6Pool
			}
		}
		c.mutex.Unlock()
		ch <- pool
	}()
	return ch
}

type clusterPoolAllocator struct {
	pool *podCIDRPool
}

func newClusterPoolAllocator(family Family, conf Configuration, owner Owner, k8sEventReg K8sEventRegister, clientset client.Clientset) Allocator {
	crdWatcherInit.Do(func() {
		nodeClient := clientset.CiliumV2().CiliumNodes()
		sharedCRDWatcher = newCRDWatcher(conf, k8sEventReg, owner, nodeClient)
	})

	var pool *podCIDRPool
	timer, stop := inctimer.New()
	defer stop()
	for pool == nil {
		select {
		case pool = <-sharedCRDWatcher.waitForPool(family):
			if pool == nil {
				log.WithField(logfields.Family, family).Fatal("failed to obtain pod CIDR pool for family")
			}
		case <-timer.After(5 * time.Second):
			log.WithFields(logrus.Fields{
				logfields.HelpMessage: "Check if cilium-operator pod is running and does not have any warnings or error messages.",
				logfields.Family:      family,
			}).Info("Waiting for pod CIDR pool to become available")
		}
	}

	return &clusterPoolAllocator{
		pool: pool,
	}
}

func (c *clusterPoolAllocator) Allocate(ip net.IP, owner string, pool Pool) (*AllocationResult, error) {
	defer sharedCRDWatcher.triggerWithReason("allocation of IP")
	return c.AllocateWithoutSyncUpstream(ip, owner, pool)
}

func (c *clusterPoolAllocator) AllocateWithoutSyncUpstream(ip net.IP, owner string, pool Pool) (*AllocationResult, error) {
	if err := c.pool.allocate(ip); err != nil {
		return nil, err
	}

	return &AllocationResult{IP: ip}, nil
}

func (c *clusterPoolAllocator) AllocateNext(owner string, pool Pool) (*AllocationResult, error) {
	defer sharedCRDWatcher.triggerWithReason("allocation of next IP")
	return c.AllocateNextWithoutSyncUpstream(owner, pool)
}

func (c *clusterPoolAllocator) AllocateNextWithoutSyncUpstream(owner string, pool Pool) (*AllocationResult, error) {
	ip, err := c.pool.allocateNext()
	if err != nil {
		return nil, err
	}

	return &AllocationResult{IP: ip}, nil
}

func (c *clusterPoolAllocator) Release(ip net.IP, pool Pool) error {
	defer sharedCRDWatcher.triggerWithReason("release of IP")
	c.pool.release(ip)
	return nil
}

func (c *clusterPoolAllocator) Dump() (map[string]string, string) {
	ipToOwner, usedIPs, availableIPs, numPodCIDRs, err := c.pool.dump()
	if err != nil {
		return nil, fmt.Sprintf("error: %s", err)
	}

	return ipToOwner, fmt.Sprintf("%d/%d allocated from %d pod CIDRs", usedIPs, availableIPs, numPodCIDRs)
}

func (c *clusterPoolAllocator) RestoreFinished() {
	sharedCRDWatcher.restoreFinished()
}
