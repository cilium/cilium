/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ipam

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/golang/glog"

	"k8s.io/api/core/v1"
	informers "k8s.io/client-go/informers/core/v1"
	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/kubernetes/pkg/cloudprovider"
	"k8s.io/kubernetes/pkg/cloudprovider/providers/gce"
	"k8s.io/kubernetes/pkg/controller/node/ipam/cidrset"
	nodesync "k8s.io/kubernetes/pkg/controller/node/ipam/sync"
	"k8s.io/kubernetes/pkg/controller/node/util"
)

// Config for the IPAM controller.
type Config struct {
	// Resync is the default timeout duration when there are no errors.
	Resync time.Duration
	// MaxBackoff is the maximum timeout when in a error backoff state.
	MaxBackoff time.Duration
	// InitialRetry is the initial retry interval when an error is reported.
	InitialRetry time.Duration
	// Mode to use to synchronize.
	Mode nodesync.NodeSyncMode
}

// Controller is the controller for synchronizing cluster and cloud node
// pod CIDR range assignments.
type Controller struct {
	config  *Config
	adapter *adapter

	lock    sync.Mutex
	syncers map[string]*nodesync.NodeSync

	set *cidrset.CidrSet
}

// NewController returns a new instance of the IPAM controller.
func NewController(
	config *Config,
	kubeClient clientset.Interface,
	cloud cloudprovider.Interface,
	clusterCIDR, serviceCIDR *net.IPNet,
	nodeCIDRMaskSize int) (*Controller, error) {

	if !nodesync.IsValidMode(config.Mode) {
		return nil, fmt.Errorf("invalid IPAM controller mode %q", config.Mode)
	}

	gceCloud, ok := cloud.(*gce.GCECloud)
	if !ok {
		return nil, fmt.Errorf("cloud IPAM controller does not support %q provider", cloud.ProviderName())
	}

	c := &Controller{
		config:  config,
		adapter: newAdapter(kubeClient, gceCloud),
		syncers: make(map[string]*nodesync.NodeSync),
		set:     cidrset.NewCIDRSet(clusterCIDR, nodeCIDRMaskSize),
	}

	if err := occupyServiceCIDR(c.set, clusterCIDR, serviceCIDR); err != nil {
		return nil, err
	}

	return c, nil
}

// Start initializes the Controller with the existing list of nodes and
// registers the informers for node chnages. This will start synchronization
// of the node and cloud CIDR range allocations.
func (c *Controller) Start(nodeInformer informers.NodeInformer) error {
	glog.V(0).Infof("Starting IPAM controller (config=%+v)", c.config)

	nodes, err := listNodes(c.adapter.k8s)
	if err != nil {
		return err
	}
	for _, node := range nodes.Items {
		if node.Spec.PodCIDR != "" {
			_, cidrRange, err := net.ParseCIDR(node.Spec.PodCIDR)
			if err == nil {
				c.set.Occupy(cidrRange)
				glog.V(3).Infof("Occupying CIDR for node %q (%v)", node.Name, node.Spec.PodCIDR)
			} else {
				glog.Errorf("Node %q has an invalid CIDR (%q): %v", node.Name, node.Spec.PodCIDR, err)
			}
		}

		func() {
			c.lock.Lock()
			defer c.lock.Unlock()

			// XXX/bowei -- stagger the start of each sync cycle.
			syncer := c.newSyncer(node.Name)
			c.syncers[node.Name] = syncer
			go syncer.Loop(nil)
		}()
	}

	nodeInformer.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    util.CreateAddNodeHandler(c.onAdd),
		UpdateFunc: util.CreateUpdateNodeHandler(c.onUpdate),
		DeleteFunc: util.CreateDeleteNodeHandler(c.onDelete),
	})

	return nil
}

// occupyServiceCIDR removes the service CIDR range from the cluster CIDR if it
// intersects.
func occupyServiceCIDR(set *cidrset.CidrSet, clusterCIDR, serviceCIDR *net.IPNet) error {
	if clusterCIDR.Contains(serviceCIDR.IP) || serviceCIDR.Contains(clusterCIDR.IP) {
		if err := set.Occupy(serviceCIDR); err != nil {
			return err
		}
	}
	return nil
}

type nodeState struct {
	t Timeout
}

func (ns *nodeState) ReportResult(err error) {
	ns.t.Update(err == nil)
}

func (ns *nodeState) ResyncTimeout() time.Duration {
	return ns.t.Next()
}

func (c *Controller) newSyncer(name string) *nodesync.NodeSync {
	ns := &nodeState{
		Timeout{
			Resync:       c.config.Resync,
			MaxBackoff:   c.config.MaxBackoff,
			InitialRetry: c.config.InitialRetry,
		},
	}
	return nodesync.New(ns, c.adapter, c.adapter, c.config.Mode, name, c.set)
}

func (c *Controller) onAdd(node *v1.Node) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	if syncer, ok := c.syncers[node.Name]; !ok {
		syncer = c.newSyncer(node.Name)
		c.syncers[node.Name] = syncer
		go syncer.Loop(nil)
	} else {
		glog.Warningf("Add for node %q that already exists", node.Name)
		syncer.Update(node)
	}

	return nil
}

func (c *Controller) onUpdate(_, node *v1.Node) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	if sync, ok := c.syncers[node.Name]; ok {
		sync.Update(node)
	} else {
		glog.Errorf("Received update for non-existant node %q", node.Name)
		return fmt.Errorf("unknown node %q", node.Name)
	}

	return nil
}

func (c *Controller) onDelete(node *v1.Node) error {
	c.lock.Lock()
	defer c.lock.Unlock()

	if syncer, ok := c.syncers[node.Name]; ok {
		syncer.Delete(node)
		delete(c.syncers, node.Name)
	} else {
		glog.Warning("Node %q was already deleted", node.Name)
	}

	return nil
}
