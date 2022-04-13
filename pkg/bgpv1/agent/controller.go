// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sLabels "k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	v1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/bgpv1"
	"github.com/cilium/cilium/pkg/k8s"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client/informers/externalversions"
	"github.com/cilium/cilium/pkg/k8s/client/listers/cilium.io/v2alpha1"
	slimlabels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slimmetav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeaddr "github.com/cilium/cilium/pkg/node"
	nodetypes "github.com/cilium/cilium/pkg/node/types"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "bgp-control-plane")
)

var (
	// ErrMultiplePolicies is a static error typed when the controller encounters
	// multiple policies which apply to its host.
	ErrMultiplePolicies = fmt.Errorf("more then one CiliumBGPPeeringPolicy applies to this node, please ensure only a single Policy matches this node's labels")
)

// Signaler multiplexes multiple event sources into a single level-triggered
// event.
//
// Signaler should always be constructed with a channel of size 1.
//
// Use of a Signaler allows for bursts of events to be "rolled-up".
// This is a suitable approach since the Controller checks the entire state of
// the world on each iteration of its control loop.
//
// Additionally, this precludes any need for ordering between different event
// sources.
type Signaler struct {
	Sig chan struct{}
}

// NewSignaler constructs a Signaler
func NewSignaler() Signaler {
	return Signaler{
		Sig: make(chan struct{}, 1),
	}
}

// Event adds an edge triggered event to the Signaler.
//
// A controller which uses this Signaler will be notified of this event some
// time after.
//
// This signature adheres to the common event handling signatures of
// cache.ResourceEventHandlerFuncs for convenience.
func (s Signaler) Event(_ interface{}) {
	select {
	case s.Sig <- struct{}{}:
	default:
	}
}

// ControlPlaneState captures a subset of Cilium's runtime state.
//
// This state carries information interesting to various BGP sub-systems
// and provides a contract for information a sub-system will be provided
// about Cilium's runtime state.
//
// ControlPlaneState should be a point-in-time snapshot of Cilium's runtime
// state and remain read-only to all sub systems its passed to.
type ControlPlaneState struct {
	// The Kubernetes Node resource at time of construction.
	Node *corev1.Node
	// Parsed 'cilium.io/bgp-virtual-router' annotations of the the node this
	// control plane is running on.
	Annotations bgpv1.AnnotationMap
	// The current IPv4 address of the agent, reachable externally.
	IPv4 net.IP
	// The current IPv6 address of the agent, reachable externally.
	IPv6 net.IP
}

// Controller is the agent side BGP Control Plane controller.
//
// Controller listens for events and drives BGP related sub-systems
// to maintain a desired state.
type Controller struct {
	// NOTE: Swap the usage of Node here to CiliumNode
	// once #18609 merges
	//
	// NodeInformer is a shared informer for Node
	// resources
	NodeInformer cache.SharedIndexInformer
	// NodeLister provides cached and indexed lookups for
	// Node API objects.
	NodeLister v1.NodeLister
	// BGPPolicyInformer is a shared informer for CiliumBGPPeerinPolicy
	BGPPolicyInformer cache.SharedIndexInformer
	// PolicyLister provides cached and indexed lookups of
	// for CilumBGPPeeringPolicy API objects.
	PolicyLister v2alpha1.CiliumBGPPeeringPolicyLister
	// Sig informs the Controller that a Kubernetes
	// event of interest has occurred.
	//
	// The signal itself provides no other information,
	// when it occurs the Controller will query each
	// informer for the latest API information required
	// to drive it's control loop.
	Sig Signaler
	// BGPMgr is an implementation of the BGPRouterManager interface
	// and provides a declarative API for configuring BGP peers.
	BGPMgr BGPRouterManager
}

// ControllerOpt is a signature for defining configurable options for a
// Controller
type ControllerOpt func(*Controller)

// NewController constructs a new BGP Control Plane Controller.
//
// When the constructor returns the Controller will be actively watching for
// events and configuring BGP related sub-systems.
//
// The constructor requires an implementation of BGPRouterManager to be provided.
// This implementation defines which BGP backend will be used (GoBGP, FRR, Bird, etc...)
// NOTE: only GoBGP currently implemented.
//
// Cancel the provided CTX to stop the Controller.
func NewController(ctx context.Context, rtMgr BGPRouterManager, opts ...ControllerOpt) (*Controller, error) {
	// create the signaler we will use
	sig := NewSignaler()

	// informers setup
	clientset := k8s.CiliumClient()
	factory := externalversions.NewSharedInformerFactory(clientset, 0)

	selfTweakList := informers.WithTweakListOptions(func(lo *metav1.ListOptions) {
		lo.FieldSelector = "metadata.name=" + nodetypes.GetName()
	})
	k8sfactory := informers.NewSharedInformerFactoryWithOptions(k8s.Client(), 0, selfTweakList)

	nodeLister := k8sfactory.Core().V1().Nodes().Lister()
	nodeInformer := k8sfactory.Core().V1().Nodes().Informer()
	nodeInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    sig.Event,
		UpdateFunc: func(_ interface{}, _ interface{}) { sig.Event(struct{}{}) },
		DeleteFunc: sig.Event,
	})

	policyLister := factory.Cilium().V2alpha1().CiliumBGPPeeringPolicies().Lister()
	policyInformer := factory.Cilium().V2alpha1().CiliumBGPPeeringPolicies().Informer()
	policyInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    sig.Event,
		UpdateFunc: func(_ interface{}, _ interface{}) { sig.Event(struct{}{}) },
		DeleteFunc: sig.Event,
	})

	c := Controller{
		Sig:               sig,
		NodeInformer:      nodeInformer,
		NodeLister:        nodeLister,
		BGPPolicyInformer: policyInformer,
		PolicyLister:      policyLister,
		BGPMgr:            rtMgr,
	}

	// apply any options.
	for _, opt := range opts {
		opt(&c)
	}

	go c.Run(ctx)
	return &c, nil
}

// Run places the Controller into its control loop.
//
// Kubernetes shared informers are started just before entering the long running
// loop.
//
// When new events trigger a signal the control loop will be evaluated.
//
// A cancel of the provided ctx will kill the control loop along with the running
// informers.
func (c *Controller) Run(ctx context.Context) {
	var (
		l = log.WithFields(logrus.Fields{
			"component": "Controller.Run",
		})
	)
	l.Debug("Starting informers")

	// add an initial signal to kick things off
	c.Sig.Event(struct{}{})

	stop := make(chan struct{})
	go c.NodeInformer.Run(stop)
	go c.BGPPolicyInformer.Run(stop)

	l.Info("Cilium BGP Control Plane Controller now running...")
	for {
		select {
		case <-ctx.Done():
			killCTX, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
			defer cancel()

			close(stop)               // kills the informers
			c.FullWithdrawal(killCTX) // kill any BGP sessions

			l.Info("Cilium BGP Control Plane Controller shut down")
			return
		case <-c.Sig.Sig:
			l.Info("Cilium BGP Control Plane Controller woken for reconciliation")
			if err := c.Reconcile(ctx); err != nil {
				l.WithError(err).Error("Encountered error during reconciliation")
			} else {
				l.Debug("Successfully completed reconciliation")
			}
		}
	}
}

// PolicySelection returns a CiliumBGPPeeringPolicy which applies to the provided
// *corev1.Node, enforced by a set of policy selection rules.
//
// Policy selection follows the following rules:
// - A policy matches a node if said policy's "nodeSelector" field matches
//   the node's
// - If (N > 1) policies match the provided *corev1.Node an error is returned.
//   only a single policy may apply to a node to avoid ambiguity at this stage
//   of development.
func PolicySelection(ctx context.Context, node *corev1.Node, policies []*v2alpha1api.CiliumBGPPeeringPolicy) (*v2alpha1api.CiliumBGPPeeringPolicy, error) {
	var (
		l = log.WithFields(logrus.Fields{
			"component": "PolicySelection",
		})
	)
	// determine which policies match our node's labels.
	var (
		selected   *v2alpha1api.CiliumBGPPeeringPolicy
		slimLabels = slimlabels.Set(node.Labels)
	)

	// range over policies and see if any match this node's labels.
	//
	// for now, only a single BGP policy can be applied to a node. if more then
	// one policy applies to a node, we disconnect from all BGP peers and log
	// an error.
	for _, policy := range policies {
		nodeSelector, err := slimmetav1.LabelSelectorAsSelector(policy.Spec.NodeSelector)
		if err != nil {
			l.WithError(err).Error("Failed to convert CiliumBGPPeeringPolicy's NodeSelector to a label.Selector interface")
		}
		l.WithFields(logrus.Fields{
			"policyNodeSelector": nodeSelector.String(),
			"nodeLabels":         slimLabels,
		}).Debug("Comparing BGP policy node selector with node's labels")
		if nodeSelector.Matches(slimLabels) {
			if selected != nil {
				return nil, ErrMultiplePolicies
			}
			selected = policy
		}
	}

	// no policy was discovered, tell router manager to withdrawal peers if they
	// are configured.
	return selected, nil
}

// Reconcile is the control loop for the Controller.
//
// Reconcile will be invoked when one or more event sources trigger a signal
// via the Controller's Signaler structure.
//
// On signal, Reconcile will obtain the state of the world necessary to drive
// the BGP control plane toward any new BGP peering policies.
//
// Reconcile will only allow a single CiliumBGPPeeringPolicy to apply to the
// node its running on.
func (c *Controller) Reconcile(ctx context.Context) error {
	var (
		l = log.WithFields(logrus.Fields{
			"component": "Controller.Reconcile",
		})
		nodeName = nodetypes.GetName()
	)

	// retrieve Node structure.
	node, err := c.NodeLister.Get(nodeName)
	if err != nil {
		return fmt.Errorf("failed to list Node with name %s: %v", nodeName, err)
	}
	if node == nil {
		return fmt.Errorf("list for Node with %s returned nil", nodeName)
	}
	l.WithFields(logrus.Fields{"Labels": node.Labels, "Name": node.Name}).Debug("Successfully listed Node")

	// retrieve all CiliumBGPPeeringPolicies
	policies, err := c.PolicyLister.List(k8sLabels.NewSelector())
	if err != nil {
		return fmt.Errorf("failed to list CiliumBGPPeeringPolicies")
	}
	l.WithField("count", len(policies)).Debug("Successfully listed CiliumBGPPeeringPolicies")

	// perform policy selection based on node.
	policy, err := PolicySelection(ctx, node, policies)
	if err != nil {
		l.WithError(err).Error("Policy selection failed")
		c.FullWithdrawal(ctx)
		return err
	}
	if policy == nil {
		// no policy was discovered, tell router manager to withdrawal peers if
		// they are configured.
		l.Debug("No BGP peering policy applies to this node, any existing BGP sessions will be removed.")
		c.FullWithdrawal(ctx)
		return nil
	}

	// parse any virtual router specific attributes defined on this node via
	// kubernetes annotations
	//
	// if we notice one or more malformed annotations report the errors up and
	// fail reconciliation.
	annoMap, err := bgpv1.NewAnnotationMap(node)
	if err != nil {
		return fmt.Errorf("failed to parse annotations: %w", err)
	}

	// define our current point-in-time control plane state.
	state := &ControlPlaneState{
		Node:        node,
		Annotations: annoMap,
		IPv4:        nodeaddr.GetIPv4(),
		IPv6:        nodeaddr.GetIPv6(),
	}

	// call bgp sub-systems required to apply this policy's BGP topology.
	l.Debug("Asking configured BGPRouterManager to configure peering")
	if err := c.BGPMgr.ConfigurePeers(ctx, policy, state); err != nil {
		return fmt.Errorf("failed to configure BGP peers, cannot apply BGP peering policy: %w", err)
	}

	return nil
}

// FullWithdrawal will instruct the configured BGPRouterManager to withdraw all
// BGP servers and peers.
func (c *Controller) FullWithdrawal(ctx context.Context) {
	_ = c.BGPMgr.ConfigurePeers(ctx, nil, nil) // cannot fail, no need for error handling
}
