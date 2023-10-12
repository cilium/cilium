// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/cilium/workerpool"

	daemon_k8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/bgpv1/agent/signaler"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	v2_api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slimlabels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slimmetav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "bgp-control-plane")
)

var (
	// ErrMultiplePolicies is a static error typed when the controller encounters
	// multiple policies which apply to its host.
	ErrMultiplePolicies = fmt.Errorf("more then one CiliumBGPPeeringPolicy applies to this node, please ensure only a single Policy matches this node's labels")
)

type policyLister interface {
	List() ([]*v2alpha1api.CiliumBGPPeeringPolicy, error)
}

type policyListerFunc func() ([]*v2alpha1api.CiliumBGPPeeringPolicy, error)

func (plf policyListerFunc) List() ([]*v2alpha1api.CiliumBGPPeeringPolicy, error) {
	return plf()
}

// Controller is the agent side BGP Control Plane controller.
//
// Controller listens for events and drives BGP related sub-systems
// to maintain a desired state.
type Controller struct {
	LocalNodeStore *node.LocalNodeStore
	// CiliumNodeResource provides a stream of events for changes to the local CiliumNode resource.
	CiliumNodeResource daemon_k8s.LocalCiliumNodeResource
	// LocalCiliumNode is the CiliumNode object for the local node.
	LocalCiliumNode *v2_api.CiliumNode
	// PolicyResource provides a store of cached policies and allows us to observe changes to the objects in its
	// store.
	PolicyResource resource.Resource[*v2alpha1api.CiliumBGPPeeringPolicy]
	// PolicyLister is an interface which allows for the listing of all known policies
	PolicyLister policyLister

	// Sig informs the Controller that a Kubernetes
	// event of interest has occurred.
	//
	// The signal itself provides no other information,
	// when it occurs the Controller will query each
	// informer for the latest API information required
	// to drive it's control loop.
	Sig *signaler.BGPCPSignaler
	// BGPMgr is an implementation of the BGPRouterManager interface
	// and provides a declarative API for configuring BGP peers.
	BGPMgr BGPRouterManager

	workerpool *workerpool.WorkerPool
}

// ControllerParams contains all parameters needed to construct a Controller
type ControllerParams struct {
	cell.In

	Lifecycle               hive.Lifecycle
	Shutdowner              hive.Shutdowner
	Sig                     *signaler.BGPCPSignaler
	RouteMgr                BGPRouterManager
	PolicyResource          resource.Resource[*v2alpha1api.CiliumBGPPeeringPolicy]
	DaemonConfig            *option.DaemonConfig
	LocalCiliumNodeResource daemon_k8s.LocalCiliumNodeResource
	LocalNodeStore          *node.LocalNodeStore
}

// NewController constructs a new BGP Control Plane Controller.
//
// When the constructor returns the Controller will be actively watching for
// events and configuring BGP related sub-systems.
//
// The constructor requires an implementation of BGPRouterManager to be provided.
// This implementation defines which BGP backend will be used (GoBGP, FRR, Bird, etc...)
// NOTE: only GoBGP currently implemented.
func NewController(params ControllerParams) (*Controller, error) {
	// If the BGP control plane is disabled, just return nil. This way the hive dependency graph is always static
	// regardless of config. The lifecycle has not been appended so no work will be done.
	if !params.DaemonConfig.BGPControlPlaneEnabled() {
		return nil, nil
	}

	c := Controller{
		Sig:                params.Sig,
		BGPMgr:             params.RouteMgr,
		PolicyResource:     params.PolicyResource,
		LocalNodeStore:     params.LocalNodeStore,
		CiliumNodeResource: params.LocalCiliumNodeResource,
	}

	params.Lifecycle.Append(&c)

	return &c, nil
}

// Start is called by hive after all of our dependencies have been started.
func (c *Controller) Start(startCtx hive.HookContext) error {
	policyStore, err := c.PolicyResource.Store(startCtx)
	if err != nil {
		return fmt.Errorf("PolicyResource.Store(): %w", err)
	}
	c.PolicyLister = policyListerFunc(func() ([]*v2alpha1api.CiliumBGPPeeringPolicy, error) {
		return policyStore.List(), nil
	})

	c.workerpool = workerpool.New(3)

	c.workerpool.Submit("policy-observer", func(ctx context.Context) error {
		for ev := range c.PolicyResource.Events(ctx) {
			switch ev.Kind {
			case resource.Upsert, resource.Delete:
				// Signal the reconciliation logic.
				c.Sig.Event(struct{}{})
			}
			ev.Done(nil)
		}
		return nil
	})

	c.workerpool.Submit("cilium-node-observer", func(ctx context.Context) error {
		for ev := range c.CiliumNodeResource.Events(ctx) {
			switch ev.Kind {
			case resource.Upsert:
				// Set the local CiliumNode.
				c.LocalCiliumNode = ev.Object
				// Signal the reconciliation logic.
				c.Sig.Event(struct{}{})
			}
			ev.Done(nil)
		}
		return nil
	})

	c.workerpool.Submit("controller", func(ctx context.Context) error {
		c.Run(ctx)
		return nil
	})

	return nil
}

// Stop is called by hive upon shutdown, after all of our dependants have been stopped.
// We should perform a graceful shutdown and return as soon as done or when the stop context is done.
func (c *Controller) Stop(ctx hive.HookContext) error {
	doneChan := make(chan struct{})
	go func() {
		c.workerpool.Close()
		close(doneChan)
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-doneChan:
	}

	return nil
}

// Run places the Controller into its control loop.
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
	l.Info("Starting LocalNodeStore Observer")

	// setup a reconciliation trigger on LocalNodeStore changes
	c.LocalNodeStore.Observe(ctx, func(node node.LocalNode) { c.Sig.Event(struct{}{}) }, func(err error) {
		l.WithError(err).Info("LocalNodeStore observe has yielded. Reconciliation will no longer be triggered for LocalNode changes")
	})

	// add an initial signal to kick things off
	c.Sig.Event(struct{}{})

	l.Info("Cilium BGP Control Plane Controller now running...")
	for {
		select {
		case <-ctx.Done():
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
//   - A policy matches a node if said policy's "nodeSelector" field matches
//     the node's labels. If "nodeSelector" is omitted, it is unconditionally
//     selected.
//   - If (N > 1) policies match the provided *corev1.Node an error is returned.
//     only a single policy may apply to a node to avoid ambiguity at this stage
//     of development.
func PolicySelection(ctx context.Context, labels map[string]string, policies []*v2alpha1api.CiliumBGPPeeringPolicy) (*v2alpha1api.CiliumBGPPeeringPolicy, error) {
	var (
		l = log.WithFields(logrus.Fields{
			"component": "PolicySelection",
		})

		// determine which policies match our node's labels.
		selectedPolicy *v2alpha1api.CiliumBGPPeeringPolicy
		slimLabels     = slimlabels.Set(labels)
	)

	// range over policies and see if any match this node's labels.
	//
	// for now, only a single BGP policy can be applied to a node. if more than
	// one policy applies to a node, we disconnect from all BGP peers and log
	// an error.
	for _, policy := range policies {
		var selected bool

		l.WithFields(logrus.Fields{
			"policyName":         policy.Name,
			"nodeLabels":         slimLabels,
			"policyNodeSelector": policy.Spec.NodeSelector.String(),
		}).Debug("Comparing BGP policy node selector with node's labels")

		if policy.Spec.NodeSelector == nil {
			selected = true
		} else {
			nodeSelector, err := slimmetav1.LabelSelectorAsSelector(policy.Spec.NodeSelector)
			if err != nil {
				l.WithError(err).Error("Failed to convert CiliumBGPPeeringPolicy's NodeSelector to a label.Selector interface")
				continue
			}
			if nodeSelector.Matches(slimLabels) {
				selected = true
			}
		}

		if selected {
			if selectedPolicy != nil {
				return nil, ErrMultiplePolicies
			}
			selectedPolicy = policy
		}
	}

	return selectedPolicy, nil
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
	)

	localNode, err := c.LocalNodeStore.Get(ctx)
	if err != nil {
		return fmt.Errorf("failed to retrieve local node: %w", err)
	}

	// retrieve all CiliumBGPPeeringPolicies
	policies, err := c.PolicyLister.List()
	if err != nil {
		return fmt.Errorf("failed to list CiliumBGPPeeringPolicies")
	}
	l.WithField("count", len(policies)).Debug("Successfully listed CiliumBGPPeeringPolicies")

	// perform policy selection based on node.
	labels := localNode.Labels
	policy, err := PolicySelection(ctx, labels, policies)
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

	// apply policy defaults to have consistent default config across sub-systems
	policy = policy.DeepCopy() // deepcopy to not modify the policy object in store
	policy.SetDefaults()

	err = c.validatePolicy(policy)
	if err != nil {
		return fmt.Errorf("invalid BGP peering policy %s: %w", policy.Name, err)
	}

	// call bgp sub-systems required to apply this policy's BGP topology.
	l.Debug("Asking configured BGPRouterManager to configure peering")
	if err := c.BGPMgr.ConfigurePeers(ctx, policy, &localNode, c.LocalCiliumNode); err != nil {
		return fmt.Errorf("failed to configure BGP peers, cannot apply BGP peering policy: %w", err)
	}

	return nil
}

// FullWithdrawal will instruct the configured BGPRouterManager to withdraw all
// BGP servers and peers.
func (c *Controller) FullWithdrawal(ctx context.Context) {
	_ = c.BGPMgr.ConfigurePeers(ctx, nil, nil, nil) // cannot fail, no need for error handling
}

// validatePolicy validates the CiliumBGPPeeringPolicy.
// The validation is normally done by kube-apiserver (based on CRD validation markers),
// this validates only those constraints that cannot be enforced by them.
func (c *Controller) validatePolicy(policy *v2alpha1api.CiliumBGPPeeringPolicy) error {
	for _, r := range policy.Spec.VirtualRouters {
		for _, n := range r.Neighbors {
			if err := n.Validate(); err != nil {
				return err
			}
		}
	}
	return nil
}
