// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"context"
	"errors"
	"fmt"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/wait"

	daemon_k8s "github.com/cilium/cilium/daemon/k8s"
	"github.com/cilium/cilium/pkg/bgpv1/agent/mode"
	"github.com/cilium/cilium/pkg/bgpv1/agent/signaler"
	"github.com/cilium/cilium/pkg/bgpv1/manager/store"
	"github.com/cilium/cilium/pkg/hive"
	v2_api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slimlabels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slimmetav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "bgp-control-plane")
)

var (
	// ErrMultiplePolicies is a static error typed when the controller encounters
	// multiple policies which apply to its host.
	ErrMultiplePolicies = fmt.Errorf("more then one CiliumBGPPeeringPolicy applies to this node, please ensure only a single Policy matches this node's labels")

	// ErrBGPControlPlaneDisabled is set when the BGP control plane is disabled
	ErrBGPControlPlaneDisabled = fmt.Errorf("BGP control plane is disabled")
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
	// CiliumNodeResource provides a stream of events for changes to the local CiliumNode resource.
	CiliumNodeResource daemon_k8s.LocalCiliumNodeResource
	// LocalCiliumNode is the CiliumNode object for the local node.
	LocalCiliumNode *v2_api.CiliumNode
	// PolicyResource provides a store of cached policies and allows us to observe changes to the objects in its
	// store.
	PolicyResource resource.Resource[*v2alpha1api.CiliumBGPPeeringPolicy]
	// PolicyLister is an interface which allows for the listing of all known policies
	PolicyLister policyLister

	// BGP v2 node store
	BGPNodeConfigStore store.BGPCPResourceStore[*v2alpha1api.CiliumBGPNodeConfig]

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

	// current configuration state
	ConfigMode *mode.ConfigMode
}

// ControllerParams contains all parameters needed to construct a Controller
type ControllerParams struct {
	cell.In

	Lifecycle               cell.Lifecycle
	Health                  cell.Health
	JobGroup                job.Group
	Shutdowner              hive.Shutdowner
	Sig                     *signaler.BGPCPSignaler
	ConfigMode              *mode.ConfigMode
	RouteMgr                BGPRouterManager
	PolicyResource          resource.Resource[*v2alpha1api.CiliumBGPPeeringPolicy]
	BGPNodeConfigStore      store.BGPCPResourceStore[*v2alpha1api.CiliumBGPNodeConfig]
	DaemonConfig            *option.DaemonConfig
	LocalCiliumNodeResource daemon_k8s.LocalCiliumNodeResource
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

	c := &Controller{
		Sig:                params.Sig,
		ConfigMode:         params.ConfigMode,
		BGPMgr:             params.RouteMgr,
		PolicyResource:     params.PolicyResource,
		BGPNodeConfigStore: params.BGPNodeConfigStore,
		CiliumNodeResource: params.LocalCiliumNodeResource,
	}

	params.JobGroup.Add(
		job.OneShot("bgp-policy-observer", func(ctx context.Context, health cell.Health) (err error) {
			for ev := range c.PolicyResource.Events(ctx) {
				switch ev.Kind {
				case resource.Upsert, resource.Delete:
					// Signal the reconciliation logic.
					c.Sig.Event(struct{}{})
				}
				ev.Done(nil)
			}
			return nil
		}),

		job.OneShot("bgp-controller",
			func(ctx context.Context, health cell.Health) (err error) {
				// initialize PolicyLister used in the controller
				policyStore, err := c.PolicyResource.Store(ctx)
				if err != nil {
					return fmt.Errorf("error creating CiliumBGPPeeringPolicy resource store: %w", err)
				}
				c.PolicyLister = policyListerFunc(func() ([]*v2alpha1api.CiliumBGPPeeringPolicy, error) {
					return policyStore.List(), nil
				})

				// run the controller
				c.Run(ctx)
				return nil
			},
			job.WithRetry(3, &job.ExponentialBackoff{Min: 100 * time.Millisecond, Max: time.Second}),
			job.WithShutdown()),
	)

	return c, nil
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

	l.Info("Cilium BGP Control Plane Controller now running...")
	ciliumNodeCh := c.CiliumNodeResource.Events(ctx)
	for {
		select {
		case ev, ok := <-ciliumNodeCh:
			if !ok {
				l.Info("LocalCiliumNode resource channel closed, Cilium BGP Control Plane Controller shut down")
				return
			}
			switch ev.Kind {
			case resource.Upsert:
				// Set the local CiliumNode.
				c.LocalCiliumNode = ev.Object
				// Signal the reconciliation logic.
				c.Sig.Event(struct{}{})
			}
			ev.Done(nil)
		case <-ctx.Done():
			l.Info("Cilium BGP Control Plane Controller shut down")
			return
		case <-c.Sig.Sig:
			if c.LocalCiliumNode == nil {
				l.Debug("localCiliumNode has not been set yet")
			} else if err := c.reconcileWithRetry(ctx); err != nil {
				l.WithError(err).Error("Reconciliation with retries failed")
			} else {
				l.Debug("Successfully completed reconciliation")
			}
		}
	}
}

// reconcileWithRetry runs Reconcile and retries if it fails until the iterations count defined in backoff is reached.
func (c *Controller) reconcileWithRetry(ctx context.Context) error {
	// reconciliation will repeat for ~15 seconds
	backoff := wait.Backoff{
		Duration: 500 * time.Millisecond,
		Factor:   2,
		Jitter:   0.5,
		Steps:    5,
	}

	var err error
	retryFn := func(ctx context.Context) (bool, error) {
		err = c.Reconcile(ctx)
		if err != nil {
			log.WithError(err).Debug("Reconciliation failed")
			return false, nil
		}
		return true, nil
	}

	if retryErr := wait.ExponentialBackoffWithContext(ctx, backoff, retryFn); retryErr != nil {
		if wait.Interrupted(retryErr) && err != nil {
			return err // return the actual reconciliation error
		}
		return retryErr
	}
	return nil
}

// Reconcile is the main reconciliation loop for the BGP Control Plane Controller.
// It is responsible for determining the current mode of BGP control plane, which can be disabled, bgpv1 or bgpv2.
// Based on presence of BGP peering policy and BGP node config, it will apply the appropriate configuration.
// Following is the state transition table for the controller:
// Initial state         | BGPPP exists | BGPNC exists | Action	                    | Next state
// ----------------------|--------------|--------------|----------------------------|-----------
// disabled              | true         | don't care   | Apply BGPv1                | bgpv1
// disabled              | false        | true         | Apply BGPv2                | bgpv2
// disabled              | false        | false        | Do nothing                 | disabled
// bgpv1                 | true         | don't care   | Apply BGPv1                | bgpv1
// bgpv1                 | false        | true         | Delete BGPv1, Apply BGPv2  | bgpv2
// bgpv1                 | false        | false        | Delete BGPv1               | disabled
// bgpv2                 | true         | don't care   | Delete BGPv2, Apply BGPv1  | bgpv1
// bgpv2                 | false        | true         | Apply BGPv2                | bgpv2
// bgpv2                 | false        | false        | Delete BGPv2               | disabled
func (c *Controller) Reconcile(ctx context.Context) error {
	bgpp, err := c.bgppSelection()
	if err != nil {
		log.WithError(err).Error("bgp peering policy selection failed")
		return err
	}
	bgppExists := bgpp != nil

	bgpnc, bgpncExists, err := c.BGPNodeConfigStore.GetByKey(resource.Key{
		Name: c.LocalCiliumNode.Name,
	})
	if err != nil {
		if errors.Is(err, store.ErrStoreUninitialized) {
			log.Debug("BGPNodeConfig store not yet initialized")
			return nil // skip the reconciliation - once the store is initialized, it will trigger new reconcile event
		}
		log.WithError(err).Error("failed to get BGPNodeConfig")
		return err
	}

	switch c.ConfigMode.Get() {
	case mode.Disabled:
		if bgppExists {
			err = c.reconcileBGPP(ctx, bgpp)
		} else if bgpncExists {
			err = c.reconcileBGPNC(ctx, bgpnc)
		}

	case mode.BGPv1:
		if bgppExists {
			err = c.reconcileBGPP(ctx, bgpp)
		} else {
			c.cleanupBGPP(ctx)

			// check if we need to reconcile bgpv2
			if bgpncExists {
				err = c.reconcileBGPNC(ctx, bgpnc)
			}
		}

	case mode.BGPv2:
		if bgppExists {
			// delete bgpv2 and apply bgpv1
			c.cleanupBGPNC(ctx)
			err = c.reconcileBGPP(ctx, bgpp)
		} else if bgpncExists {
			err = c.reconcileBGPNC(ctx, bgpnc)
		} else {
			c.cleanupBGPNC(ctx)
		}
	}
	return err
}

func (c *Controller) reconcileBGPP(ctx context.Context, policy *v2alpha1api.CiliumBGPPeeringPolicy) error {
	// apply policy defaults to have consistent default config across sub-systems
	policy = policy.DeepCopy() // deepcopy to not modify the policy object in store
	policy.SetDefaults()

	err := c.validatePolicy(policy)
	if err != nil {
		return fmt.Errorf("invalid BGP peering policy %s: %w", policy.Name, err)
	}

	// call bgp sub-systems required to apply this policy's BGP topology.
	if err := c.BGPMgr.ConfigurePeers(ctx, policy, c.LocalCiliumNode); err != nil {
		return fmt.Errorf("failed to configure BGP peers, cannot apply BGP peering policy: %w", err)
	}

	c.ConfigMode.Set(mode.BGPv1)
	return nil
}

func (c *Controller) cleanupBGPP(ctx context.Context) {
	err := c.BGPMgr.ConfigurePeers(ctx, nil, nil)
	if err != nil {
		// log cleanup error
		log.WithError(err).Error("failed to cleanup BGP peering policy peers")
	}

	c.ConfigMode.Set(mode.Disabled)
}

func (c *Controller) reconcileBGPNC(ctx context.Context, bgpnc *v2alpha1api.CiliumBGPNodeConfig) error {
	err := c.BGPMgr.ReconcileInstances(ctx, bgpnc, c.LocalCiliumNode)
	if err != nil {
		return fmt.Errorf("failed to reconcile BGPNodeConfig: %w", err)
	}

	c.ConfigMode.Set(mode.BGPv2)
	return nil
}

func (c *Controller) cleanupBGPNC(ctx context.Context) {
	err := c.BGPMgr.ReconcileInstances(ctx, nil, c.LocalCiliumNode)
	if err != nil {
		log.WithError(err).Error("failed to cleanup BGPNodeConfig")
	}

	c.ConfigMode.Set(mode.Disabled)
}

func (c *Controller) bgppSelection() (*v2alpha1api.CiliumBGPPeeringPolicy, error) {
	// retrieve all CiliumBGPPeeringPolicies
	policies, err := c.PolicyLister.List()
	if err != nil {
		return nil, fmt.Errorf("failed to list CiliumBGPPeeringPolicies")
	}
	// perform policy selection based on node.
	labels := c.LocalCiliumNode.Labels

	return PolicySelection(labels, policies)
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
func PolicySelection(labels map[string]string, policies []*v2alpha1api.CiliumBGPPeeringPolicy) (*v2alpha1api.CiliumBGPPeeringPolicy, error) {
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
