// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"context"
	"fmt"
	"net/netip"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/cilium/workerpool"

	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/ip"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	slimlabels "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/labels"
	slimmetav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	nodeaddr "github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
)

// minHoldTime represents the minimal BGP hold time duration
const minHoldTime = 3 * time.Second

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
	// A list of configured PodCIDRs for the current Node.
	PodCIDRs []string
	// Parsed 'cilium.io/bgp-virtual-router' annotations of the the node this
	// control plane is running on.
	Annotations AnnotationMap
	// The current IPv4 address of the agent, reachable externally.
	IPv4 netip.Addr
	// The current IPv6 address of the agent, reachable externally.
	IPv6 netip.Addr
}

// ResolveRouterID resolves router ID, if we have an annotation and it can be
// parsed into a valid ipv4 address use it. If not, determine if Cilium is
// configured with an IPv4 address, if so use it. If neither, return an error,
// we cannot assign an router ID.
func (cstate *ControlPlaneState) ResolveRouterID(localASN int) (string, error) {
	if _, ok := cstate.Annotations[localASN]; ok {
		if parsed, err := netip.ParseAddr(cstate.Annotations[localASN].RouterID); err == nil && !parsed.IsUnspecified() {
			return parsed.String(), nil
		}
	}

	if !cstate.IPv4.IsUnspecified() {
		return cstate.IPv4.String(), nil
	}

	return "", fmt.Errorf("router id not specified by annotation and no IPv4 address assigned by cilium, cannot resolve router id for virtual router with local ASN %v", localASN)
}

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
	NodeSpec nodeSpecer
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
	Sig Signaler
	// BGPMgr is an implementation of the BGPRouterManager interface
	// and provides a declarative API for configuring BGP peers.
	BGPMgr BGPRouterManager

	workerpool *workerpool.WorkerPool
}

// ControllerParams contains all parameters needed to construct a Controller
type ControllerParams struct {
	cell.In

	Lifecycle      hive.Lifecycle
	Sig            Signaler
	RouteMgr       BGPRouterManager
	PolicyResource resource.Resource[*v2alpha1api.CiliumBGPPeeringPolicy]
	DaemonConfig   *option.DaemonConfig
	NodeSpec       nodeSpecer
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
		Sig:            params.Sig,
		BGPMgr:         params.RouteMgr,
		PolicyResource: params.PolicyResource,
		NodeSpec:       params.NodeSpec,
	}

	params.Lifecycle.Append(&c)

	return &c, nil
}

// Start is called by hive after all of our dependencies have been started.
func (c *Controller) Start(startCtx hive.HookContext) error {
	store, err := c.PolicyResource.Store(startCtx)
	if err != nil {
		return fmt.Errorf("PolicyResource.Store(): %w", err)
	}
	c.PolicyLister = policyListerFunc(func() ([]*v2alpha1api.CiliumBGPPeeringPolicy, error) {
		return store.List(), nil
	})

	c.workerpool = workerpool.New(2)

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

	l.Info("Cilium BGP Control Plane Controller now running...")
	for {
		select {
		case <-ctx.Done():
			killCTX, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
			defer cancel()

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
//   - A policy matches a node if said policy's "nodeSelector" field matches
//     the node's labels
//   - If (N > 1) policies match the provided *corev1.Node an error is returned.
//     only a single policy may apply to a node to avoid ambiguity at this stage
//     of development.
func PolicySelection(ctx context.Context, labels map[string]string, policies []*v2alpha1api.CiliumBGPPeeringPolicy) (*v2alpha1api.CiliumBGPPeeringPolicy, error) {
	var (
		l = log.WithFields(logrus.Fields{
			"component": "PolicySelection",
		})
	)
	// determine which policies match our node's labels.
	var (
		selected   *v2alpha1api.CiliumBGPPeeringPolicy
		slimLabels = slimlabels.Set(labels)
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
	)

	// retrieve all CiliumBGPPeeringPolicies
	policies, err := c.PolicyLister.List()
	if err != nil {
		return fmt.Errorf("failed to list CiliumBGPPeeringPolicies")
	}
	l.WithField("count", len(policies)).Debug("Successfully listed CiliumBGPPeeringPolicies")

	// perform policy selection based on node.
	labels, err := c.NodeSpec.Labels()
	if err != nil {
		return fmt.Errorf("failed to retrieve labels for Node: %w", err)
	}
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
	policy = c.applyPolicyDefaults(policy)

	err = c.validatePolicy(policy)
	if err != nil {
		return fmt.Errorf("invalid BGP peering policy %s: %w", policy.Name, err)
	}

	// parse any virtual router specific attributes defined on this node via
	// kubernetes annotations
	//
	// if we notice one or more malformed annotations report the errors up and
	// fail reconciliation.
	annotations, err := c.NodeSpec.Annotations()
	if err != nil {
		return fmt.Errorf("failed to retrieve Node's annotations: %w", err)
	}

	annoMap, err := NewAnnotationMap(annotations)
	if err != nil {
		return fmt.Errorf("failed to parse annotations: %w", err)
	}

	podCIDRs, err := c.NodeSpec.PodCIDRs()
	if err != nil {
		return fmt.Errorf("failed to retrieve Node's pod CIDR ranges: %w", err)
	}

	ipv4, _ := ip.AddrFromIP(nodeaddr.GetIPv4())
	ipv6, _ := ip.AddrFromIP(nodeaddr.GetIPv6())

	// define our current point-in-time control plane state.
	state := &ControlPlaneState{
		PodCIDRs:    podCIDRs,
		Annotations: annoMap,
		IPv4:        ipv4,
		IPv6:        ipv6,
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

// applyPolicyDefaults applies default values on the CiliumBGPPeeringPolicy.
func (c *Controller) applyPolicyDefaults(policy *v2alpha1api.CiliumBGPPeeringPolicy) *v2alpha1api.CiliumBGPPeeringPolicy {
	p := policy.DeepCopy() // deepcopy to not modify the policy object in store
	for _, r := range p.Spec.VirtualRouters {
		for j := range r.Neighbors {
			n := &r.Neighbors[j]
			if n.ConnectRetryTime.Duration == 0 {
				n.ConnectRetryTime.Duration = types.DefaultBGPConnectRetryTime
			}
			if n.HoldTime.Duration == 0 {
				// RFC4271 Sec 4.4 says that hold time can be 0 and has a special meaning that disables keepalive.
				// However, as GoBGP defaults the hold time for 0 value, it cannot be 0 in our case.
				n.HoldTime.Duration = types.DefaultBGPHoldTime
			}
			if n.KeepAliveTime.Duration == 0 {
				n.KeepAliveTime.Duration = n.HoldTime.Duration / 3
			}
		}
	}
	return p
}

// validatePolicy validates the CiliumBGPPeeringPolicy.
func (c *Controller) validatePolicy(policy *v2alpha1api.CiliumBGPPeeringPolicy) error {
	for _, r := range policy.Spec.VirtualRouters {
		for _, n := range r.Neighbors {
			if n.ConnectRetryTime.Duration < 0 {
				return fmt.Errorf("connectRetryTime is negative for peer ASN %d, IP %s", n.PeerASN, n.PeerAddress)
			}
			if n.HoldTime.Duration < minHoldTime {
				// RFC4271 Sec 4.2 says that the hold time MUST be zero or at least 3 seconds.
				// However, as GoBGP defaults the hold time for 0 value, it cannot be 0 in our case.
				return fmt.Errorf("holdTime is lower than %v for peer ASN %d, IP %s", minHoldTime, n.PeerASN, n.PeerAddress)
			}
			if n.KeepAliveTime.Duration < 0 {
				return fmt.Errorf("keepAliveTime is negative for peer ASN %d, IP %s", n.PeerASN, n.PeerAddress)
			}
			if n.KeepAliveTime.Duration > n.HoldTime.Duration {
				return fmt.Errorf("keepAliveTime time larger than holdTime for peer ASN %d, IP %s", n.PeerASN, n.PeerAddress)
			}
		}
	}
	return nil
}
