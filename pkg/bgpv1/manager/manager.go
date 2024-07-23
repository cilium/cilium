// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"context"
	"errors"
	"fmt"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/cilium/cilium/api/v1/models"
	restapi "github.com/cilium/cilium/api/v1/server/restapi/bgp"
	"github.com/cilium/cilium/pkg/bgpv1/agent"
	"github.com/cilium/cilium/pkg/bgpv1/agent/mode"
	"github.com/cilium/cilium/pkg/bgpv1/api"
	"github.com/cilium/cilium/pkg/bgpv1/manager/instance"
	"github.com/cilium/cilium/pkg/bgpv1/manager/reconciler"
	"github.com/cilium/cilium/pkg/bgpv1/manager/reconcilerv2"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	v2api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

var (
	// ATTENTION:
	// All logs generated from this package will have the k/v
	// `subsys=bgp-control-plane`.
	//
	// Each log message will additionally contain the k/v
	// 'component=manager.{Struct}.{Method}' or 'component=manager.{Function}' to
	// provide further granularity on where the log is originating from.
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "bgp-control-plane")
)

// LocalASNMap maps local ASNs to their associated BgpServers and server
// configuration info.
type LocalASNMap map[int64]*instance.ServerWithConfig

// LocalInstanceMap maps instance names to their associated BgpInstances and
// configuration info.
type LocalInstanceMap map[string]*instance.BGPInstance

type bgpRouterManagerParams struct {
	cell.In
	Logger           logrus.FieldLogger
	JobGroup         job.Group
	ConfigMode       *mode.ConfigMode
	Reconcilers      []reconciler.ConfigReconciler   `group:"bgp-config-reconciler"`
	ReconcilersV2    []reconcilerv2.ConfigReconciler `group:"bgp-config-reconciler-v2"`
	StateReconcilers []reconcilerv2.StateReconciler  `group:"bgp-state-reconciler-v2"`
}

type State struct {
	// reconcilers are list of state reconcilers which will be called when instance state changes.
	reconcilers []reconcilerv2.StateReconciler

	// notifications is a map of instance name to the channel which will be used to get notification
	// from underlying BGP instance. This map is used for bookkeeping and closing of channel when
	// instance is deleted.
	notifications map[string]types.StateNotificationCh

	// pendingInstancesMutex is used to protect the pendingInstances set.
	//
	// pendingInstancesMutex in BGPRouterManager is introduced as we can have high number of
	// state notifications. We do not want to hold the BGPRouterManager.Lock for each
	// state update.
	//
	// Order of locking: pendingInstancesMutex -> BGPRouterManager.Lock
	// DO NOT take BGPRouterManager.Lock and then State.pendingInstancesMutex.
	pendingInstancesMutex lock.Mutex

	// pendingInstances set contains the instances which need to be reconciled for state change.
	pendingInstances sets.Set[string]

	// reconcileSignal is used to signal bgp-state-observer to reconcile the state based on
	// pendingInstances set.
	reconcileSignal chan struct{}

	// instanceDeletionSignal is used to signal bgp-state-observer to reconcile the cleanup of
	// instance. Instance name is signaled on this channel.
	instanceDeletionSignal chan string
}

// BGPRouterManager implements the pkg.bgpv1.agent.BGPRouterManager interface.
//
// Logically, this manager views each CiliumBGPVirtualRouter within a
// CiliumBGPPeeringPolicy as a BGP router instantiated on its host.
//
// BGP routers are grouped and accessed by their local ASNs, thus this backend
// mandates that each CiliumBGPPeeringConfig have a unique local ASN and
// precludes a single host instantiating two routers with the same local ASN.
//
// This manager employs two main data structures to implement its high level
// business logic.
//
// A reconcilerDiff is used to establish which BgpServers must be created,
// and removed from the Manager along with which servers must have their
// configurations reconciled.
//
// A set of ReconcilerConfigFunc(s), which usages are wrapped by the
// ReconcileBGPConfig function, reconcile individual features of a
// CiliumBGPPeeringConfig.
//
// Together, the high-level flow the manager takes is:
//   - Instantiate a reconcilerDiff to compute which BgpServers to create, remove,
//     and reconcile
//   - Create any BgpServers necessary, run ReconcilerConfigFuncs(s) on each
//   - Run each ReconcilerConfigFunc, by way of ReconcileBGPConfig,
//     on any BgpServers marked for reconcile
//
// BgpServers are abstracted by the ServerWithConfig structure which provides a
// method set for low-level BGP operations.
//
// As part of BGPv2 development, this manager has been extended to support BGPv2
// fields - BGPInstance and ReconcilersV2.
type BGPRouterManager struct {
	lock.RWMutex

	Logger logrus.FieldLogger

	// Helper to determine the mode of the agent
	ConfigMode *mode.ConfigMode

	// BGPv1 servers and reconcilers
	Servers     LocalASNMap
	Reconcilers []reconciler.ConfigReconciler

	// BGPv2 instances and reconcilers
	BGPInstances      LocalInstanceMap
	ConfigReconcilers []reconcilerv2.ConfigReconciler

	// running is set when the manager is running, and unset when it is stopped.
	running bool

	// state management
	state State
}

// NewBGPRouterManager constructs a GoBGP-backed BGPRouterManager.
//
// See BGPRouterManager for details.
func NewBGPRouterManager(params bgpRouterManagerParams) agent.BGPRouterManager {
	activeReconcilers := reconciler.GetActiveReconcilers(params.Reconcilers)
	activeReconcilersV2 := reconcilerv2.GetActiveReconcilers(params.Logger, params.ReconcilersV2)

	m := &BGPRouterManager{
		Logger:      params.Logger,
		ConfigMode:  params.ConfigMode,
		Servers:     make(LocalASNMap),
		Reconcilers: activeReconcilers,
		running:     true, // start with running state set

		// BGPv2
		BGPInstances:      make(LocalInstanceMap),
		ConfigReconcilers: activeReconcilersV2,

		// state
		state: State{
			reconcilers:            reconcilerv2.GetActiveStateReconcilers(params.Logger, params.StateReconcilers),
			notifications:          make(map[string]types.StateNotificationCh),
			pendingInstances:       sets.New[string](),
			reconcileSignal:        make(chan struct{}, 1),
			instanceDeletionSignal: make(chan string),
		},
	}

	params.JobGroup.Add(
		job.OneShot("bgp-state-observer", func(ctx context.Context, health cell.Health) (err error) {
			for {
				select {
				case <-ctx.Done():
					return nil
				case <-m.state.reconcileSignal:
					err := m.reconcileStateWithRetry(ctx)
					if err != nil {
						m.Logger.WithError(err).Error("failed to reconcile state")
					}
				case instanceName := <-m.state.instanceDeletionSignal:
					m.reconcileInstanceDeletion(ctx, instanceName)
				}
			}
		}),
	)

	return m
}

func (m *BGPRouterManager) reconcileStateWithRetry(ctx context.Context) error {
	bo := wait.Backoff{
		Duration: 100 * time.Millisecond,
		Factor:   1.2,
		Steps:    10,
	}

	retryFn := func(ctx context.Context) (bool, error) {
		err := m.reconcileState(ctx)
		if err != nil {
			m.Logger.WithError(err).Error("failed to reconcile state")
			return false, nil
		}
		return true, nil
	}

	return wait.ExponentialBackoffWithContext(ctx, bo, retryFn)
}

// ConfigurePeers is a declarative API for configuring the BGP peering topology
// given a desired CiliumBGPPeeringPolicy.
//
// ConfigurePeers will evaluate BGPRouterManager's current state and the desired
// CiliumBGPPeeringPolicy policy then take the necessary actions to apply the
// provided policy. For more details see BGPRouterManager's comments.
//
// ConfigurePeers should return only once a subsequent invocation is safe.
// This method is not thread safe and does not intend to be called concurrently.
func (m *BGPRouterManager) ConfigurePeers(ctx context.Context,
	policy *v2alpha1api.CiliumBGPPeeringPolicy,
	ciliumNode *v2api.CiliumNode) error {
	m.Lock()
	defer m.Unlock()

	if !m.running {
		return fmt.Errorf("bgp router manager is not running")
	}

	l := log.WithFields(
		logrus.Fields{
			"component": "manager.ConfigurePeers",
		},
	)

	// use a reconcileDiff to compute which BgpServers must be created, removed
	// and reconciled.
	rd := newReconcileDiff(ciliumNode)

	if policy == nil {
		return m.withdrawAll(ctx, rd)
	}

	rd.diff(m.Servers, policy)

	if rd.empty() {
		l.Debug("GoBGP peering topology up-to-date with CiliumBGPPeeringPolicy for this node.")
		return nil
	}
	l.WithField("diff", rd.String()).Debug("Reconciling new CiliumBGPPeeringPolicy")

	if len(rd.register) > 0 {
		if err := m.register(ctx, rd); err != nil {
			return fmt.Errorf("encountered error adding new BGP Servers: %w", err)
		}
	}
	if len(rd.withdraw) > 0 {
		if err := m.withdraw(ctx, rd); err != nil {
			return fmt.Errorf("encountered error removing existing BGP Servers: %w", err)
		}
	}
	if len(rd.reconcile) > 0 {
		if err := m.reconcile(ctx, rd); err != nil {
			return fmt.Errorf("encountered error reconciling existing BGP Servers: %w", err)
		}
	}
	return nil
}

// register instantiates and configures BgpServer(s) as instructed by the provided
// work diff.
func (m *BGPRouterManager) register(ctx context.Context, rd *reconcileDiff) error {
	l := log.WithFields(
		logrus.Fields{
			"component": "manager.add",
		},
	)
	for _, asn := range rd.register {
		var config *v2alpha1api.CiliumBGPVirtualRouter
		var ok bool
		if config, ok = rd.seen[asn]; !ok {
			l.Errorf("Work diff (add) contains unseen ASN %v, skipping", asn)
			continue
		}
		if err := m.registerBGPServer(ctx, config, rd.ciliumNode); err != nil {
			// we'll just log the error and attempt to register the next BgpServer.
			l.WithError(err).Errorf("Error while registering new BGP server for local ASN %v.", config.LocalASN)
		}
	}
	return nil
}

// registerBGPServer encapsulates the logic for instantiating a
// BgpServer, configuring it based on a CiliumBGPVirtualRouter, and
// registering it with the Manager.
//
// If this registration process fails the server will be stopped (if it was started)
// and deleted from our manager (if it was added).
func (m *BGPRouterManager) registerBGPServer(ctx context.Context,
	c *v2alpha1api.CiliumBGPVirtualRouter,
	ciliumNode *v2api.CiliumNode) error {
	l := log.WithFields(
		logrus.Fields{
			"component": "manager.registerBGPServer",
		},
	)

	l.Infof("Registering BGP servers for policy with local ASN %v", c.LocalASN)

	annoMap, err := agent.NewAnnotationMap(ciliumNode.Annotations)
	if err != nil {
		return fmt.Errorf("unable to parse local node's annotations: %w", err)
	}

	// resolve local port from kubernetes annotations
	var localPort int32
	localPort = -1
	if attrs, ok := annoMap[c.LocalASN]; ok {
		if attrs.LocalPort != 0 {
			localPort = int32(attrs.LocalPort)
		}
	}

	routerID, err := annoMap.ResolveRouterID(c.LocalASN)
	if err != nil {
		if nodeIP := ciliumNode.GetIP(false); nodeIP == nil {
			return fmt.Errorf("failed to get ciliumnode IP %v: %w", nodeIP, err)
		} else {
			routerID = nodeIP.String()
		}
	}

	globalConfig := types.ServerParameters{
		Global: types.BGPGlobal{
			ASN:        uint32(c.LocalASN),
			RouterID:   routerID,
			ListenPort: localPort,
			RouteSelectionOptions: &types.RouteSelectionOptions{
				AdvertiseInactiveRoutes: true,
			},
		},
	}

	s, err := instance.NewServerWithConfig(ctx, log, globalConfig)
	if err != nil {
		return fmt.Errorf("failed to start BGP server for config with local ASN %v: %w", c.LocalASN, err)
	}

	// We can commit the register the server here. Even if the following
	// reconciliation fails, we can return error and it triggers retry. The
	// next retry will be handled by reconcile(). We don't need to retry
	// the server creation which already succeeded.
	m.Servers[c.LocalASN] = s

	if err = m.reconcileBGPConfig(ctx, s, c, ciliumNode); err != nil {
		return fmt.Errorf("failed initial reconciliation for peer config with local ASN %v: %w", c.LocalASN, err)
	}

	l.Infof("Successfully registered GoBGP servers for policy with local ASN %v", c.LocalASN)

	return err
}

// withdraw disconnects and removes BgpServer(s) as instructed by the provided
// work diff.
func (m *BGPRouterManager) withdraw(ctx context.Context, rd *reconcileDiff) error {
	l := log.WithFields(
		logrus.Fields{
			"component": "manager.remove",
		},
	)
	for _, asn := range rd.withdraw {
		var (
			s  *instance.ServerWithConfig
			ok bool
		)
		if s, ok = m.Servers[asn]; !ok {
			l.Warnf("Server with local ASN %v marked for deletion but does not exist", asn)
			continue
		}
		s.Server.Stop()
		delete(m.Servers, asn)
		l.Infof("Removed BGP server with local ASN %v", asn)
	}
	return nil
}

// withdrawAll will disconnect and remove all currently registered BgpServer(s).
//
// `rd` must be a newly created reconcileDiff which has not had its `Diff` method
// called.
func (m *BGPRouterManager) withdrawAll(ctx context.Context, rd *reconcileDiff) error {
	if len(m.Servers) == 0 {
		return nil
	}
	for asn := range m.Servers {
		rd.withdraw = append(rd.withdraw, asn)
	}
	return m.withdraw(ctx, rd)
}

// reconcile evaluates existing BgpServer(s), making changes if necessary, as
// instructed by the provided reoncileDiff.
func (m *BGPRouterManager) reconcile(ctx context.Context, rd *reconcileDiff) error {
	l := log.WithFields(
		logrus.Fields{
			"component": "manager.reconcile",
		},
	)
	for _, asn := range rd.reconcile {
		var (
			sc   = m.Servers[asn]
			newc = rd.seen[asn]
		)
		if sc == nil {
			l.Errorf("Virtual router with local ASN %v marked for reconciliation but missing from Manager", newc.LocalASN) // really shouldn't happen
			continue
		}
		if newc == nil {
			l.Errorf("Virtual router with local ASN %v marked for reconciliation but missing from incoming configurations", sc.Config.LocalASN) // also really shouldn't happen
			continue
		}
		if err := m.reconcileBGPConfig(ctx, sc, newc, rd.ciliumNode); err != nil {
			l.WithError(err).Errorf("Encountered error reconciling virtual router with local ASN %v", newc.LocalASN)
		}
	}
	return nil
}

// reconcileBGPConfig will utilize the current set of ConfigReconciler(s)
// to push a BgpServer to its desired configuration.
//
// If any ConfigReconciler fails so will ReconcileBGPConfig and the caller
// is left to decide how to handle the possible inconsistent state of the
// BgpServer left over.
//
// Providing a ServerWithConfig that has a nil `Config` field indicates that
// this is the first time this BgpServer is being configured, each
// ConfigReconciler must be prepared to handle this.
//
// The two CiliumBGPVirtualRouter(s) being compared must have the same local
// ASN, unless `sc.Config` is nil, or else an error is returned.
//
// On success the provided `newc` will be written to `sc.Config`. The caller
// should then store `sc` until next reconciliation.
func (m *BGPRouterManager) reconcileBGPConfig(ctx context.Context,
	sc *instance.ServerWithConfig,
	newc *v2alpha1api.CiliumBGPVirtualRouter,
	ciliumNode *v2api.CiliumNode) error {
	if sc.Config != nil {
		if sc.Config.LocalASN != newc.LocalASN {
			return fmt.Errorf("cannot reconcile two BgpServers with different local ASNs")
		}
	}
	for _, r := range m.Reconcilers {
		if err := r.Reconcile(ctx, reconciler.ReconcileParams{
			CurrentServer: sc,
			DesiredConfig: newc,
			CiliumNode:    ciliumNode,
		}); err != nil {
			return fmt.Errorf("reconciliation of virtual router with local ASN %v failed: %w", newc.LocalASN, err)
		}
	}
	// all reconcilers succeeded so update Server's config with new peering config.
	sc.Config = newc
	return nil
}

// GetPeers gets peering state from previously initialized bgp instances.
func (m *BGPRouterManager) GetPeers(ctx context.Context) ([]*models.BgpPeer, error) {
	m.RLock()
	defer m.RUnlock()

	if !m.running {
		return nil, fmt.Errorf("bgp router manager is not running")
	}

	var res []*models.BgpPeer
	switch m.ConfigMode.Get() {
	case mode.BGPv1:
		for _, s := range m.Servers {
			getPeerResp, err := s.Server.GetPeerState(ctx)
			if err != nil {
				return nil, err
			}
			res = append(res, getPeerResp.Peers...)
		}

	case mode.BGPv2:
		for _, i := range m.BGPInstances {
			getPeerResp, err := i.Router.GetPeerState(ctx)
			if err != nil {
				return nil, err
			}
			res = append(res, getPeerResp.Peers...)
		}
	}
	return res, nil
}

// GetRoutes retrieves routes from the RIB of underlying router
func (m *BGPRouterManager) GetRoutes(ctx context.Context, params restapi.GetBgpRoutesParams) ([]*models.BgpRoute, error) {
	m.RLock()
	defer m.RUnlock()

	if !m.running {
		return nil, fmt.Errorf("bgp router manager is not running")
	}

	switch m.ConfigMode.Get() {
	case mode.BGPv1:
		return m.getRoutesV1(ctx, params)
	case mode.BGPv2:
		return m.getRoutesV2(ctx, params)
	default:
		return nil, nil
	}
}

func (m *BGPRouterManager) getRoutesV1(ctx context.Context, params restapi.GetBgpRoutesParams) ([]*models.BgpRoute, error) {
	// validate router ASN
	if params.RouterAsn != nil {
		if _, found := m.Servers[*params.RouterAsn]; !found {
			return nil, fmt.Errorf("virtual router with ASN %d does not exist", *params.RouterAsn)
		}
	}

	// validate that router ASN is set for the neighbor if there are multiple servers
	if params.Neighbor != nil && len(m.Servers) > 1 && params.RouterAsn == nil {
		return nil, fmt.Errorf("multiple virtual routers configured, router ASN must be specified")
	}

	// determine if we need to retrieve the routes for each peer (in case of adj-rib but no peer specified)
	tt := types.ParseTableType(params.TableType)
	allPeers := (tt == types.TableTypeAdjRIBIn || tt == types.TableTypeAdjRIBOut) && (params.Neighbor == nil || *params.Neighbor == "")

	var res []*models.BgpRoute
	for _, s := range m.Servers {
		if params.RouterAsn != nil && *params.RouterAsn != s.Config.LocalASN {
			continue // return routes matching provided router ASN only
		}
		if allPeers {
			// get routes for each peer of the server
			getPeerResp, err := s.Server.GetPeerState(ctx)
			if err != nil {
				return nil, err
			}
			for _, peer := range getPeerResp.Peers {
				params.Neighbor = &peer.PeerAddress
				routes, err := m.getRoutesFromServer(ctx, s, params)
				if err != nil {
					return nil, err
				}
				res = append(res, routes...)
			}
		} else {
			// get routes with provided params
			routes, err := m.getRoutesFromServer(ctx, s, params)
			if err != nil {
				return nil, err
			}
			res = append(res, routes...)
		}
	}

	return res, nil
}

// getRoutesFromServer retrieves routes from the RIB of the specified server
func (m *BGPRouterManager) getRoutesFromServer(ctx context.Context, sc *instance.ServerWithConfig, params restapi.GetBgpRoutesParams) ([]*models.BgpRoute, error) {
	req, err := api.ToAgentGetRoutesRequest(params)
	if err != nil {
		return nil, err
	}
	rs, err := sc.Server.GetRoutes(ctx, req)
	if err != nil {
		return nil, err
	}
	neighbor := ""
	if params.Neighbor != nil {
		neighbor = *params.Neighbor
	}
	return api.ToAPIRoutes(rs.Routes, sc.Config.LocalASN, neighbor)
}

func (m *BGPRouterManager) getRoutesV2(ctx context.Context, params restapi.GetBgpRoutesParams) ([]*models.BgpRoute, error) {
	// validate router ASN
	if params.RouterAsn != nil {
		if m.asnExistsInInstances(*params.RouterAsn) {
			return nil, fmt.Errorf("virtual router with ASN %d does not exist", *params.RouterAsn)
		}
	}

	// validate that router ASN is set for the neighbor if there are multiple servers
	if params.Neighbor != nil && len(m.BGPInstances) > 1 && params.RouterAsn == nil {
		return nil, fmt.Errorf("multiple virtual routers configured, router ASN must be specified")
	}

	// determine if we need to retrieve the routes for each peer (in case of adj-rib but no peer specified)
	tt := types.ParseTableType(params.TableType)
	allPeers := (tt == types.TableTypeAdjRIBIn || tt == types.TableTypeAdjRIBOut) && (params.Neighbor == nil || *params.Neighbor == "")

	var res []*models.BgpRoute
	for _, i := range m.BGPInstances {
		if params.RouterAsn != nil && i.Config.LocalASN != nil && *params.RouterAsn != *i.Config.LocalASN {
			continue // return routes matching provided router ASN only
		}
		if allPeers {
			// get routes for each peer of the server
			getPeerResp, err := i.Router.GetPeerState(ctx)
			if err != nil {
				return nil, err
			}
			for _, peer := range getPeerResp.Peers {
				params.Neighbor = &peer.PeerAddress
				routes, err := m.getRoutesFromInstance(ctx, i, params)
				if err != nil {
					return nil, err
				}
				res = append(res, routes...)
			}
		} else {
			// get routes with provided params
			routes, err := m.getRoutesFromInstance(ctx, i, params)
			if err != nil {
				return nil, err
			}
			res = append(res, routes...)
		}
	}
	return res, nil
}

// getRoutesFromInstance retrieves routes from the RIB of the specified BGP instance
func (m *BGPRouterManager) getRoutesFromInstance(ctx context.Context, i *instance.BGPInstance, params restapi.GetBgpRoutesParams) ([]*models.BgpRoute, error) {
	if i.Config.LocalASN == nil {
		return nil, fmt.Errorf("local ASN not set for instance")
	}

	req, err := api.ToAgentGetRoutesRequest(params)
	if err != nil {
		return nil, err
	}

	rs, err := i.Router.GetRoutes(ctx, req)
	if err != nil {
		return nil, err
	}

	neighbor := ""
	if params.Neighbor != nil {
		neighbor = *params.Neighbor
	}
	return api.ToAPIRoutes(rs.Routes, *i.Config.LocalASN, neighbor)
}

func (m *BGPRouterManager) asnExistsInInstances(asn int64) bool {
	for _, instance := range m.BGPInstances {
		if instance.Config.LocalASN != nil && *instance.Config.LocalASN == asn {
			return true
		}
	}
	return false
}

// GetRoutePolicies fetches BGP routing policies from underlying routing daemon.
func (m *BGPRouterManager) GetRoutePolicies(ctx context.Context, params restapi.GetBgpRoutePoliciesParams) ([]*models.BgpRoutePolicy, error) {
	m.RLock()
	defer m.RUnlock()

	if !m.running {
		return nil, fmt.Errorf("bgp router manager is not running")
	}

	switch m.ConfigMode.Get() {
	case mode.BGPv1:
		return m.getRoutePoliciesV1(ctx, params)
	case mode.BGPv2:
		return m.getRoutePoliciesV2(ctx, params)
	default:
		return nil, nil
	}
}

func (m *BGPRouterManager) getRoutePoliciesV1(ctx context.Context, params restapi.GetBgpRoutePoliciesParams) ([]*models.BgpRoutePolicy, error) {
	// validate router ASN
	if params.RouterAsn != nil {
		if _, found := m.Servers[*params.RouterAsn]; !found {
			return nil, fmt.Errorf("virtual router with ASN %d does not exist", *params.RouterAsn)
		}
	}

	var res []*models.BgpRoutePolicy
	for _, s := range m.Servers {
		if params.RouterAsn != nil && *params.RouterAsn != s.Config.LocalASN {
			continue // return policies matching provided router ASN only
		}
		rs, err := s.Server.GetRoutePolicies(ctx)
		if err != nil {
			return nil, err
		}
		res = append(res, api.ToAPIRoutePolicies(rs.Policies, s.Config.LocalASN)...)
	}
	return res, nil
}

func (m *BGPRouterManager) getRoutePoliciesV2(ctx context.Context, params restapi.GetBgpRoutePoliciesParams) ([]*models.BgpRoutePolicy, error) {
	// validate router ASN
	if params.RouterAsn != nil {
		if m.asnExistsInInstances(*params.RouterAsn) {
			return nil, fmt.Errorf("virtual router with ASN %d does not exist", *params.RouterAsn)
		}
	}

	var res []*models.BgpRoutePolicy
	for _, i := range m.BGPInstances {
		if params.RouterAsn != nil && i.Config.LocalASN != nil && *params.RouterAsn != *i.Config.LocalASN {
			continue // return policies matching provided router ASN only
		}
		rs, err := i.Router.GetRoutePolicies(ctx)
		if err != nil {
			return nil, err
		}
		res = append(res, api.ToAPIRoutePolicies(rs.Policies, *i.Config.LocalASN)...)
	}
	return res, nil
}

// Stop cleans up all servers, should be called at shutdown
func (m *BGPRouterManager) Stop() {
	m.Lock()
	defer m.Unlock()

	for _, s := range m.Servers {
		s.Server.Stop()
	}

	for name, i := range m.BGPInstances {
		i.CancelCtx()
		i.Router.Stop()
		notifCh, exists := m.state.notifications[name]
		if exists {
			close(notifCh)
		}
	}

	m.Servers = make(LocalASNMap)
	m.BGPInstances = make(LocalInstanceMap)
	m.state.notifications = make(map[string]types.StateNotificationCh)
	m.running = false
}

// ReconcileInstances is a API for configuring the BGP Instances from the
// desired CiliumBGPNodeConfig resource.
//
// ReconcileInstances will evaluate BGP instances to be created, removed and
// reconciled.
func (m *BGPRouterManager) ReconcileInstances(ctx context.Context,
	nodeObj *v2alpha1api.CiliumBGPNodeConfig,
	ciliumNode *v2api.CiliumNode) error {
	m.Lock()
	defer m.Unlock()

	// use a reconcileDiff to compute which BgpServers must be created, removed
	// and reconciled.
	rd := newReconcileDiffV2(ciliumNode)

	if nodeObj == nil {
		m.withdrawAllV2(ctx, rd)
		return nil
	}

	l := m.Logger.WithFields(logrus.Fields{
		types.BGPNodeConfigLogField: nodeObj.Name,
	})

	err := rd.diff(m.BGPInstances, nodeObj)
	if err != nil {
		return err
	}

	if rd.empty() {
		l.Debug("BGP instance up-to-date with CiliumBGPNodeConfig")
		return nil
	}
	l.WithField("diff", rd.String()).Debug("Reconciling BGP instances")

	if len(rd.register) > 0 {
		if err := m.registerV2(ctx, rd); err != nil {
			return err
		}
	}
	if len(rd.withdraw) > 0 {
		m.withdrawV2(ctx, rd)
	}
	if len(rd.reconcile) > 0 {
		if err := m.reconcileV2(ctx, rd); err != nil {
			return err
		}
	}

	return nil
}

// registerV2 instantiates and configures BGP Instance(s) as instructed by the provided
// work diff.
func (m *BGPRouterManager) registerV2(ctx context.Context, rd *reconcileDiffV2) error {
	var (
		instancesWithError []string
		lastErr            error
	)
	for _, name := range rd.register {
		var config *v2alpha1api.CiliumBGPNodeInstance
		var ok bool
		if config, ok = rd.seen[name]; !ok {
			m.Logger.WithField(types.InstanceLogField, name).Debug("Work diff (add) contains unseen instance, skipping")
			instancesWithError = append(instancesWithError, name)
			lastErr = errors.New("unseen instance")
			continue
		}
		if rErr := m.registerBGPInstance(ctx, config, rd.ciliumNode); rErr != nil {
			// we'll log the error and attempt to register the next instance.
			m.Logger.WithField(types.InstanceLogField, name).WithError(rErr).Debug("Error registering new BGP instance")
			instancesWithError = append(instancesWithError, name)
			lastErr = rErr
		}
	}
	if len(instancesWithError) > 0 {
		return fmt.Errorf("error registering new BGP instances: %v (last error: %w)", instancesWithError, lastErr)
	}
	return nil
}

// registerBGPServer encapsulates the logic for instantiating a
// BgpInstance
func (m *BGPRouterManager) registerBGPInstance(ctx context.Context,
	c *v2alpha1api.CiliumBGPNodeInstance,
	ciliumNode *v2api.CiliumNode) error {

	l := m.Logger.WithFields(logrus.Fields{
		types.InstanceLogField: c.Name,
	})

	l.Info("Registering BGP instance")

	var localASN int64
	if c.LocalASN != nil {
		localASN = *c.LocalASN
	} else {
		// TODO for now we require a local ASN to be specified
		// remove this check once we support auto-ASN assignment.
		return fmt.Errorf("local ASN must be specified")
	}

	annoMap, err := agent.NewAnnotationMap(ciliumNode.Annotations)
	if err != nil {
		return fmt.Errorf("unable to parse local node annotations: %w", err)
	}

	// resolve local port from kubernetes annotations
	var localPort int32
	localPort = -1
	if attrs, ok := annoMap[localASN]; ok {
		if attrs.LocalPort != 0 {
			localPort = int32(attrs.LocalPort)
		}
	}

	routerID, err := annoMap.ResolveRouterID(localASN)
	if err != nil {
		if nodeIP := ciliumNode.GetIP(false); nodeIP == nil {
			return fmt.Errorf("failed to get cilium node IP %v: %w", nodeIP, err)
		} else {
			routerID = nodeIP.String()
		}
	}

	// override configuration via CiliumBGPNodeConfigOverride, it will take precedence over
	// the annotations.
	if c.LocalPort != nil {
		localPort = *c.LocalPort
	}

	if c.RouterID != nil {
		routerID = *c.RouterID
	}

	globalConfig := types.ServerParameters{
		Global: types.BGPGlobal{
			ASN:        uint32(localASN),
			RouterID:   routerID,
			ListenPort: localPort,
			RouteSelectionOptions: &types.RouteSelectionOptions{
				AdvertiseInactiveRoutes: true,
			},
		},
		StateNotification: make(types.StateNotificationCh, 1),
	}

	i, err := instance.NewBGPInstance(ctx, m.Logger.WithField(types.InstanceLogField, c.Name), globalConfig)
	if err != nil {
		return fmt.Errorf("failed to start BGP instance: %w", err)
	}

	// register with manager
	m.BGPInstances[c.Name] = i
	m.state.notifications[c.Name] = globalConfig.StateNotification

	// start consuming state notifications
	go m.trackInstanceStateChange(c.Name, globalConfig.StateNotification)

	if err = m.reconcileBGPConfigV2(ctx, i, c, ciliumNode); err != nil {
		return fmt.Errorf("failed initial reconciliation of BGP instance: %w", err)
	}

	l.Info("Successfully registered BGP instance")

	return err
}

// reconcileBGPConfigV2 will utilize the current set of ConfigReconcilerV2
// to push a BGP Instance to its desired configuration.
//
// Each reconcilier is responsible for getting the desired configuration from
// resource store and applying it to the BGP Instance.
func (m *BGPRouterManager) reconcileBGPConfigV2(ctx context.Context,
	i *instance.BGPInstance,
	newc *v2alpha1api.CiliumBGPNodeInstance,
	ciliumNode *v2api.CiliumNode) error {

	for _, r := range m.ConfigReconcilers {
		if err := r.Reconcile(ctx, reconcilerv2.ReconcileParams{
			BGPInstance:   i,
			DesiredConfig: newc,
			CiliumNode:    ciliumNode,
		}); err != nil {
			return err
		}
	}
	i.Config = newc
	return nil
}

// withdraw disconnects and removes BGP Instance(s) as instructed by the provided
// work diff.
func (m *BGPRouterManager) withdrawV2(ctx context.Context, rd *reconcileDiffV2) {
	for _, name := range rd.withdraw {
		var (
			i  *instance.BGPInstance
			ok bool
		)
		if i, ok = m.BGPInstances[name]; !ok {
			m.Logger.WithField(types.InstanceLogField, name).Warn("BGP instance marked for deletion but does not exist")
			continue
		}

		i.CancelCtx()
		i.Router.Stop()
		notifCh, exists := m.state.notifications[name]
		if exists {
			close(notifCh)
		}
		delete(m.BGPInstances, name)
		delete(m.state.notifications, name)
		m.Logger.WithField(types.InstanceLogField, name).Info("Removed BGP instance")
	}
}

// withdrawAll will disconnect and remove all currently registered BGP Instance(s).
//
// `rd` must be a newly created reconcileDiff which has not had its `Diff` method
// called.
func (m *BGPRouterManager) withdrawAllV2(ctx context.Context, rd *reconcileDiffV2) {
	if len(m.BGPInstances) == 0 {
		return
	}
	for name := range m.BGPInstances {
		rd.withdraw = append(rd.withdraw, name)
	}
	m.withdrawV2(ctx, rd)
}

// reconcile evaluates existing BGP Instance(s).
func (m *BGPRouterManager) reconcileV2(ctx context.Context, rd *reconcileDiffV2) error {
	var (
		instancesWithError []string
		lastErr            error
	)
	for _, name := range rd.reconcile {
		var (
			i    = m.BGPInstances[name]
			newc = rd.seen[name]
		)
		if i == nil {
			m.Logger.WithField(types.InstanceLogField, name).Error("BUG: BGP instance marked for reconciliation but missing from Manager") // really shouldn't happen, tagging as bug
			instancesWithError = append(instancesWithError, name)
			continue
		}
		if newc == nil {
			m.Logger.WithField(types.InstanceLogField, name).Error("BUG: BGP instance marked for reconciliation but missing from incoming configurations") // also really shouldn't happen
			instancesWithError = append(instancesWithError, name)
			continue
		}

		if err := m.reconcileBGPConfigV2(ctx, i, newc, rd.ciliumNode); err != nil {
			m.Logger.WithField(types.InstanceLogField, name).WithError(err).Debug("Error reconciling BGP instance")
			instancesWithError = append(instancesWithError, name)
			lastErr = err
		}
	}

	if len(instancesWithError) > 0 {
		return fmt.Errorf("error reconciling BGP instances: %v (last error: %w)", instancesWithError, lastErr)
	}
	return nil
}
