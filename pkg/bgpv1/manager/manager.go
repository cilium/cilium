// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"context"
	"fmt"
	"sort"

	"github.com/cilium/cilium/api/v1/models"
	restapi "github.com/cilium/cilium/api/v1/server/restapi/bgp"
	"github.com/cilium/cilium/pkg/bgpv1/agent"
	"github.com/cilium/cilium/pkg/bgpv1/api"
	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/hive/cell"
	v2api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/sirupsen/logrus"
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
type LocalASNMap map[int64]*ServerWithConfig

type bgpRouterManagerParams struct {
	cell.In

	Reconcilers []ConfigReconciler `group:"bgp-config-reconciler"`
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
type BGPRouterManager struct {
	lock.RWMutex
	Servers     LocalASNMap
	Reconcilers []ConfigReconciler
}

// NewBGPRouterManager constructs a GoBGP-backed BGPRouterManager.
//
// See BGPRouterManager for details.
func NewBGPRouterManager(params bgpRouterManagerParams) agent.BGPRouterManager {
	reconcilers := make(map[string]ConfigReconciler)
	for _, r := range params.Reconcilers {
		if r == nil {
			continue // reconciler not initialized
		}
		if existing, exists := reconcilers[r.Name()]; exists {
			if existing.Priority() == r.Priority() {
				log.Warnf("Skipping duplicate reconciler %s with the same priority (%d)", existing.Name(), existing.Priority())
				continue
			}
			if existing.Priority() < r.Priority() {
				log.Debugf("Skipping reconciler %s (priority %d) as it has lower priority than the existing one (%d)",
					r.Name(), r.Priority(), existing.Priority())
				continue
			}
			log.Debugf("Overriding existing reconciler %s (priority %d) with higher priority one (%d)",
				existing.Name(), existing.Priority(), r.Priority())
		}
		reconcilers[r.Name()] = r
	}

	var activeReconcilers []ConfigReconciler
	for _, r := range reconcilers {
		log.Debugf("Adding BGP reconciler: %v (priority %d)", r.Name(), r.Priority())
		activeReconcilers = append(activeReconcilers, r)
	}
	sort.Slice(activeReconcilers, func(i, j int) bool {
		return activeReconcilers[i].Priority() < activeReconcilers[j].Priority()
	})

	return &BGPRouterManager{
		Servers:     make(LocalASNMap),
		Reconcilers: activeReconcilers,
	}
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
			return fmt.Errorf("encountered error adding new BGP Servers: %v", err)
		}
	}
	if len(rd.withdraw) > 0 {
		if err := m.withdraw(ctx, rd); err != nil {
			return fmt.Errorf("encountered error removing existing BGP Servers: %v", err)
		}
	}
	if len(rd.reconcile) > 0 {
		if err := m.reconcile(ctx, rd); err != nil {
			return fmt.Errorf("encountered error reconciling existing BGP Servers: %v", err)
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

	// ATTENTION: this defer handles cleaning up of a server if an error in
	// registration occurs. for this to work the below err variable must be
	// overwritten for the length of this method.
	var err error
	var s *ServerWithConfig
	defer func() {
		if err != nil {
			if s != nil {
				s.Server.Stop()
			}
			delete(m.Servers, c.LocalASN) // optimistic delete
		}
	}()

	annoMap, err := agent.NewAnnotationMap(ciliumNode.Annotations)
	if err != nil {
		return fmt.Errorf("unable to parse local node's annotations: %v", err)
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

	if s, err = NewServerWithConfig(ctx, globalConfig); err != nil {
		return fmt.Errorf("failed to start BGP server for config with local ASN %v: %w", c.LocalASN, err)
	}

	if err = m.reconcileBGPConfig(ctx, s, c, ciliumNode); err != nil {
		return fmt.Errorf("failed initial reconciliation for peer config with local ASN %v: %w", c.LocalASN, err)
	}

	// register with manager
	m.Servers[c.LocalASN] = s
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
			s  *ServerWithConfig
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
			l.WithError(err).Errorf("Encountered error reconciling virtual router with local ASN %v, shutting down this server", newc.LocalASN)
			sc.Server.Stop()
			delete(m.Servers, asn)
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
	sc *ServerWithConfig,
	newc *v2alpha1api.CiliumBGPVirtualRouter,
	ciliumNode *v2api.CiliumNode) error {
	if sc.Config != nil {
		if sc.Config.LocalASN != newc.LocalASN {
			return fmt.Errorf("cannot reconcile two BgpServers with different local ASNs")
		}
	}
	for _, r := range m.Reconcilers {
		if err := r.Reconcile(ctx, ReconcileParams{
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

	var res []*models.BgpPeer

	for _, s := range m.Servers {
		getPeerResp, err := s.Server.GetPeerState(ctx)
		if err != nil {
			return nil, err
		}
		res = append(res, getPeerResp.Peers...)
	}
	return res, nil
}

// GetRoutes retrieves routes from the RIB of underlying router
func (m *BGPRouterManager) GetRoutes(ctx context.Context, params restapi.GetBgpRoutesParams) ([]*models.BgpRoute, error) {
	m.RLock()
	defer m.RUnlock()

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

	var res []*models.BgpRoute
	req, err := api.ToAgentGetRoutesRequest(params)
	if err != nil {
		return nil, err
	}

	for _, s := range m.Servers {
		if params.RouterAsn != nil && *params.RouterAsn != s.Config.LocalASN {
			continue // return routes matching provided router ASN only
		}
		rs, err := s.Server.GetRoutes(ctx, req)
		if err != nil {
			return nil, err
		}

		routes, err := api.ToAPIRoutes(rs.Routes, s.Config.LocalASN)
		if err != nil {
			return nil, err
		}

		res = append(res, routes...)
	}

	return res, nil
}

// GetRoutePolicies fetches BGP routing policies from underlying routing daemon.
func (m *BGPRouterManager) GetRoutePolicies(ctx context.Context, params restapi.GetBgpRoutePoliciesParams) ([]*models.BgpRoutePolicy, error) {
	m.RLock()
	defer m.RUnlock()

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

// Stop cleans up all servers, should be called at shutdown
func (m *BGPRouterManager) Stop() {
	m.Lock()
	defer m.Unlock()

	for _, s := range m.Servers {
		s.Server.Stop()
	}

	m.Servers = make(LocalASNMap)
}
