// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gobgp

import (
	"context"
	"fmt"
	"net"

	gobgp "github.com/osrg/gobgp/v3/api"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/bgpv1/agent"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	// ATTENTION:
	// All logs generated from this package will have the k/v
	// `subsys=bgp-control-plane`.
	//
	// Each log message will additionally contain the k/v
	// 'component=gobgp.{Struct}.{Method}' or 'component=gobgp.{Function}' to
	// provide further granularity on where the log is originating from.
	//
	// Every instantiated BgpServer will log with the k/v
	// `subsys=bgp-control-plane`, `component=gobgp.BgpServerInstance` and
	// `asn={Local ASN}`
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "bgp-control-plane")
)

// LocalASNMap maps local ASNs to their associated BgpServers and server
// configuration info.
type LocalASNMap map[int]*ServerWithConfig

// BGPRouterManager implements the pkg.bgpv1.agent.BGPRouterManager interface.
//
// This BGPRouterMananger utilizes the gobgp project to implement a BGP routing
// plane.
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
// and removed from the Mananger along with which servers must have their
// configurations reconciled.
//
// A set of ReconcilerConfigFunc(s), which usages are wrapped by the
// ReconcileBGPConfig function, reconcile individual features of a
// CiliumBGPPeeringConfig.
//
// Together, the high-level flow the manager takes is:
// - Instantiate a reconcilerDiff to compute which BgpServers to create, remove,
//   and reconcile
// - Create any BgpServers necessary, run ReconcilerConfigFuncs(s) on each
// - Run each ReconcilerConfigFunc, by way of ReconcileBGPConfig,
//   on any BgpServers marked for reconcile
//
// BgpServers are abstracted by the ServerWithConfig structure which provides a
// method set for low-level BGP operations.
type BGPRouterManager struct {
	Servers LocalASNMap
}

// NewBGPRouterManager constructs a GoBGP-backed BGPRouterManager.
//
// See NewBGPRouterManager for details.
func NewBGPRouterManager() *BGPRouterManager {
	return &BGPRouterManager{
		Servers: make(LocalASNMap),
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
func (m *BGPRouterManager) ConfigurePeers(ctx context.Context, policy *v2alpha1api.CiliumBGPPeeringPolicy, cstate *agent.ControlPlaneState) error {
	l := log.WithFields(
		logrus.Fields{
			"component": "gobgp.RouterManager.ConfigurePeers",
		},
	)

	// use a reconcileDiff to compute which BgpServers must be created, removed
	// and reconciled.
	rd := newReconcileDiff(cstate)

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
			"component": "gobgp.RouterManager.add",
		},
	)
	for _, asn := range rd.register {
		var config *v2alpha1api.CiliumBGPVirtualRouter
		var ok bool
		if config, ok = rd.seen[asn]; !ok {
			l.Errorf("Work diff (add) contains unseen ASN %v, skipping", asn)
			continue
		}
		if err := m.registerBGPServer(ctx, config, rd.state); err != nil {
			// we'll just log the error and attempt to register the next BgpServer.
			l.WithError(err).Errorf("Error while registering new BGP server for local ASN %v.", config.LocalASN)
		}
	}
	return nil
}

// registerBGPServer encapsulates the logic for instantiating a gobgp
// BgpServer, configuring it based on a CiliumBGPVirtualRouter, and
// registering it with the Manager.
//
// If this registration process fails the server will be stopped (if it was started)
// and deleted from our manager (if it was added).
func (m *BGPRouterManager) registerBGPServer(ctx context.Context, c *v2alpha1api.CiliumBGPVirtualRouter, cstate *agent.ControlPlaneState) error {
	l := log.WithFields(
		logrus.Fields{
			"component": "gobgp.RouterManager.registerBGPServer",
		},
	)

	l.Infof("Registering GoBGP servers for policy with local ASN %v", c.LocalASN)

	// ATTENTION: this defer handles cleaning up of a server if an error in
	// registration occurs. for this to work the below err variable must be
	// overwritten for the lengh of this method.
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

	// resolve local port from kubernetes annotations
	var localPort int32
	localPort = -1
	if attrs, ok := cstate.Annotations[c.LocalASN]; ok {
		if attrs.LocalPort != 0 {
			localPort = int32(attrs.LocalPort)
		}
	}

	// resolve router ID, if we have an annotation and it can be parsed into
	// a valid ipv4 address use this,
	//
	// if not determine if Cilium is configured with an IPv4 address, if so use
	// this.
	//
	// if neither, return an error, we cannot assign an router ID.
	var routerID string
	_, ok := cstate.Annotations[c.LocalASN]
	switch {
	case ok && !net.ParseIP(cstate.Annotations[c.LocalASN].RouterID).IsUnspecified():
		routerID = cstate.Annotations[c.LocalASN].RouterID
	case !cstate.IPv4.IsUnspecified():
		routerID = cstate.IPv4.String()
	default:
		return fmt.Errorf("router id not specified by annotation and no IPv4 address assigned by cilium, cannot resolve router id for virtual router with local ASN %v", c.LocalASN)
	}

	startReq := &gobgp.StartBgpRequest{
		Global: &gobgp.Global{
			Asn:        uint32(c.LocalASN),
			RouterId:   routerID,
			ListenPort: localPort,
			RouteSelectionOptions: &gobgp.RouteSelectionOptionsConfig{
				AdvertiseInactiveRoutes: true,
			},
		},
	}

	if s, err = NewServerWithConfig(ctx, startReq); err != nil {
		return fmt.Errorf("failed to start BGP server for config with local ASN %v: %w", c.LocalASN, err)
	}

	if err = ReconcileBGPConfig(ctx, m, s, c, cstate); err != nil {
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
			"component": "gobgp.RouterManager.remove",
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
			"component": "gobgp.RouterManager.reconcile",
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

		if err := ReconcileBGPConfig(ctx, m, sc, newc, rd.state); err != nil {
			l.WithError(err).Errorf("Encountered error reconciling virtual router with local ASN %v, shutting down this server", newc.LocalASN)
			sc.Server.Stop()
			delete(m.Servers, asn)
		}
	}
	return nil
}
