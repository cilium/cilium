// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gobgp

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	gobgp "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/server"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

const (
	wildcardIPv4Addr = "0.0.0.0"
	wildcardIPv6Addr = "::"

	// idleHoldTimeAfterResetSeconds defines time BGP session will stay idle after neighbor reset.
	idleHoldTimeAfterResetSeconds = 5

	// globalPolicyAssignmentName is a special GoBGP policy assignment name that refers to the router-global policy
	globalPolicyAssignmentName = "global"
)

var (
	// GoBGPIPv6Family is a read-only pointer to a gobgp.Family structure
	// representing IPv6 address family.
	GoBGPIPv6Family = &gobgp.Family{
		Afi:  gobgp.Family_AFI_IP6,
		Safi: gobgp.Family_SAFI_UNICAST,
	}
	// GoBGPIPv4Family is a read-only pointer to a gobgp.Family structure
	// representing IPv4 address family.
	GoBGPIPv4Family = &gobgp.Family{
		Afi:  gobgp.Family_AFI_IP,
		Safi: gobgp.Family_SAFI_UNICAST,
	}
	// The default S/Afi pair to use if not provided by the user.
	defaultSafiAfi = []*gobgp.AfiSafi{
		{
			Config: &gobgp.AfiSafiConfig{
				Family: GoBGPIPv4Family,
			},
		},
		{
			Config: &gobgp.AfiSafiConfig{
				Family: GoBGPIPv6Family,
			},
		},
	}
)

// GoBGPServer is wrapper on top of go bgp server implementation
type GoBGPServer struct {
	logger *logrus.Entry

	// asn is local AS number
	asn uint32

	// a gobgp backed BgpServer configured in accordance to the accompanying
	// CiliumBGPVirtualRouter configuration.
	server *server.BgpServer
}

// NewGoBGPServer returns instance of go bgp router wrapper.
func NewGoBGPServer(ctx context.Context, log *logrus.Entry, params types.ServerParameters) (types.Router, error) {
	logger := NewServerLogger(log.Logger, LogParams{
		AS:        params.Global.ASN,
		Component: "gobgp.BgpServerInstance",
		SubSys:    "bgp-control-plane",
	})

	s := server.NewBgpServer(server.LoggerOption(logger))
	go s.Serve()

	startReq := &gobgp.StartBgpRequest{
		Global: &gobgp.Global{
			Asn:        params.Global.ASN,
			RouterId:   params.Global.RouterID,
			ListenPort: params.Global.ListenPort,
		},
	}

	if params.Global.RouteSelectionOptions != nil {
		startReq.Global.RouteSelectionOptions = &gobgp.RouteSelectionOptionsConfig{
			AdvertiseInactiveRoutes: params.Global.RouteSelectionOptions.AdvertiseInactiveRoutes,
		}
	}

	if err := s.StartBgp(ctx, startReq); err != nil {
		return nil, fmt.Errorf("failed starting BGP server: %w", err)
	}

	// will log out any peer changes.
	watchRequest := &gobgp.WatchEventRequest{
		Peer: &gobgp.WatchEventRequest_Peer{},
	}
	err := s.WatchEvent(ctx, watchRequest, func(r *gobgp.WatchEventResponse) {
		if p := r.GetPeer(); p != nil && p.Type == gobgp.WatchEventResponse_PeerEvent_STATE {
			logger.l.Info(p)
		}
	})
	if err != nil {
		return nil, fmt.Errorf("failed to configure logging for virtual router with local-asn %v: %w", startReq.Global.Asn, err)
	}

	return &GoBGPServer{
		logger: log,
		asn:    params.Global.ASN,
		server: s,
	}, nil
}

// AddNeighbor will add the CiliumBGPNeighbor to the gobgp.BgpServer, creating
// a BGP peering connection.
func (g *GoBGPServer) AddNeighbor(ctx context.Context, n types.NeighborRequest) error {
	peer, _, err := g.getPeerConfig(ctx, n, false)
	if err != nil {
		return err
	}
	peerReq := &gobgp.AddPeerRequest{
		Peer: peer,
	}
	if err = g.server.AddPeer(ctx, peerReq); err != nil {
		return fmt.Errorf("failed while adding peer %v:%v with ASN %v: %w", n.Neighbor.PeerAddress, *n.Neighbor.PeerPort, n.Neighbor.PeerASN, err)
	}
	return nil
}

// UpdateNeighbor will update the existing CiliumBGPNeighbor in the gobgp.BgpServer.
func (g *GoBGPServer) UpdateNeighbor(ctx context.Context, n types.NeighborRequest) error {
	peer, needsHardReset, err := g.getPeerConfig(ctx, n, true)
	if err != nil {
		return err
	}

	// update peer config
	peerReq := &gobgp.UpdatePeerRequest{
		Peer: peer,
	}
	updateRes, err := g.server.UpdatePeer(ctx, peerReq)
	if err != nil {
		return fmt.Errorf("failed while updating peer %v:%v with ASN %v: %w", n.Neighbor.PeerAddress, *n.Neighbor.PeerPort, n.Neighbor.PeerASN, err)
	}

	// perform full / soft peer reset if necessary
	if needsHardReset || updateRes.NeedsSoftResetIn {
		g.logger.Infof("Resetting peer %s:%v (ASN %d) due to a config change", peer.Conf.NeighborAddress, *n.Neighbor.PeerPort, peer.Conf.PeerAsn)
		resetReq := &gobgp.ResetPeerRequest{
			Address:       peer.Conf.NeighborAddress,
			Communication: "Peer configuration changed",
		}
		if !needsHardReset {
			resetReq.Soft = true
			resetReq.Direction = gobgp.ResetPeerRequest_IN
		}
		if err = g.server.ResetPeer(ctx, resetReq); err != nil {
			return fmt.Errorf("failed while resetting peer %v:%v in ASN %v: %w", n.Neighbor.PeerAddress, *n.Neighbor.PeerPort, n.Neighbor.PeerASN, err)
		}
	}

	return nil
}

// convertBGPNeighborSAFI will convert a slice of CiliumBGPFamily to a slice of
// gobgp.AfiSafi.
//
// Our internal S/Afi types use the same integer values as the gobgp library,
// so we can simply cast our types into the corresponding gobgp types.
func convertBGPNeighborSAFI(fams []v2alpha1.CiliumBGPFamily) ([]*gobgp.AfiSafi, error) {
	if len(fams) == 0 {
		return defaultSafiAfi, nil
	}

	out := make([]*gobgp.AfiSafi, 0, len(fams))
	for _, fam := range fams {
		var safi types.Safi
		var afi types.Afi
		if err := safi.FromString(fam.Safi); err != nil {
			return out, fmt.Errorf("failed to parse Safi: %w", err)
		}
		if err := afi.FromString(fam.Afi); err != nil {
			return out, fmt.Errorf("failed to parse Afi: %w", err)
		}
		out = append(out, &gobgp.AfiSafi{
			Config: &gobgp.AfiSafiConfig{
				Family: &gobgp.Family{
					Afi:  gobgp.Family_Afi(afi),
					Safi: gobgp.Family_Safi(safi),
				},
			},
		})
	}
	return out, nil
}

// getPeerConfig returns GoBGP Peer configuration for the provided CiliumBGPNeighbor.
func (g *GoBGPServer) getPeerConfig(ctx context.Context, n types.NeighborRequest, isUpdate bool) (peer *gobgp.Peer, needsReset bool, err error) {
	// cilium neighbor uses prefix string, gobgp neighbor uses IP string, convert.
	prefix, err := netip.ParsePrefix(n.Neighbor.PeerAddress)
	if err != nil {
		// unlikely, we validate this on CR write to k8s api.
		return peer, needsReset, fmt.Errorf("failed to parse PeerAddress: %w", err)
	}
	peerAddr := prefix.Addr()
	peerPort := uint32(*n.Neighbor.PeerPort)

	var existingPeer *gobgp.Peer
	if isUpdate {
		// If this is an update, try retrieving the existing Peer.
		// This is necessary as many Peer fields are defaulted internally in GoBGP,
		// and if they were not set, the update would always cause BGP peer reset.
		// This will not fail if the peer is not found for whatever reason.
		existingPeer, err = g.getExistingPeer(ctx, peerAddr, uint32(n.Neighbor.PeerASN))
		if err != nil {
			return peer, needsReset, fmt.Errorf("failed retrieving peer: %w", err)
		}
		// use only necessary parts of the existing peer struct
		peer = &gobgp.Peer{
			Conf:      existingPeer.Conf,
			Transport: existingPeer.Transport,
		}
		// Update the peer port if needed.
		if existingPeer.Transport.RemotePort != peerPort {
			peer.Transport.RemotePort = peerPort
		}

		// Update the password if needed.
		if existingPeer.Conf.AuthPassword != n.Password {
			peer.Conf.AuthPassword = n.Password
		}

	} else {
		// Create a new peer
		peer = &gobgp.Peer{
			Conf: &gobgp.PeerConf{
				NeighborAddress: peerAddr.String(),
				PeerAsn:         uint32(n.Neighbor.PeerASN),
				AuthPassword:    n.Password,
			},
			Transport: &gobgp.Transport{
				RemotePort: peerPort,
			},
		}
	}

	peer.AfiSafis, err = convertBGPNeighborSAFI(n.Neighbor.Families)
	if err != nil {
		return peer, needsReset, fmt.Errorf("failed to convert CiliumBGPNeighbor Families to gobgp AfiSafi: %w", err)
	}

	// As GoBGP defaulting of peer's Transport.LocalAddress follows different paths
	// when calling AddPeer / UpdatePeer / ListPeer, we set it explicitly to a wildcard address
	// based on peer's address family, to not cause unnecessary connection resets upon update.
	if peerAddr.Is4() {
		peer.Transport.LocalAddress = wildcardIPv4Addr
	} else {
		peer.Transport.LocalAddress = wildcardIPv6Addr
	}

	// Enable multi-hop for eBGP if non-zero TTL is provided
	if g.asn != uint32(n.Neighbor.PeerASN) && *n.Neighbor.EBGPMultihopTTL > 1 {
		peer.EbgpMultihop = &gobgp.EbgpMultihop{
			Enabled:     true,
			MultihopTtl: uint32(*n.Neighbor.EBGPMultihopTTL),
		}
	}

	if peer.Timers == nil {
		peer.Timers = &gobgp.Timers{}
	}
	peer.Timers.Config = &gobgp.TimersConfig{
		ConnectRetry:           uint64(*n.Neighbor.ConnectRetryTimeSeconds),
		HoldTime:               uint64(*n.Neighbor.HoldTimeSeconds),
		KeepaliveInterval:      uint64(*n.Neighbor.KeepAliveTimeSeconds),
		IdleHoldTimeAfterReset: idleHoldTimeAfterResetSeconds,
	}

	// populate graceful restart config
	if peer.GracefulRestart == nil {
		peer.GracefulRestart = &gobgp.GracefulRestart{}
	}
	if n.Neighbor.GracefulRestart != nil && n.Neighbor.GracefulRestart.Enabled {
		peer.GracefulRestart.Enabled = true
		peer.GracefulRestart.RestartTime = uint32(*n.Neighbor.GracefulRestart.RestartTimeSeconds)
		peer.GracefulRestart.NotificationEnabled = true
		peer.GracefulRestart.LocalRestarting = true
	}

	for _, afiConf := range peer.AfiSafis {
		if afiConf.MpGracefulRestart == nil {
			afiConf.MpGracefulRestart = &gobgp.MpGracefulRestart{}
		}
		afiConf.MpGracefulRestart.Config = &gobgp.MpGracefulRestartConfig{
			Enabled: peer.GracefulRestart.Enabled,
		}
	}

	if isUpdate {
		// In some cases, we want to perform full session reset on update even if GoBGP would not perform it.
		// An example of that is updating timer parameters that are negotiated during the session setup.
		// As we provide declarative API (CRD), we want this config to be applied on existing sessions
		// immediately, therefore we need full session reset.
		needsReset = existingPeer != nil &&
			(peer.Timers.Config.HoldTime != existingPeer.Timers.Config.HoldTime ||
				peer.Timers.Config.KeepaliveInterval != existingPeer.Timers.Config.KeepaliveInterval)
	}

	return peer, needsReset, err
}

// getExistingPeer returns the existing GoBGP Peer matching provided peer address and ASN.
// If no such peer can be found, error is returned.
func (g *GoBGPServer) getExistingPeer(ctx context.Context, peerAddr netip.Addr, peerASN uint32) (*gobgp.Peer, error) {
	var res *gobgp.Peer
	fn := func(peer *gobgp.Peer) {
		pIP, err := netip.ParseAddr(peer.Conf.NeighborAddress)
		if err == nil && pIP == peerAddr && peer.Conf.PeerAsn == peerASN {
			res = peer
		}
	}

	err := g.server.ListPeer(ctx, &gobgp.ListPeerRequest{Address: peerAddr.String()}, fn)
	if err != nil {
		return nil, fmt.Errorf("listing peers failed: %w", err)
	}
	if res == nil {
		return nil, fmt.Errorf("could not find existing peer with ASN: %d and IP: %s", peerASN, peerAddr)
	}
	return res, nil
}

// RemoveNeighbor will remove the CiliumBGPNeighbor from the gobgp.BgpServer,
// disconnecting the BGP peering connection.
func (g *GoBGPServer) RemoveNeighbor(ctx context.Context, n types.NeighborRequest) error {
	// cilium neighbor uses prefix string, gobgp neighbor uses IP string, convert.
	prefix, err := netip.ParsePrefix(n.Neighbor.PeerAddress)
	if err != nil {
		// unlikely, we validate this on CR write to k8s api.
		return fmt.Errorf("failed to parse PeerAddress: %w", err)
	}
	peerReq := &gobgp.DeletePeerRequest{
		Address: prefix.Addr().String(),
	}
	if err := g.server.DeletePeer(ctx, peerReq); err != nil {
		return fmt.Errorf("failed while reconciling neighbor %v %v: %w", n.Neighbor.PeerAddress, n.Neighbor.PeerASN, err)
	}
	return nil
}

// ResetNeighbor resets BGP peering with the provided neighbor address.
func (g *GoBGPServer) ResetNeighbor(ctx context.Context, r types.ResetNeighborRequest) error {
	// for this request we need a peer address without prefix
	peerAddr := r.PeerAddress
	if p, err := netip.ParsePrefix(r.PeerAddress); err == nil {
		peerAddr = p.Addr().String()
	}

	resetReq := &gobgp.ResetPeerRequest{
		Address:       peerAddr,
		Communication: r.AdminCommunication,
	}
	if r.Soft {
		resetReq.Soft = true
		resetReq.Direction = toGoBGPSoftResetDirection(r.SoftResetDirection)
	}
	if err := g.server.ResetPeer(ctx, resetReq); err != nil {
		return fmt.Errorf("failed while resetting peer %s: %w", r.PeerAddress, err)
	}
	return nil
}

// AdvertisePath will advertise the provided Path to any existing and all
// subsequently added Neighbors currently peered with this BgpServer.
//
// It is an error to advertise an IPv6 path when no IPv6 address is configured
// on this Cilium node, selfsame for IPv4.
//
// A Path is returned which may be passed to WithdrawPath to stop advertising the Path.
func (g *GoBGPServer) AdvertisePath(ctx context.Context, p types.PathRequest) (types.PathResponse, error) {
	gobgpPath, err := ToGoBGPPath(p.Path)
	if err != nil {
		return types.PathResponse{}, fmt.Errorf("failed converting Path to %v: %w", p.Path.NLRI, err)
	}

	resp, err := g.server.AddPath(ctx, &gobgp.AddPathRequest{Path: gobgpPath})
	if err != nil {
		return types.PathResponse{}, fmt.Errorf("failed adding Path to %v: %w", gobgpPath.Nlri, err)
	}

	agentPath, err := ToAgentPath(gobgpPath)
	if err != nil {
		return types.PathResponse{}, fmt.Errorf("failed converting Path to %v: %w", gobgpPath.Nlri, err)
	}
	agentPath.UUID = resp.Uuid

	return types.PathResponse{
		Path: agentPath,
	}, err
}

// WithdrawPath withdraws a Path produced by AdvertisePath from this BgpServer.
func (g *GoBGPServer) WithdrawPath(ctx context.Context, p types.PathRequest) error {
	err := g.server.DeletePath(ctx, &gobgp.DeletePathRequest{
		Uuid: p.Path.UUID,
	})
	return err
}

// AddRoutePolicy adds a new routing policy into the global policies of the server.
//
// The same RoutePolicy can be later passed to RemoveRoutePolicy to remove it from the
// global policies of the server.
//
// Note that we use the global server policies here, as per-neighbor policies can be used only
// in the route-server mode of GoBGP, which we are not using in Cilium.

// AddRoutePolicy adds a new routing policy into the global policies of the server.
func (g *GoBGPServer) AddRoutePolicy(ctx context.Context, r types.RoutePolicyRequest) error {
	if r.Policy == nil {
		return fmt.Errorf("nil policy in the RoutePolicyRequest")
	}
	policy, definedSets := toGoBGPPolicy(r.Policy)

	for i, ds := range definedSets {
		err := g.server.AddDefinedSet(ctx, &gobgp.AddDefinedSetRequest{DefinedSet: ds})
		if err != nil {
			g.deleteDefinedSets(ctx, definedSets[:i]) // clean up already created defined sets
			return fmt.Errorf("failed adding policy defined set %s: %w", ds.Name, err)
		}
	}

	err := g.server.AddPolicy(ctx, &gobgp.AddPolicyRequest{Policy: policy})
	if err != nil {
		g.deleteDefinedSets(ctx, definedSets) // clean up defined sets
		return fmt.Errorf("failed adding policy %s: %w", policy.Name, err)
	}

	// Note that we are using global policy assignment here (per-neighbor policies work only in the route-server mode)
	assignment := g.getGlobalPolicyAssignment(policy, r.Policy.Type)
	err = g.server.AddPolicyAssignment(ctx, &gobgp.AddPolicyAssignmentRequest{Assignment: assignment})
	if err != nil {
		g.deletePolicy(ctx, policy)           // clean up policy
		g.deleteDefinedSets(ctx, definedSets) // clean up defined sets
		return fmt.Errorf("failed adding policy assignment %s: %w", assignment.Name, err)
	}

	return nil
}

// RemoveRoutePolicy removes a routing policy from the global policies of the server.
func (g *GoBGPServer) RemoveRoutePolicy(ctx context.Context, r types.RoutePolicyRequest) error {
	if r.Policy == nil {
		return fmt.Errorf("nil policy in the RoutePolicyRequest")
	}
	policy, definedSets := toGoBGPPolicy(r.Policy)

	assignment := g.getGlobalPolicyAssignment(policy, r.Policy.Type)
	err := g.server.DeletePolicyAssignment(ctx, &gobgp.DeletePolicyAssignmentRequest{Assignment: assignment})
	if err != nil {
		return fmt.Errorf("failed deleting policy assignment %s: %w", assignment.Name, err)
	}

	err = g.deletePolicy(ctx, policy)
	if err != nil {
		return err
	}

	err = g.deleteDefinedSets(ctx, definedSets)
	if err != nil {
		return err
	}

	return nil
}

func (g *GoBGPServer) getGlobalPolicyAssignment(policy *gobgp.Policy, policyType types.RoutePolicyType) *gobgp.PolicyAssignment {
	return &gobgp.PolicyAssignment{
		Name:          globalPolicyAssignmentName,
		Direction:     toGoBGPPolicyDirection(policyType),
		DefaultAction: gobgp.RouteAction_NONE, // no change to the default action
		Policies:      []*gobgp.Policy{policy},
	}
}

func (g *GoBGPServer) deletePolicy(ctx context.Context, policy *gobgp.Policy) error {
	req := &gobgp.DeletePolicyRequest{
		Policy:             policy,
		PreserveStatements: false, // delete all statements as well
		All:                true,  // clean up completely (without this, policy name would still exist internally)
	}
	err := g.server.DeletePolicy(ctx, req)
	if err != nil {
		return fmt.Errorf("failed deleting policy %s: %w", policy.Name, err)
	}
	return nil
}

func (g *GoBGPServer) deleteDefinedSets(ctx context.Context, definedSets []*gobgp.DefinedSet) error {
	var errs error
	for _, ds := range definedSets {
		req := &gobgp.DeleteDefinedSetRequest{
			DefinedSet: ds,
			All:        true, // clean up completely (without this, defined set name would still exist internally)
		}
		err := g.server.DeleteDefinedSet(ctx, req)
		if err != nil {
			// log and store the error, but continue cleanup with next defined sets
			errs = errors.Join(errs, fmt.Errorf("failed deleting defined set %s: %w", ds.Name, err))
		}
	}
	if errs != nil {
		g.logger.WithError(errs).Error("Error by deleting policy defined sets")
	}
	return errs
}

// Stop closes gobgp server
func (g *GoBGPServer) Stop() {
	if g.server != nil {
		g.server.Stop()
	}
}
