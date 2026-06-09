// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gobgp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	gobgp "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/apiutil"
	"github.com/osrg/gobgp/v4/pkg/server"

	"github.com/cilium/cilium/pkg/bgp/types"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

const (
	wildcardIPv4Addr = "0.0.0.0"
	wildcardIPv6Addr = "::"

	// idleHoldTimeAfterResetSeconds defines time BGP session will stay idle after neighbor reset.
	idleHoldTimeAfterResetSeconds = 5

	// globalAllowLocalPolicyName is the GoBGP policy that permits local routes that overrides
	// the default reject import policy which rejects paths announced toward Cilium from external peers.
	globalAllowLocalPolicyName = "allow-local"
	// globalAllowLocalPolicyStatementName is the name of the statement in the global allow-local policy
	globalAllowLocalPolicyStatementName = "accept-local"
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
	// allowLocalPolicy is a GoBGP policy which allows local routes
	allowLocalPolicy = &gobgp.Policy{
		Name: globalAllowLocalPolicyName,
		Statements: []*gobgp.Statement{
			{
				Name: scopedPolicyStatementName(globalAllowLocalPolicyName, globalAllowLocalPolicyStatementName),
				Conditions: &gobgp.Conditions{
					RouteType: gobgp.Conditions_ROUTE_TYPE_LOCAL,
				},
				Actions: &gobgp.Actions{
					RouteAction: gobgp.RouteAction_ROUTE_ACTION_ACCEPT,
				},
			},
		},
	}
	// The default S/Afi pair to use if not provided by the user.
	defaultAfiSafi = []*gobgp.AfiSafi{
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
	logger *slog.Logger

	// asn is local AS number
	asn uint32

	// a gobgp backed BgpServer configured in accordance to the accompanying
	// CiliumBGPVirtualRouter configuration.
	server *server.BgpServer

	// stopping is a flag to indicate if the server is stopping.
	stopping  bool
	stopMutex lock.Mutex
}

// NewGoBGPServer returns instance of go bgp router wrapper.
func NewGoBGPServer(ctx context.Context, log *slog.Logger, params types.ServerParameters) (types.Router, error) {
	logger := log.With(
		types.ComponentLogField, "gobgp-server",
		types.LocalASNLogField, params.Global.ASN,
	)

	s := server.NewBgpServer(server.LoggerOption(logger, nil))
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

	gobgpSrv := &GoBGPServer{
		logger: logger,
		asn:    params.Global.ASN,
		server: s,
	}

	// Reject all paths announced toward Cilium from external peers. This first step configures an
	// "allow" policy for local routes. It was observed during testing that global policies are also
	// applied to local routes, which we need to permit.
	if err := gobgpSrv.server.AddPolicy(ctx, &gobgp.AddPolicyRequest{Policy: allowLocalPolicy}); err != nil {
		return nil, fmt.Errorf("failed to add %s policy: %w", allowLocalPolicy.Name, err)
	}

	// Reject all paths announced toward Cilium from external peers. This step configures the actual
	// import policy.
	err := gobgpSrv.server.SetPolicyAssignment(ctx, &gobgp.SetPolicyAssignmentRequest{
		Assignment: &gobgp.PolicyAssignment{
			Name:          globalPolicyAssignmentName,
			Direction:     gobgp.PolicyDirection_POLICY_DIRECTION_IMPORT,
			DefaultAction: gobgp.RouteAction_ROUTE_ACTION_REJECT,
			Policies:      []*gobgp.Policy{allowLocalPolicy},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed configuring BGP server's global import policy: %w", err)
	}

	// will log out any peer changes
	peerCallback := func(p *apiutil.WatchEventMessage_PeerEvent, _ time.Time) {
		if p.Type == apiutil.PEER_EVENT_STATE {
			gobgpSrv.stopMutex.Lock()
			defer gobgpSrv.stopMutex.Unlock()

			if gobgpSrv.stopping {
				return
			}

			logger.Debug("Peer state change", types.PeerLogField, p)

			// if channel is nil (e.g. in tests) below code will not block and will act as a no-op.
			select {
			case params.StateNotification <- struct{}{}:
			default:
			}
		}
	}
	// will trigger state notifications upon route changes
	routeCallback := func(_ []*apiutil.Path, _ time.Time) {
		gobgpSrv.stopMutex.Lock()
		defer gobgpSrv.stopMutex.Unlock()

		if gobgpSrv.stopping {
			return
		}

		logger.Debug("Route event received")

		// if channel is nil (e.g. in tests) below code will not block and will act as a no-op.
		select {
		case params.StateNotification <- struct{}{}:
		default:
		}
	}

	err = s.WatchEvent(ctx,
		server.WatchEventMessageCallbacks{
			OnPeerUpdate: peerCallback,
			OnPathUpdate: routeCallback,
		},
		server.WatchPeer(),
		server.WatchPostUpdate(true, "", ""),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to configure event watching for virtual router with local-asn %v: %w", startReq.Global.Asn, err)
	}

	return gobgpSrv, nil
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

	resp, err := g.server.AddPath(apiutil.AddPathRequest{Paths: []*apiutil.Path{gobgpPath}})
	if err != nil {
		return types.PathResponse{}, fmt.Errorf("failed adding Path to %v: %w", gobgpPath.Nlri, err)
	}

	agentPath, err := ToAgentPath(gobgpPath)
	if err != nil {
		return types.PathResponse{}, fmt.Errorf("failed converting Path to %v: %w", gobgpPath.Nlri, err)
	}
	if len(resp) > 0 {
		agentPath.UUID, err = resp[0].UUID.MarshalBinary()
		if err != nil {
			return types.PathResponse{}, fmt.Errorf("failed marshalling UUID to %v: %w", gobgpPath.Nlri, err)
		}
	} else {
		return types.PathResponse{}, fmt.Errorf("empty AddPath reply for %v", gobgpPath.Nlri)
	}

	return types.PathResponse{
		Path: agentPath,
	}, err
}

// WithdrawPath withdraws a Path produced by AdvertisePath from this BgpServer.
func (g *GoBGPServer) WithdrawPath(ctx context.Context, p types.PathRequest) error {
	id, err := uuid.FromBytes(p.Path.UUID)
	if err != nil {
		return fmt.Errorf("failed converting UUID %v: %w", p.Path.UUID, err)
	}
	err = g.server.DeletePath(apiutil.DeletePathRequest{
		UUIDs: []uuid.UUID{id},
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
	assignment := g.getGlobalPolicyAssignment(policy, r.Policy.Type, r.DefaultExportAction)
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

	assignment := g.getGlobalPolicyAssignment(policy, r.Policy.Type, r.DefaultExportAction)
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

func (g *GoBGPServer) getGlobalPolicyAssignment(policy *gobgp.Policy, policyType types.RoutePolicyType, defaultAction types.RoutePolicyAction) *gobgp.PolicyAssignment {
	return &gobgp.PolicyAssignment{
		Name:          globalPolicyAssignmentName,
		Direction:     toGoBGPPolicyDirection(policyType),
		DefaultAction: toGoBGPRouteAction(defaultAction),
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
		g.logger.Error("Error by deleting policy defined sets", logfields.Error, errs)
	}
	return errs
}

// Stop closes gobgp server
func (g *GoBGPServer) Stop(ctx context.Context, r types.StopRequest) {
	g.stopMutex.Lock()
	defer g.stopMutex.Unlock()

	g.stopping = true

	if g.server != nil {
		if r.FullDestroy {
			// destroys all resources, but sends notification to all peers (breaks Graceful Restart)
			g.server.Stop()
		} else {
			// stops BGP instance only, does not send notification to Graceful Restart -enabled peers
			err := g.server.StopBgp(ctx, &gobgp.StopBgpRequest{AllowGracefulRestart: true})
			if err != nil {
				g.logger.Error("Error stopping bgp server", logfields.Error, err)
			}
		}
	}
}
