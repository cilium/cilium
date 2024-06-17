// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"context"
	"net/netip"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"

	"github.com/cilium/cilium/api/v1/models"
	v2alpha1api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

// BGPGlobal contains high level BGP configuration for given instance.
type BGPGlobal struct {
	ASN                   uint32
	RouterID              string
	ListenPort            int32 // When -1 gobgp won't listen on tcp:179
	RouteSelectionOptions *RouteSelectionOptions
}

// RouteSelectionOptions contains generic BGP route selection tuning parameters
type RouteSelectionOptions struct {
	// AdvertiseInactiveRoutes when set will advertise route even if it is not present in RIB
	AdvertiseInactiveRoutes bool
}

// Path is an object representing a single routing Path. It is an analogue of GoBGP's Path object,
// but only contains minimal fields required for Cilium usecases.
type Path struct {
	// read/write
	NLRI           bgp.AddrPrefixInterface
	PathAttributes []bgp.PathAttributeInterface
	Family         Family // can be empty, in which case it will be inferred from NLRI

	// readonly
	AgeNanoseconds int64 // time duration in nanoseconds since the Path was created
	Best           bool
	UUID           []byte // path identifier in underlying implementation
}

// NeighborRequest contains neighbor parameters used when enabling or disabling peer
type NeighborRequest struct {
	// Deprecated: field kept for backward compatibility.
	//
	// Both Neighbor and Peer should not be used at the same time.
	// Neighbor field is used in BGPv1 and Peer, PeerConfig fields are used in BGPv2.
	Neighbor *v2alpha1api.CiliumBGPNeighbor

	Peer       *v2alpha1api.CiliumBGPNodePeer
	PeerConfig *v2alpha1api.CiliumBGPPeerConfigSpec
	// Password is the "AuthSecret" in the Neighbor, fetched from a secret
	Password string
}

// SoftResetDirection defines the direction in which a BGP soft reset should be performed
type SoftResetDirection int

const (
	SoftResetDirectionIn SoftResetDirection = iota
	SoftResetDirectionOut
	SoftResetDirectionBoth
)

// ResetNeighborRequest contains parameters used when resetting a BGP peer
type ResetNeighborRequest struct {
	PeerAddress        string
	Soft               bool
	SoftResetDirection SoftResetDirection
	AdminCommunication string
}

// PathRequest contains parameters for advertising or withdrawing a Path
type PathRequest struct {
	Path *Path
}

// PathResponse contains response after advertising the Path, the returned Path can be used
// for withdrawing the Path (based on UUID set by the underlying implementation)
type PathResponse struct {
	Path *Path
}

// RoutePolicyPrefixMatch can be used to match a CIDR prefix in a routing policy.
// It can be used to perform exact prefix length matches (if CIDR.Bits() == PrefixLenMin == PrefixLenMax),
// or variable prefix length matches.
//
// +deepequal-gen=true
// +deepequal-gen:private-method=true
type RoutePolicyPrefixMatch struct {
	// CIDR is a prefix to match with.
	// +deepequal-gen=false
	CIDR netip.Prefix
	// PrefixLenMin is the minimal prefix length that will match if it falls under CIDR.
	PrefixLenMin int
	// PrefixLenMax is the maximal prefix length that will match if it falls under CIDR.
	PrefixLenMax int
}

// RoutePolicyConditions represent conditions of a policy statement.
//
// +deepequal-gen=true
type RoutePolicyConditions struct {
	// MatchNeighbors matches ANY of the provided BGP neighbor IP addresses. If empty matches all neighbors.
	MatchNeighbors []string
	// MatchPrefixes matches ANY of the provided prefixes. If empty matches all prefixes.
	MatchPrefixes []*RoutePolicyPrefixMatch
}

// RoutePolicyAction defines the action taken on a route matched by a routing policy.
type RoutePolicyAction int

const (
	// RoutePolicyActionNone does not affect processing of a route.
	// The policy evaluation continues with the next policy statements / other policies.
	RoutePolicyActionNone RoutePolicyAction = iota
	// RoutePolicyActionAccept accepts a route into the RIB / adjacency RIB.
	// No further policy statements / policies are evaluated for the route.
	RoutePolicyActionAccept
	// RoutePolicyActionReject rejects a route from the RIB / adjacency RIB.
	// No further policy statements / policies are evaluated for the route.
	RoutePolicyActionReject
)

// RoutePolicyActions define policy actions taken on route matched by a routing policy.
//
// +deepequal-gen=true
type RoutePolicyActions struct {
	// RouteAction defines an action taken on the matched route.
	RouteAction RoutePolicyAction
	// AddCommunities defines a list of BGP standard community values to be added to the matched route.
	// If empty, no communities will be added.
	AddCommunities []string
	// AddCommunities defines a list of BGP large community values to be added to the matched route.
	// If empty, no communities will be added.
	AddLargeCommunities []string
	// SetLocalPreference define a BGP local preference value to be set on the matched route.
	// If nil, no local preference is set.
	SetLocalPreference *int64
}

// RoutePolicyStatement represents a single statement of a routing RoutePolicy. It contains conditions for
// matching a route and actions taken if a route matches the conditions.
//
// +deepequal-gen=true
type RoutePolicyStatement struct {
	// Conditions of the statement. If ALL of them match a route, the Actions are taken on the route.
	Conditions RoutePolicyConditions
	// Actions define actions taken on a matched route.
	Actions RoutePolicyActions
}

// RoutePolicyType defines the type of routing policy.
type RoutePolicyType int

const (
	// RoutePolicyTypeExport represents export routing policy type (affecting how the routes from RIB are advertised to peers).
	RoutePolicyTypeExport RoutePolicyType = iota
	// RoutePolicyTypeImport represents import routing policy type (affecting how the routes are imported into RIB).
	RoutePolicyTypeImport
)

// RoutePolicy represents a BGP routing policy, also called "route map" in some BGP implementations.
// It can contain multiple Statements that are evaluated in the given order. Each Statement
// contains conditions for matching a route and actions taken if a route matches the conditions.
// Whenever a Statement matches a route and the action taken on it is to either accept or reject the route,
// the policy evaluation for the given route stops, and no further Statements nor other RoutePolicies are evaluated.
//
// +deepequal-gen=true
type RoutePolicy struct {
	// Name is a unique string identifier of the policy for the given router.
	Name string
	// RoutePolicyType is the type of the policy.
	Type RoutePolicyType
	// Statements is an ordered list of policy statements.
	Statements []*RoutePolicyStatement
}

// RoutePolicyRequest contains parameters for adding or removing a routing policy.
type RoutePolicyRequest struct {
	DefaultExportAction RoutePolicyAction
	Policy              *RoutePolicy
}

// GetPeerStateResponse contains state of peers configured in given instance
type GetPeerStateResponse struct {
	Peers []*models.BgpPeer
}

// GetBGPResponse contains BGP global parameters
type GetBGPResponse struct {
	Global BGPGlobal
}

// ServerParameters contains information for underlying bgp implementation layer to initializing BGP process.
type ServerParameters struct {
	Global BGPGlobal
}

// Family holds Address Family Indicator (AFI) and Subsequent Address Family Indicator for Multi-Protocol BGP
type Family struct {
	Afi  Afi
	Safi Safi
}

func (f Family) String() string {
	return f.Afi.String() + "-" + f.Safi.String()
}

// Route represents a single route in the RIB of underlying router
type Route struct {
	Prefix string
	Paths  []*Path
}

// TableType specifies the routing table type of underlying router
type TableType int

const (
	TableTypeUnknown TableType = iota
	TableTypeLocRIB
	TableTypeAdjRIBIn
	TableTypeAdjRIBOut
)

// ParseTableType parses s as a routing table type. If s is unknown,
// TableTypeUnknown is returned.
func ParseTableType(s string) TableType {
	switch s {
	case "loc-rib":
		return TableTypeLocRIB
	case "adj-rib-in":
		return TableTypeAdjRIBIn
	case "adj-rib-out":
		return TableTypeAdjRIBOut
	default:
		return TableTypeUnknown
	}
}

// GetRoutesRequest contains parameters for retrieving routes from the RIB of underlying router
type GetRoutesRequest struct {
	// TableType specifies a table type to retrieve
	TableType TableType

	// Family specifies an address family of the table
	Family Family

	// Neighbor specifies which neighbor's table to retrieve. Must be
	// specified when TableTypeAdjRIBIn/Out is specified in TableType.
	Neighbor netip.Addr
}

// GetRoutesResponse contains routes retrieved from the RIB of underlying router
type GetRoutesResponse struct {
	Routes []*Route
}

// GetRoutePoliciesResponse contains route policies retrieved from the underlying router
type GetRoutePoliciesResponse struct {
	Policies []*RoutePolicy
}

// Router is vendor-agnostic cilium bgp configuration layer. Parameters of this layer
// are standard BGP RFC complaint and not specific to any underlying implementation.
type Router interface {
	Stop()

	// AddNeighbor configures BGP peer
	AddNeighbor(ctx context.Context, n NeighborRequest) error

	// UpdateNeighbor updates BGP peer
	UpdateNeighbor(ctx context.Context, n NeighborRequest) error

	// RemoveNeighbor removes BGP peer
	RemoveNeighbor(ctx context.Context, n NeighborRequest) error

	// ResetNeighbor resets BGP peering with the provided neighbor address
	ResetNeighbor(ctx context.Context, r ResetNeighborRequest) error

	// AdvertisePath advertises BGP Path to all configured peers
	AdvertisePath(ctx context.Context, p PathRequest) (PathResponse, error)

	// WithdrawPath  removes BGP Path from all peers
	WithdrawPath(ctx context.Context, p PathRequest) error

	// AddRoutePolicy adds a new routing policy into the underlying router.
	AddRoutePolicy(ctx context.Context, p RoutePolicyRequest) error

	// RemoveRoutePolicy removes a routing policy from the underlying router.
	RemoveRoutePolicy(ctx context.Context, p RoutePolicyRequest) error

	// GetPeerState returns status of BGP peers
	GetPeerState(ctx context.Context) (GetPeerStateResponse, error)

	// GetRoutes retrieves routes from the RIB of underlying router
	GetRoutes(ctx context.Context, r *GetRoutesRequest) (*GetRoutesResponse, error)

	// GetRoutePolicies retrieves route policies from the underlying router
	GetRoutePolicies(ctx context.Context) (*GetRoutePoliciesResponse, error)

	// GetBGP returns configured BGP global parameters
	GetBGP(ctx context.Context) (GetBGPResponse, error)
}
