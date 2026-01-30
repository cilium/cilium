// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"

	"github.com/cilium/cilium/api/v1/models"
)

// BGP metric labels
const (
	LabelClusterConfig = "bgp_cluster_config"
	LabelVRouter       = "vrouter"
	LabelNeighbor      = "neighbor"
	LabelNeighborAsn   = "neighbor_asn"
	LabelAfi           = "afi"
	LabelSafi          = "safi"
	LabelResourceKind  = "resource_kind"
	LabelResourceName  = "resource_name"

	MetricsSubsystem                  = "bgp_control_plane"
	MetricReconcileErrorsTotal        = "reconcile_errors_total"
	MetricReconcileRunDurationSeconds = "reconcile_run_duration_seconds"
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

// StateNotificationCh is a channel used to notify the state of the BGP instance has changed
type StateNotificationCh chan struct{}

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
	SourceASN      uint32
}

// Neighbor is an object representing a single BGP neighbor. It is an analogue
// of GoBGP's Peer object, but only contains minimal fields required for Cilium
// usecases.
type Neighbor struct {
	Name            string
	Address         netip.Addr
	ASN             uint32
	AuthPassword    string
	EbgpMultihop    *NeighborEbgpMultihop
	Timers          *NeighborTimers
	Transport       *NeighborTransport
	GracefulRestart *NeighborGracefulRestart
	AfiSafis        []*Family
}

type NeighborTransport struct {
	LocalAddress string
	LocalPort    uint32
	RemotePort   uint32
}

type NeighborEbgpMultihop struct {
	TTL uint32
}

type NeighborTimers struct {
	ConnectRetry      uint64
	HoldTime          uint64
	KeepaliveInterval uint64
}

type NeighborGracefulRestart struct {
	Enabled     bool
	RestartTime uint32
}

// SoftResetDirection defines the direction in which a BGP soft reset should be performed
type SoftResetDirection int

const (
	SoftResetDirectionNone SoftResetDirection = iota
	SoftResetDirectionIn
	SoftResetDirectionOut
	SoftResetDirectionBoth
)

func (d SoftResetDirection) String() string {
	switch d {
	case SoftResetDirectionNone:
		return "none"
	case SoftResetDirectionIn:
		return "in"
	case SoftResetDirectionOut:
		return "out"
	case SoftResetDirectionBoth:
		return "both"
	default:
		return "unknown"
	}
}

// ResetNeighborRequest contains parameters used when resetting a BGP peer
type ResetNeighborRequest struct {
	PeerAddress        netip.Addr
	Soft               bool
	SoftResetDirection SoftResetDirection
	AdminCommunication string
}

// ResetAllNeighborsRequest contains parameters used when resetting all BGP peers
type ResetAllNeighborsRequest struct {
	Soft               bool
	SoftResetDirection SoftResetDirection
	AdminCommunication string
}

// PeerState contains status information for a BGP peer
type PeerState struct {
	// Name of the peer
	Name string

	// BGP peer state
	SessionState SessionState

	// The rest of the fields are only valid if SessionState is Established

	// Time since the BGP session was established
	Uptime time.Duration

	// BGP peer address family states. All configured address families are present here.
	Families []PeerFamilyState
}

// PeerFamilyState contains status information for a specific address family.
type PeerFamilyState struct {
	Family
	ReceivedRoutes   uint64
	AcceptedRoutes   uint64
	AdvertisedRoutes uint64
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

// RoutePolicyMatchType defines the route policy matching logic in case of multiple match elements.
type RoutePolicyMatchType int

const (
	RoutePolicyMatchAny RoutePolicyMatchType = iota
	RoutePolicyMatchAll
	RoutePolicyMatchInvert
)

func (t RoutePolicyMatchType) String() string {
	switch t {
	case RoutePolicyMatchAny:
		return "any"
	case RoutePolicyMatchAll:
		return "all"
	case RoutePolicyMatchInvert:
		return "invert"
	default:
		return "unknown"
	}
}

func (t RoutePolicyMatchType) MarshalJSON() ([]byte, error) {
	return []byte("\"" + t.String() + "\""), nil
}

func (t RoutePolicyMatchType) MarshalYAML() (any, error) {
	return t.String(), nil
}

// RoutePolicyNeighborMatch matches BGP neighbor IP address with the provided IPs using the provided match logic type.
//
// +deepequal-gen=true
// +deepequal-gen:private-method=true
type RoutePolicyNeighborMatch struct {
	Type RoutePolicyMatchType
	// +deepequal-gen=false
	Neighbors []netip.Addr
}

// RoutePolicyPrefixMatch matches CIDR prefix with the provided prefixes using the provided match logic type.
//
// +deepequal-gen=true
type RoutePolicyPrefixMatch struct {
	Type     RoutePolicyMatchType
	Prefixes []RoutePolicyPrefix
}

// RoutePolicyPrefix can be used to match a CIDR prefix in a routing policy.
// It can be used to perform exact prefix length matches (if CIDR.Bits() == PrefixLenMin == PrefixLenMax),
// or variable prefix length matches.
//
// +deepequal-gen=true
// +deepequal-gen:private-method=true
type RoutePolicyPrefix struct {
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
	// MatchNeighbors matches BGP neighbor IP address with the provided match rules.
	MatchNeighbors *RoutePolicyNeighborMatch
	// MatchPrefixes matches CIDR prefix with the provided match rules.
	MatchPrefixes *RoutePolicyPrefixMatch
	// MatchFamilies matches ANY of the provided address families. If empty, matches all address families.
	// (Note: the underlying GoBGP infrastructure does not support any other matching criteria for families).
	MatchFamilies []Family
}

// String() constructs a string identifier
func (r RoutePolicyConditions) String() string {
	values := []string{}
	if r.MatchNeighbors != nil {
		neighbors := []string{}
		for _, neighbor := range r.MatchNeighbors.Neighbors {
			neighbors = append(neighbors, neighbor.String())
		}
		if len(neighbors) > 1 {
			values = append(values, r.MatchNeighbors.Type.String())
		}
		values = append(values, strings.Join(neighbors, ","))
	}
	for _, family := range r.MatchFamilies {
		values = append(values, family.String())
	}
	if r.MatchPrefixes != nil {
		prefixes := []string{}
		for _, prefix := range r.MatchPrefixes.Prefixes {
			prefixes = append(prefixes, prefix.CIDR.String())
		}
		if len(prefixes) > 1 {
			values = append(values, r.MatchPrefixes.Type.String())
		}
		values = append(values, strings.Join(prefixes, ","))
	}
	return strings.Join(values, "-")
}

// DeepEqual is a manually created deepequal function, deeply comparing the receiver with another.
// It compares fields with types that do not implement the `DeepEqual` method
// and calls the generated private `deepEqual` method which compares the rest of the fields.
func (n *RoutePolicyNeighborMatch) DeepEqual(other *RoutePolicyNeighborMatch) bool {
	if other == nil {
		return false
	}
	if len(n.Neighbors) != len(other.Neighbors) {
		return false
	}
	for i, neighbor := range n.Neighbors {
		if neighbor != other.Neighbors[i] {
			return false
		}
	}
	// Call generated `deepEqual` method which compares all fields except 'Neighbors'
	return n.deepEqual(other)
}

// DeepEqual is a manually created deepequal function, deeply comparing the receiver with another.
// It compares fields with types that do not implement the `DeepEqual` method
// and calls the generated private `deepEqual` method which compares the rest of the fields.
func (p *RoutePolicyPrefix) DeepEqual(other *RoutePolicyPrefix) bool {
	if other == nil {
		return false
	}
	if p.CIDR != other.CIDR {
		return false
	}
	// Call generated `deepEqual` method which compares all fields except 'CIDR'
	return p.deepEqual(other)
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

func (a RoutePolicyAction) String() string {
	switch a {
	case RoutePolicyActionNone:
		return "none"
	case RoutePolicyActionAccept:
		return "accept"
	case RoutePolicyActionReject:
		return "reject"
	default:
		return "unknown"
	}
}

func (a RoutePolicyAction) MarshalJSON() ([]byte, error) {
	return []byte("\"" + a.String() + "\""), nil
}

func (a RoutePolicyAction) MarshalYAML() (any, error) {
	return a.String(), nil
}

// RoutePolicyActions define policy actions taken on route matched by a routing policy.
//
// +deepequal-gen=true
type RoutePolicyActions struct {
	// RouteAction defines an action taken on the matched route.
	RouteAction RoutePolicyAction
	// AddCommunities defines a list of BGP standard community values to be added to the matched route.
	// If empty, no communities will be added.
	AddCommunities []string
	// AddLargeCommunities defines a list of BGP large community values to be added to the matched route.
	// If empty, no communities will be added.
	AddLargeCommunities []string
	// SetLocalPreference defines a BGP local preference value to be set on the matched route.
	// If nil, no local preference is set.
	SetLocalPreference *int64
	// NextHop sets (or doesn't set) a next hop value on the matched route.
	NextHop *RoutePolicyActionNextHop
}

// RoutingPolicyActionNextHop defines the action taken on the next hop of a
// route matched by a routing policy.
//
// +deepequal-gen=true
type RoutePolicyActionNextHop struct {
	// Set nexthop to the self address of the router
	Self bool
	// Don't change the nexthop of the route
	Unchanged bool
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

func (t RoutePolicyType) String() string {
	switch t {
	case RoutePolicyTypeExport:
		return "export"
	case RoutePolicyTypeImport:
		return "import"
	default:
		return "unknown"
	}
}

func (t RoutePolicyType) MarshalJSON() ([]byte, error) {
	return []byte("\"" + t.String() + "\""), nil
}

func (t RoutePolicyType) MarshalYAML() (any, error) {
	return t.String(), nil
}

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

// GetPeerStateRequest contains parameters for retrieving BGP peer states
type GetPeerStateRequest struct{}

// GetPeerStateResponse contains state of peers configured in given instances
type GetPeerStateResponse struct {
	Peers []PeerState
}

// GetPeerStateLegacyResponse contains state of peers configured in given instance
type GetPeerStateLegacyResponse struct {
	Peers []*models.BgpPeer
}

// GetBGPResponse contains BGP global parameters
type GetBGPResponse struct {
	Global BGPGlobal
}

// ServerParameters contains information for underlying bgp implementation layer to initializing BGP process.
type ServerParameters struct {
	Global            BGPGlobal
	StateNotification StateNotificationCh
}

// Family holds Address Family Indicator (AFI) and Subsequent Address Family Indicator for Multi-Protocol BGP
//
// +deepequal-gen=true
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

// StopRequest contains parameters for stopping the underlying router
type StopRequest struct {
	// FullDestroy should be set to true if full destroy of the router instance should be performed.
	// Note that this causes sending a Cease notification to BGP peers, which terminates Graceful Restart progress.
	FullDestroy bool
}

// RouterProvider provides instances of underlying BGP router implementation.
type RouterProvider interface {
	NewRouter(ctx context.Context, log *slog.Logger, params ServerParameters) (Router, error)
}

// Router is vendor-agnostic cilium bgp configuration layer. Parameters of this layer
// are standard BGP RFC complaint and not specific to any underlying implementation.
type Router interface {
	// Stop stops the router
	Stop(ctx context.Context, r StopRequest)

	// AddNeighbor configures BGP peer
	AddNeighbor(ctx context.Context, n *Neighbor) error

	// UpdateNeighbor updates BGP peer
	UpdateNeighbor(ctx context.Context, n *Neighbor) error

	// RemoveNeighbor removes BGP peer
	RemoveNeighbor(ctx context.Context, n *Neighbor) error

	// ResetNeighbor resets BGP peering with the provided neighbor address
	ResetNeighbor(ctx context.Context, r ResetNeighborRequest) error

	// ResetAllNeighbors resets BGP peering with all configured neighbors
	ResetAllNeighbors(ctx context.Context, r ResetAllNeighborsRequest) error

	// AdvertisePath advertises BGP Path to all configured peers
	AdvertisePath(ctx context.Context, p PathRequest) (PathResponse, error)

	// WithdrawPath  removes BGP Path from all peers
	WithdrawPath(ctx context.Context, p PathRequest) error

	// AddRoutePolicy adds a new routing policy into the underlying router.
	AddRoutePolicy(ctx context.Context, p RoutePolicyRequest) error

	// RemoveRoutePolicy removes a routing policy from the underlying router.
	RemoveRoutePolicy(ctx context.Context, p RoutePolicyRequest) error

	// GetPeerState returns status of BGP peers
	GetPeerState(ctx context.Context, r *GetPeerStateRequest) (*GetPeerStateResponse, error)

	// GetPeerStateLegacy returns status of BGP peers
	GetPeerStateLegacy(ctx context.Context) (GetPeerStateLegacyResponse, error)

	// GetRoutes retrieves routes from the RIB of underlying router
	GetRoutes(ctx context.Context, r *GetRoutesRequest) (*GetRoutesResponse, error)

	// GetRoutePolicies retrieves route policies from the underlying router
	GetRoutePolicies(ctx context.Context) (*GetRoutePoliciesResponse, error)

	// GetBGP returns configured BGP global parameters
	GetBGP(ctx context.Context) (GetBGPResponse, error)
}
