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

	// readonly
	AgeNanoseconds int64 // time duration in nanoseconds since the Path was created
	Best           bool
	UUID           []byte // path identifier in underlying implementation
}

// NeighborRequest contains neighbor parameters used when enabling or disabling peer
type NeighborRequest struct {
	Neighbor *v2alpha1api.CiliumBGPNeighbor
	VR       *v2alpha1api.CiliumBGPVirtualRouter
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

	// AdvertisePath advertises BGP Path to all configured peers
	AdvertisePath(ctx context.Context, p PathRequest) (PathResponse, error)

	// WithdrawPath  removes BGP Path from all peers
	WithdrawPath(ctx context.Context, p PathRequest) error

	// GetPeerState returns status of BGP peers
	GetPeerState(ctx context.Context) (GetPeerStateResponse, error)

	// GetRoutes retrieves routes from the RIB of underlying router
	GetRoutes(ctx context.Context, r *GetRoutesRequest) (*GetRoutesResponse, error)

	// GetBGP returns configured BGP global parameters
	GetBGP(ctx context.Context) (GetBGPResponse, error)
}
