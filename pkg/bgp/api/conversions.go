// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"

	"github.com/osrg/gobgp/v3/pkg/packet/bgp"

	"github.com/cilium/cilium/api/v1/models"
	restapi "github.com/cilium/cilium/api/v1/server/restapi/bgp"
	"github.com/cilium/cilium/pkg/bgp/types"
)

const (
	routePolicyTypeExport = "export"
	routePolicyTypeImport = "import"

	routePolicyActionNone   = "none"
	routePolicyActionAccept = "accept"
	routePolicyActionReject = "reject"
)

func ToAgentGetRoutesRequest(params restapi.GetBgpRoutesParams) (*types.GetRoutesRequest, error) {
	ret := &types.GetRoutesRequest{}

	if ret.TableType = types.ParseTableType(params.TableType); ret.TableType == types.TableTypeUnknown {
		return nil, fmt.Errorf("unknown table type %s", params.TableType)
	}

	if ret.Family.Afi = types.ParseAfi(params.Afi); ret.Family.Afi == types.AfiUnknown {
		return nil, fmt.Errorf("unknown AFI %s", params.Afi)
	}

	if ret.Family.Safi = types.ParseSafi(params.Safi); ret.Family.Safi == types.SafiUnknown {
		return nil, fmt.Errorf("unknown SAFI %s", params.Safi)
	}

	if params.Neighbor != nil {
		if ret.TableType == types.TableTypeLocRIB {
			return nil, fmt.Errorf("neighbor is unnecessary for loc-rib table type")
		}
		addr, err := netip.ParseAddr(*params.Neighbor)
		if err != nil {
			return nil, fmt.Errorf("invalid neighbor address: %w", err)
		}
		ret.Neighbor = addr
	} else {
		if ret.TableType == types.TableTypeAdjRIBIn || ret.TableType == types.TableTypeAdjRIBOut {
			return nil, fmt.Errorf("table %s requires neighbor parameter", params.TableType)
		}
	}

	return ret, nil
}

func ToAPIFamily(f *types.Family) (*models.BgpFamily, error) {
	return &models.BgpFamily{
		Afi:  f.Afi.String(),
		Safi: f.Safi.String(),
	}, nil
}

func ToAPIFamilies(families []types.Family) []*models.BgpFamily {
	var res []*models.BgpFamily
	for _, f := range families {
		if family, err := ToAPIFamily(&f); err == nil {
			res = append(res, family)
		}
	}
	return res
}

func ToAPIPath(p *types.Path) (*models.BgpPath, error) {
	ret := &models.BgpPath{}

	ret.AgeNanoseconds = p.AgeNanoseconds
	ret.Best = p.Best

	// We need this Base64 encoding because OpenAPI 2.0 spec doesn't support Union
	// type and we don't have any way to express the API response field which can
	// be a multiple types. This is especially inconvenient for NLRI and Path
	// Attributes. The workaround here is serialize NLRI or Path Attribute into
	// BGP UPDATE message format and encode it with base64 to put them into text
	// based protocol. So that we can still stick to the standard (theoretically
	// people can use standard BGP decoder to decode this base64 field).
	bin, err := p.NLRI.Serialize()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize NLRI: %w", err)
	}
	ret.Nlri = &models.BgpNlri{Base64: base64.StdEncoding.EncodeToString(bin)}

	if ret.Family, err = ToAPIFamily(&types.Family{
		Afi:  types.Afi(p.NLRI.AFI()),
		Safi: types.Safi(p.NLRI.SAFI()),
	}); err != nil {
		return nil, fmt.Errorf("failed to serialize address family: %w", err)
	}

	for _, pattr := range p.PathAttributes {
		bin, err := pattr.Serialize()
		if err != nil {
			return nil, fmt.Errorf("failed to serialize Path Attribute: %w", err)
		}

		ret.PathAttributes = append(ret.PathAttributes, &models.BgpPathAttribute{
			Base64: base64.StdEncoding.EncodeToString(bin),
		})
	}

	return ret, nil
}

func ToAgentPath(m *models.BgpPath) (*types.Path, error) {
	p := &types.Path{}

	p.AgeNanoseconds = m.AgeNanoseconds
	p.Best = m.Best

	afi := types.ParseAfi(m.Family.Afi)
	safi := types.ParseSafi(m.Family.Safi)

	// Create empty NLRI structure. The underlying type will be set correctly by providing AFI/SAFI
	nlri, err := bgp.NewPrefixFromRouteFamily(uint16(afi), uint8(safi))
	if err != nil {
		return nil, fmt.Errorf("failed to create native NLRI struct from AFI/SAFI: %w", err)
	}

	// Decode serialized NLRI
	bin, err := base64.StdEncoding.DecodeString(m.Nlri.Base64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64-encoded NLRI: %w", err)
	}

	if err := nlri.DecodeFromBytes(bin); err != nil {
		return nil, fmt.Errorf("failed to decode NLRI: %w", err)
	}

	p.NLRI = nlri

	// Decode path attributes
	for _, pattr := range m.PathAttributes {
		bin, err := base64.StdEncoding.DecodeString(pattr.Base64)
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64-encoded Path Attribute: %w", err)
		}

		attr, err := bgp.GetPathAttribute(bin)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve serialized Path Attribute: %w", err)
		}
		err = attr.DecodeFromBytes(bin)
		if err != nil {
			return nil, fmt.Errorf("failed to decode serialized Path Attribute: %w", err)
		}

		p.PathAttributes = append(p.PathAttributes, attr)
	}

	return p, nil
}

func ToAPIPaths(ps []*types.Path) ([]*models.BgpPath, error) {
	errs := []error{}
	ret := []*models.BgpPath{}

	for _, p := range ps {
		path, err := ToAPIPath(p)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		ret = append(ret, path)
	}

	if len(errs) != 0 {
		return nil, errors.Join(errs...)
	}

	return ret, nil
}

func ToAgentPaths(ms []*models.BgpPath) ([]*types.Path, error) {
	errs := []error{}
	ret := []*types.Path{}

	for _, m := range ms {
		path, err := ToAgentPath(m)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		ret = append(ret, path)
	}

	if len(errs) != 0 {
		return nil, errors.Join(errs...)
	}

	return ret, nil
}

func ToAPIRoute(r *types.Route, routerASN int64, neighbor string) (*models.BgpRoute, error) {
	paths, err := ToAPIPaths(r.Paths)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Paths: %w", err)
	}
	return &models.BgpRoute{
		RouterAsn: routerASN,
		Neighbor:  neighbor,
		Prefix:    r.Prefix,
		Paths:     paths,
	}, nil
}

func ToAgentRoute(m *models.BgpRoute) (*types.Route, error) {
	paths, err := ToAgentPaths(m.Paths)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize Paths: %w", err)
	}
	return &types.Route{
		Prefix: m.Prefix,
		Paths:  paths,
	}, nil
}

func ToAPIRoutes(rs []*types.Route, routerASN int64, neighbor string) ([]*models.BgpRoute, error) {
	errs := []error{}
	ret := []*models.BgpRoute{}

	for _, r := range rs {
		route, err := ToAPIRoute(r, routerASN, neighbor)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		ret = append(ret, route)
	}

	if len(errs) != 0 {
		return nil, errors.Join(errs...)
	}

	return ret, nil
}

func ToAPIRoutePolicies(policies []*types.RoutePolicy, routerASN int64) []*models.BgpRoutePolicy {
	ret := make([]*models.BgpRoutePolicy, 0, len(policies))

	for _, p := range policies {
		policy := ToAPIRoutePolicy(p, routerASN)
		ret = append(ret, policy)
	}
	return ret
}

func ToAPIRoutePolicy(policy *types.RoutePolicy, routerASN int64) *models.BgpRoutePolicy {
	return &models.BgpRoutePolicy{
		RouterAsn:  routerASN,
		Name:       policy.Name,
		Type:       ToApiRoutePolicyType(policy.Type),
		Statements: ToAPIRoutePolicyStatements(policy.Statements),
	}
}

func ToAPIRoutePolicyStatements(statements []*types.RoutePolicyStatement) []*models.BgpRoutePolicyStatement {
	ret := make([]*models.BgpRoutePolicyStatement, 0, len(statements))

	for _, s := range statements {
		ret = append(ret, ToAPIRoutePolicyStatement(s))
	}
	return ret
}

func ToAPIRoutePolicyStatement(s *types.RoutePolicyStatement) *models.BgpRoutePolicyStatement {
	localPref := int64(-1)
	if s.Actions.SetLocalPreference != nil {
		localPref = *s.Actions.SetLocalPreference
	}
	ret := &models.BgpRoutePolicyStatement{
		MatchNeighbors:      ToApiMatchNeighbors(s.Conditions.MatchNeighbors),
		MatchFamilies:       ToAPIFamilies(s.Conditions.MatchFamilies),
		MatchPrefixes:       ToApiMatchPrefixes(s.Conditions.MatchPrefixes),
		RouteAction:         ToApiRoutePolicyAction(s.Actions.RouteAction),
		AddCommunities:      s.Actions.AddCommunities,
		AddLargeCommunities: s.Actions.AddLargeCommunities,
		SetLocalPreference:  localPref,
		Nexthop:             toApiRoutePolicyActionNextHop(s.Actions.NextHop),
	}
	return ret
}

func toApiRoutePolicyActionNextHop(a *types.RoutePolicyActionNextHop) *models.BgpRoutePolicyNexthopAction {
	if a == nil {
		return nil
	}
	return &models.BgpRoutePolicyNexthopAction{
		Self:      a.Self,
		Unchanged: a.Unchanged,
	}
}

func ToApiMatchNeighbors(match *types.RoutePolicyNeighborMatch) *models.BgpRoutePolicyNeighborMatch {
	if match == nil || len(match.Neighbors) == 0 {
		return nil
	}
	ret := &models.BgpRoutePolicyNeighborMatch{
		Type:      ToApiRoutePolicyMatchType(match.Type),
		Neighbors: make([]string, 0, len(match.Neighbors)),
	}
	for _, neighbor := range match.Neighbors {
		ret.Neighbors = append(ret.Neighbors, neighbor.String())
	}
	return ret
}

func ToApiMatchPrefixes(match *types.RoutePolicyPrefixMatch) *models.BgpRoutePolicyPrefixMatch {
	if match == nil || len(match.Prefixes) == 0 {
		return nil
	}
	ret := &models.BgpRoutePolicyPrefixMatch{
		Type:     ToApiRoutePolicyMatchType(match.Type),
		Prefixes: make([]*models.BgpRoutePolicyPrefix, 0, len(match.Prefixes)),
	}
	for _, p := range match.Prefixes {
		ret.Prefixes = append(ret.Prefixes, &models.BgpRoutePolicyPrefix{
			Cidr:         p.CIDR.String(),
			PrefixLenMin: int64(p.PrefixLenMin),
			PrefixLenMax: int64(p.PrefixLenMax),
		})
	}
	return ret
}

func ToApiRoutePolicyType(t types.RoutePolicyType) string {
	if t == types.RoutePolicyTypeExport {
		return routePolicyTypeExport
	}
	return routePolicyTypeImport
}

func ToApiRoutePolicyMatchType(t types.RoutePolicyMatchType) models.BgpRoutePolicyMatchType {
	switch t {
	case types.RoutePolicyMatchAny:
		return models.BgpRoutePolicyMatchTypeAny
	case types.RoutePolicyMatchAll:
		return models.BgpRoutePolicyMatchTypeAll
	case types.RoutePolicyMatchInvert:
		return models.BgpRoutePolicyMatchTypeInvert
	}
	return models.BgpRoutePolicyMatchTypeAny
}

func ToApiRoutePolicyAction(a types.RoutePolicyAction) string {
	switch a {
	case types.RoutePolicyActionNone:
		return routePolicyActionNone
	case types.RoutePolicyActionAccept:
		return routePolicyActionAccept
	case types.RoutePolicyActionReject:
		return routePolicyActionReject
	}
	return routePolicyActionNone
}
