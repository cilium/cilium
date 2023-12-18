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
	"github.com/cilium/cilium/pkg/bgpv1/types"
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
			return nil, fmt.Errorf("invalid neighbor address %w", err)
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

func ToAgentFamily(m *models.BgpFamily) (*types.Family, error) {
	f := &types.Family{}

	if f.Afi = types.ParseAfi(m.Afi); f.Afi == types.AfiUnknown {
		return nil, fmt.Errorf("unknown afi %s", m.Afi)
	}

	if f.Safi = types.ParseSafi(m.Safi); f.Safi == types.SafiUnknown {
		return nil, fmt.Errorf("unknown safi %s", m.Safi)
	}

	return f, nil
}

func ToAPIPath(p *types.Path) (*models.BgpPath, error) {
	ret := &models.BgpPath{}

	ret.AgeNanoseconds = p.AgeNanoseconds
	ret.Best = p.Best

	// We need this Base64 encoding because OpenAPI 2.0 spec doesn't support Union
	// type and we don't have any way to express the API response field which can
	// be a multiple types. This is especially inconvenient for NLRI and Path
	// Attributes. The workaround here is serialize NLRI or Path Attribute into
	// BGP UPDATE messsage format and encode it with base64 to put them into text
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

func ToAPIRoute(r *types.Route, routerASN int64) (*models.BgpRoute, error) {
	paths, err := ToAPIPaths(r.Paths)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Paths: %w", err)
	}
	return &models.BgpRoute{
		RouterAsn: routerASN,
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

func ToAPIRoutes(rs []*types.Route, routerASN int64) ([]*models.BgpRoute, error) {
	errs := []error{}
	ret := []*models.BgpRoute{}

	for _, r := range rs {
		route, err := ToAPIRoute(r, routerASN)
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

func ToAgentRoutes(ms []*models.BgpRoute) ([]*types.Route, error) {
	errs := []error{}
	ret := []*types.Route{}

	for _, m := range ms {
		route, err := ToAgentRoute(m)
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

func ToAgentRoutePolicies(policies []*models.BgpRoutePolicy) ([]*types.RoutePolicy, error) {
	var retErr error
	ret := make([]*types.RoutePolicy, 0, len(policies))

	for _, p := range policies {
		policy, err := ToAgentRoutePolicy(p)
		if err != nil {
			retErr = errors.Join(retErr, err)
			continue
		}
		ret = append(ret, policy)
	}
	return ret, retErr
}

func ToAPIRoutePolicy(policy *types.RoutePolicy, routerASN int64) *models.BgpRoutePolicy {
	return &models.BgpRoutePolicy{
		RouterAsn:  routerASN,
		Name:       policy.Name,
		Type:       ToApiRoutePolicyType(policy.Type),
		Statements: ToAPIRoutePolicyStatements(policy.Statements),
	}
}

func ToAgentRoutePolicy(policy *models.BgpRoutePolicy) (*types.RoutePolicy, error) {
	stmts, err := ToAgentRoutePolicyStatements(policy.Statements)
	if err != nil {
		return nil, err
	}
	return &types.RoutePolicy{
		Name:       policy.Name,
		Type:       ToAgentRoutePolicyType(policy.Type),
		Statements: stmts,
	}, nil
}

func ToAPIRoutePolicyStatements(statements []*types.RoutePolicyStatement) []*models.BgpRoutePolicyStatement {
	ret := make([]*models.BgpRoutePolicyStatement, 0, len(statements))

	for _, s := range statements {
		ret = append(ret, ToAPIRoutePolicyStatement(s))
	}
	return ret
}

func ToAgentRoutePolicyStatements(statements []*models.BgpRoutePolicyStatement) ([]*types.RoutePolicyStatement, error) {
	var retErr error
	ret := make([]*types.RoutePolicyStatement, 0, len(statements))

	for _, s := range statements {
		stmt, err := ToAgentRoutePolicyStatement(s)
		if err != nil {
			retErr = errors.Join(retErr, err)
			continue
		}
		ret = append(ret, stmt)
	}
	return ret, retErr
}

func ToAPIRoutePolicyStatement(s *types.RoutePolicyStatement) *models.BgpRoutePolicyStatement {
	localPref := int64(-1)
	if s.Actions.SetLocalPreference != nil {
		localPref = *s.Actions.SetLocalPreference
	}
	ret := &models.BgpRoutePolicyStatement{
		MatchNeighbors:      s.Conditions.MatchNeighbors,
		MatchPrefixes:       ToApiMatchPrefixes(s.Conditions.MatchPrefixes),
		RouteAction:         ToApiRoutePolicyAction(s.Actions.RouteAction),
		AddCommunities:      s.Actions.AddCommunities,
		AddLargeCommunities: s.Actions.AddLargeCommunities,
		SetLocalPreference:  localPref,
	}
	return ret
}

func ToAgentRoutePolicyStatement(s *models.BgpRoutePolicyStatement) (*types.RoutePolicyStatement, error) {
	var localPref *int64
	if s.SetLocalPreference >= 0 {
		localPref = &s.SetLocalPreference
	}
	prefixes, err := ToAgentMatchPrefixes(s.MatchPrefixes)
	if err != nil {
		return nil, err
	}
	ret := &types.RoutePolicyStatement{
		Conditions: types.RoutePolicyConditions{
			MatchNeighbors: s.MatchNeighbors,
			MatchPrefixes:  prefixes,
		},
		Actions: types.RoutePolicyActions{
			RouteAction:         ToAgentRoutePolicyAction(s.RouteAction),
			AddCommunities:      s.AddCommunities,
			AddLargeCommunities: s.AddLargeCommunities,
			SetLocalPreference:  localPref,
		},
	}
	return ret, nil
}

func ToApiMatchPrefixes(prefixes []*types.RoutePolicyPrefixMatch) []*models.BgpRoutePolicyPrefixMatch {
	ret := make([]*models.BgpRoutePolicyPrefixMatch, 0, len(prefixes))

	for _, p := range prefixes {
		ret = append(ret, &models.BgpRoutePolicyPrefixMatch{
			Cidr:         p.CIDR.String(),
			PrefixLenMin: int64(p.PrefixLenMin),
			PrefixLenMax: int64(p.PrefixLenMax),
		})
	}
	return ret
}

func ToAgentMatchPrefixes(prefixes []*models.BgpRoutePolicyPrefixMatch) ([]*types.RoutePolicyPrefixMatch, error) {
	var retErr error
	ret := make([]*types.RoutePolicyPrefixMatch, 0, len(prefixes))

	for _, p := range prefixes {
		cidr, err := netip.ParsePrefix(p.Cidr)
		if err != nil {
			retErr = errors.Join(retErr, err)
			continue
		}
		ret = append(ret, &types.RoutePolicyPrefixMatch{
			CIDR:         cidr,
			PrefixLenMin: int(p.PrefixLenMin),
			PrefixLenMax: int(p.PrefixLenMax),
		})
	}
	return ret, retErr
}

func ToApiRoutePolicyType(t types.RoutePolicyType) string {
	if t == types.RoutePolicyTypeExport {
		return routePolicyTypeExport
	}
	return routePolicyTypeImport
}

func ToAgentRoutePolicyType(t string) types.RoutePolicyType {
	if t == routePolicyTypeExport {
		return types.RoutePolicyTypeExport
	}
	return types.RoutePolicyTypeImport
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

func ToAgentRoutePolicyAction(a string) types.RoutePolicyAction {
	switch a {
	case routePolicyActionNone:
		return types.RoutePolicyActionNone
	case routePolicyActionAccept:
		return types.RoutePolicyActionAccept
	case routePolicyActionReject:
		return types.RoutePolicyActionReject
	}
	return types.RoutePolicyActionNone
}
