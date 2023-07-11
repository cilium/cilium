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

func ToAgentAfi(s string) types.Afi {
	switch s {
	case "ipv4":
		return types.AfiIPv4
	case "ipv6":
		return types.AfiIPv6
	case "l2vpn":
		return types.AfiL2VPN
	case "ls":
		return types.AfiLS
	case "opaque":
		return types.AfiOpaque
	default:
		return types.AfiUnknown
	}
}

func ToAPIAfi(afi types.Afi) string {
	switch afi {
	case types.AfiUnknown:
		return "unknown"
	case types.AfiIPv4:
		return "ipv4"
	case types.AfiIPv6:
		return "ipv6"
	case types.AfiL2VPN:
		return "l2vpn"
	case types.AfiLS:
		return "ls"
	case types.AfiOpaque:
		return "opaque"
	default:
		return "unknown"
	}
}

func ToAgentSafi(s string) types.Safi {
	switch s {
	case "unicast":
		return types.SafiUnicast
	case "multicast":
		return types.SafiMulticast
	case "mpls_label":
		return types.SafiMplsLabel
	case "encapsulation":
		return types.SafiEncapsulation
	case "vpls":
		return types.SafiVpls
	case "evpn":
		return types.SafiEvpn
	case "ls":
		return types.SafiLs
	case "sr_policy":
		return types.SafiSrPolicy
	case "mup":
		return types.SafiMup
	case "mpls_vpn":
		return types.SafiMplsVpn
	case "mpls_vpn_multicast":
		return types.SafiMplsVpnMulticast
	case "route_target_constraints":
		return types.SafiRouteTargetConstraints
	case "flowspec_unicast":
		return types.SafiFlowSpecUnicast
	case "flowspec_vpn":
		return types.SafiFlowSpecVpn
	case "key_value":
		return types.SafiKeyValue
	default:
		return types.SafiUnknown
	}
}

func ToAPISafi(safi types.Safi) string {
	switch safi {
	case types.SafiUnknown:
		return "unknown"
	case types.SafiUnicast:
		return "unicast"
	case types.SafiMulticast:
		return "multicast"
	case types.SafiMplsLabel:
		return "mpls_label"
	case types.SafiEncapsulation:
		return "encapsulation"
	case types.SafiVpls:
		return "vpls"
	case types.SafiEvpn:
		return "evpn"
	case types.SafiLs:
		return "ls"
	case types.SafiSrPolicy:
		return "sr_policy"
	case types.SafiMup:
		return "mup"
	case types.SafiMplsVpn:
		return "mpls_vpn"
	case types.SafiMplsVpnMulticast:
		return "mpls_vpn_multicast"
	case types.SafiRouteTargetConstraints:
		return "route_target_constraints"
	case types.SafiFlowSpecUnicast:
		return "flowspec_unicast"
	case types.SafiFlowSpecVpn:
		return "flowspec_vpn"
	case types.SafiKeyValue:
		return "key_value"
	default:
		return "unknown"
	}
}

func ToAgentTableType(s string) types.TableType {
	switch s {
	case "loc-rib":
		return types.TableTypeLocRIB
	case "adj-rib-in":
		return types.TableTypeAdjRIBIn
	case "adj-rib-out":
		return types.TableTypeAdjRIBOut
	default:
		return types.TableTypeUnknown
	}
}

func ToAgentGetRoutesRequest(params restapi.GetBgpRoutesParams) (*types.GetRoutesRequest, error) {
	ret := &types.GetRoutesRequest{}

	if ret.TableType = ToAgentTableType(params.TableType); ret.TableType == types.TableTypeUnknown {
		return nil, fmt.Errorf("unknown table type %s", params.TableType)
	}

	if ret.Family.Afi = ToAgentAfi(params.Afi); ret.Family.Afi == types.AfiUnknown {
		return nil, fmt.Errorf("unknown AFI %s", params.Afi)
	}

	if ret.Family.Safi = ToAgentSafi(params.Safi); ret.Family.Safi == types.SafiUnknown {
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
		Afi:  ToAPIAfi(f.Afi),
		Safi: ToAPISafi(f.Safi),
	}, nil
}

func ToAgentFamily(m *models.BgpFamily) (*types.Family, error) {
	f := &types.Family{}

	if f.Afi = ToAgentAfi(m.Afi); f.Afi == types.AfiUnknown {
		return nil, fmt.Errorf("unknown afi %s", m.Afi)
	}

	if f.Safi = ToAgentSafi(m.Safi); f.Safi == types.SafiUnknown {
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

	afi := ToAgentAfi(m.Family.Afi)
	safi := ToAgentSafi(m.Family.Safi)

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
