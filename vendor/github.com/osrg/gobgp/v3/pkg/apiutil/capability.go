// Copyright (C) 2018 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package apiutil

import (
	"fmt"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	proto "google.golang.org/protobuf/proto"
	apb "google.golang.org/protobuf/types/known/anypb"
)

func NewMultiProtocolCapability(a *bgp.CapMultiProtocol) *api.MultiProtocolCapability {
	afi, safi := bgp.RouteFamilyToAfiSafi(a.CapValue)
	return &api.MultiProtocolCapability{
		Family: ToApiFamily(afi, safi),
	}
}

func NewRouteRefreshCapability(a *bgp.CapRouteRefresh) *api.RouteRefreshCapability {
	return &api.RouteRefreshCapability{}
}

func NewCarryingLabelInfoCapability(a *bgp.CapCarryingLabelInfo) *api.CarryingLabelInfoCapability {
	return &api.CarryingLabelInfoCapability{}
}

func NewExtendedNexthopCapability(a *bgp.CapExtendedNexthop) *api.ExtendedNexthopCapability {
	tuples := make([]*api.ExtendedNexthopCapabilityTuple, 0, len(a.Tuples))
	for _, t := range a.Tuples {
		tuples = append(tuples, &api.ExtendedNexthopCapabilityTuple{
			NlriFamily:    ToApiFamily(t.NLRIAFI, uint8(t.NLRISAFI)),
			NexthopFamily: ToApiFamily(t.NexthopAFI, bgp.SAFI_UNICAST),
		})
	}
	return &api.ExtendedNexthopCapability{
		Tuples: tuples,
	}
}

func NewGracefulRestartCapability(a *bgp.CapGracefulRestart) *api.GracefulRestartCapability {
	tuples := make([]*api.GracefulRestartCapabilityTuple, 0, len(a.Tuples))
	for _, t := range a.Tuples {
		tuples = append(tuples, &api.GracefulRestartCapabilityTuple{
			Family: ToApiFamily(t.AFI, t.SAFI),
			Flags:  uint32(t.Flags),
		})
	}
	return &api.GracefulRestartCapability{
		Flags:  uint32(a.Flags),
		Time:   uint32(a.Time),
		Tuples: tuples,
	}
}

func NewFourOctetASNumberCapability(a *bgp.CapFourOctetASNumber) *api.FourOctetASNCapability {
	return &api.FourOctetASNCapability{
		Asn: a.CapValue,
	}
}

func NewAddPathCapability(a *bgp.CapAddPath) *api.AddPathCapability {
	tuples := make([]*api.AddPathCapabilityTuple, 0, len(a.Tuples))
	for _, t := range a.Tuples {
		afi, safi := bgp.RouteFamilyToAfiSafi(t.RouteFamily)
		tuples = append(tuples, &api.AddPathCapabilityTuple{
			Family: ToApiFamily(afi, safi),
			Mode:   api.AddPathCapabilityTuple_Mode(t.Mode),
		})
	}
	return &api.AddPathCapability{
		Tuples: tuples,
	}
}

func NewEnhancedRouteRefreshCapability(a *bgp.CapEnhancedRouteRefresh) *api.EnhancedRouteRefreshCapability {
	return &api.EnhancedRouteRefreshCapability{}
}

func NewLongLivedGracefulRestartCapability(a *bgp.CapLongLivedGracefulRestart) *api.LongLivedGracefulRestartCapability {
	tuples := make([]*api.LongLivedGracefulRestartCapabilityTuple, 0, len(a.Tuples))
	for _, t := range a.Tuples {
		tuples = append(tuples, &api.LongLivedGracefulRestartCapabilityTuple{
			Family: ToApiFamily(t.AFI, uint8(t.SAFI)),
			Flags:  uint32(t.Flags),
			Time:   t.RestartTime,
		})
	}
	return &api.LongLivedGracefulRestartCapability{
		Tuples: tuples,
	}
}

func NewRouteRefreshCiscoCapability(a *bgp.CapRouteRefreshCisco) *api.RouteRefreshCiscoCapability {
	return &api.RouteRefreshCiscoCapability{}
}

func NewFQDNCapability(a *bgp.CapFQDN) *api.FqdnCapability {
	return &api.FqdnCapability{
		HostName:   a.HostName,
		DomainName: a.DomainName,
	}
}

func NewSoftwareVersionCapability(a *bgp.CapSoftwareVersion) *api.SoftwareVersionCapability {
	return &api.SoftwareVersionCapability{
		SoftwareVersion: a.SoftwareVersion,
	}
}

func NewUnknownCapability(a *bgp.CapUnknown) *api.UnknownCapability {
	return &api.UnknownCapability{
		Code:  uint32(a.CapCode),
		Value: a.CapValue,
	}
}

func MarshalCapability(value bgp.ParameterCapabilityInterface) (*apb.Any, error) {
	var m proto.Message
	switch n := value.(type) {
	case *bgp.CapMultiProtocol:
		m = NewMultiProtocolCapability(n)
	case *bgp.CapRouteRefresh:
		m = NewRouteRefreshCapability(n)
	case *bgp.CapCarryingLabelInfo:
		m = NewCarryingLabelInfoCapability(n)
	case *bgp.CapExtendedNexthop:
		m = NewExtendedNexthopCapability(n)
	case *bgp.CapGracefulRestart:
		m = NewGracefulRestartCapability(n)
	case *bgp.CapFourOctetASNumber:
		m = NewFourOctetASNumberCapability(n)
	case *bgp.CapAddPath:
		m = NewAddPathCapability(n)
	case *bgp.CapEnhancedRouteRefresh:
		m = NewEnhancedRouteRefreshCapability(n)
	case *bgp.CapLongLivedGracefulRestart:
		m = NewLongLivedGracefulRestartCapability(n)
	case *bgp.CapRouteRefreshCisco:
		m = NewRouteRefreshCiscoCapability(n)
	case *bgp.CapFQDN:
		m = NewFQDNCapability(n)
	case *bgp.CapSoftwareVersion:
		m = NewSoftwareVersionCapability(n)
	case *bgp.CapUnknown:
		m = NewUnknownCapability(n)
	default:
		return nil, fmt.Errorf("invalid capability type to marshal: %+v", value)
	}
	return apb.New(m)
}

func MarshalCapabilities(values []bgp.ParameterCapabilityInterface) ([]*apb.Any, error) {
	caps := make([]*apb.Any, 0, len(values))
	for _, value := range values {
		a, err := MarshalCapability(value)
		if err != nil {
			return nil, err
		}
		caps = append(caps, a)
	}
	return caps, nil
}

func unmarshalCapability(a *apb.Any) (bgp.ParameterCapabilityInterface, error) {
	value, err := a.UnmarshalNew()
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal capability: %s", err)
	}
	switch a := value.(type) {
	case *api.MultiProtocolCapability:
		return bgp.NewCapMultiProtocol(ToRouteFamily(a.Family)), nil
	case *api.RouteRefreshCapability:
		return bgp.NewCapRouteRefresh(), nil
	case *api.CarryingLabelInfoCapability:
		return bgp.NewCapCarryingLabelInfo(), nil
	case *api.ExtendedNexthopCapability:
		tuples := make([]*bgp.CapExtendedNexthopTuple, 0, len(a.Tuples))
		for _, t := range a.Tuples {
			var nhAfi uint16
			switch t.NexthopFamily.Afi {
			case api.Family_AFI_IP:
				nhAfi = bgp.AFI_IP
			case api.Family_AFI_IP6:
				nhAfi = bgp.AFI_IP6
			default:
				return nil, fmt.Errorf("invalid address family for nexthop afi in extended nexthop capability: %s", t.NexthopFamily)
			}
			tuples = append(tuples, bgp.NewCapExtendedNexthopTuple(ToRouteFamily(t.NlriFamily), nhAfi))
		}
		return bgp.NewCapExtendedNexthop(tuples), nil
	case *api.GracefulRestartCapability:
		tuples := make([]*bgp.CapGracefulRestartTuple, 0, len(a.Tuples))
		for _, t := range a.Tuples {
			var forward bool
			if t.Flags&0x80 > 0 {
				forward = true
			}
			tuples = append(tuples, bgp.NewCapGracefulRestartTuple(ToRouteFamily(t.Family), forward))
		}
		var restarting bool
		if a.Flags&0x08 > 0 {
			restarting = true
		}
		var notification bool
		if a.Flags&0x04 > 0 {
			notification = true
		}
		return bgp.NewCapGracefulRestart(restarting, notification, uint16(a.Time), tuples), nil
	case *api.FourOctetASNCapability:
		return bgp.NewCapFourOctetASNumber(a.Asn), nil
	case *api.AddPathCapability:
		tuples := make([]*bgp.CapAddPathTuple, 0, len(a.Tuples))
		for _, t := range a.Tuples {
			tuples = append(tuples, bgp.NewCapAddPathTuple(ToRouteFamily(t.Family), bgp.BGPAddPathMode(t.Mode)))
		}
		return bgp.NewCapAddPath(tuples), nil
	case *api.EnhancedRouteRefreshCapability:
		return bgp.NewCapEnhancedRouteRefresh(), nil
	case *api.LongLivedGracefulRestartCapability:
		tuples := make([]*bgp.CapLongLivedGracefulRestartTuple, 0, len(a.Tuples))
		for _, t := range a.Tuples {
			var forward bool
			if t.Flags&0x80 > 0 {
				forward = true
			}
			tuples = append(tuples, bgp.NewCapLongLivedGracefulRestartTuple(ToRouteFamily(t.Family), forward, t.Time))
		}
		return bgp.NewCapLongLivedGracefulRestart(tuples), nil
	case *api.RouteRefreshCiscoCapability:
		return bgp.NewCapRouteRefreshCisco(), nil
	case *api.FqdnCapability:
		return bgp.NewCapFQDN(a.HostName, a.DomainName), nil
	case *api.SoftwareVersionCapability:
		return bgp.NewCapSoftwareVersion(a.SoftwareVersion), nil
	case *api.UnknownCapability:
		return bgp.NewCapUnknown(bgp.BGPCapabilityCode(a.Code), a.Value), nil
	}
	return nil, fmt.Errorf("invalid capability type to unmarshal: %s", a.TypeUrl)
}

func UnmarshalCapabilities(values []*apb.Any) ([]bgp.ParameterCapabilityInterface, error) {
	caps := make([]bgp.ParameterCapabilityInterface, 0, len(values))
	for _, value := range values {
		c, err := unmarshalCapability(value)
		if err != nil {
			return nil, err
		}
		caps = append(caps, c)
	}
	return caps, nil
}
