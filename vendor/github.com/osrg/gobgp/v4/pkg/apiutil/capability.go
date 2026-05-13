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

	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
)

func NewMultiProtocolCapability(a *bgp.CapMultiProtocol) *api.MultiProtocolCapability {
	return &api.MultiProtocolCapability{
		Family: ToApiFamily(a.CapValue.Afi(), a.CapValue.Safi()),
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
		tuples = append(tuples, &api.AddPathCapabilityTuple{
			Family: ToApiFamily(t.Family.Afi(), t.Family.Safi()),
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
			Family: ToApiFamily(t.AFI, t.SAFI),
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

func MarshalCapability(value bgp.ParameterCapabilityInterface) (*api.Capability, error) {
	var m api.Capability
	switch n := value.(type) {
	case *bgp.CapMultiProtocol:
		m.Cap = &api.Capability_MultiProtocol{MultiProtocol: NewMultiProtocolCapability(n)}
	case *bgp.CapRouteRefresh:
		m.Cap = &api.Capability_RouteRefresh{RouteRefresh: NewRouteRefreshCapability(n)}
	case *bgp.CapCarryingLabelInfo:
		m.Cap = &api.Capability_CarryingLabelInfo{CarryingLabelInfo: NewCarryingLabelInfoCapability(n)}
	case *bgp.CapExtendedNexthop:
		m.Cap = &api.Capability_ExtendedNexthop{ExtendedNexthop: NewExtendedNexthopCapability(n)}
	case *bgp.CapGracefulRestart:
		m.Cap = &api.Capability_GracefulRestart{GracefulRestart: NewGracefulRestartCapability(n)}
	case *bgp.CapFourOctetASNumber:
		m.Cap = &api.Capability_FourOctetAsn{FourOctetAsn: NewFourOctetASNumberCapability(n)}
	case *bgp.CapAddPath:
		m.Cap = &api.Capability_AddPath{AddPath: NewAddPathCapability(n)}
	case *bgp.CapEnhancedRouteRefresh:
		m.Cap = &api.Capability_EnhancedRouteRefresh{EnhancedRouteRefresh: NewEnhancedRouteRefreshCapability(n)}
	case *bgp.CapLongLivedGracefulRestart:
		m.Cap = &api.Capability_LongLivedGracefulRestart{LongLivedGracefulRestart: NewLongLivedGracefulRestartCapability(n)}
	case *bgp.CapRouteRefreshCisco:
		m.Cap = &api.Capability_RouteRefreshCisco{RouteRefreshCisco: NewRouteRefreshCiscoCapability(n)}
	case *bgp.CapFQDN:
		m.Cap = &api.Capability_Fqdn{Fqdn: NewFQDNCapability(n)}
	case *bgp.CapSoftwareVersion:
		m.Cap = &api.Capability_SoftwareVersion{SoftwareVersion: NewSoftwareVersionCapability(n)}
	case *bgp.CapUnknown:
		m.Cap = &api.Capability_Unknown{Unknown: NewUnknownCapability(n)}
	default:
		return nil, fmt.Errorf("invalid capability type to marshal: %+v", value)
	}
	return &m, nil
}

func MarshalCapabilities(values []bgp.ParameterCapabilityInterface) ([]*api.Capability, error) {
	caps := make([]*api.Capability, 0, len(values))
	for _, value := range values {
		a, err := MarshalCapability(value)
		if err != nil {
			return nil, err
		}
		caps = append(caps, a)
	}
	return caps, nil
}

func unmarshalCapability(a *api.Capability) (bgp.ParameterCapabilityInterface, error) {
	switch cap := a.GetCap().(type) {
	case *api.Capability_MultiProtocol:
		a := cap.MultiProtocol
		return bgp.NewCapMultiProtocol(ToFamily(a.Family)), nil
	case *api.Capability_RouteRefresh:
		return bgp.NewCapRouteRefresh(), nil
	case *api.Capability_CarryingLabelInfo:
		return bgp.NewCapCarryingLabelInfo(), nil
	case *api.Capability_ExtendedNexthop:
		a := cap.ExtendedNexthop
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
			tuples = append(tuples, bgp.NewCapExtendedNexthopTuple(ToFamily(t.NlriFamily), nhAfi))
		}
		return bgp.NewCapExtendedNexthop(tuples), nil
	case *api.Capability_GracefulRestart:
		a := cap.GracefulRestart
		tuples := make([]*bgp.CapGracefulRestartTuple, 0, len(a.Tuples))
		for _, t := range a.Tuples {
			var forward bool
			if t.Flags&0x80 > 0 {
				forward = true
			}
			tuples = append(tuples, bgp.NewCapGracefulRestartTuple(ToFamily(t.Family), forward))
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
	case *api.Capability_FourOctetAsn:
		a := cap.FourOctetAsn
		return bgp.NewCapFourOctetASNumber(a.Asn), nil
	case *api.Capability_AddPath:
		a := cap.AddPath
		tuples := make([]*bgp.CapAddPathTuple, 0, len(a.Tuples))
		for _, t := range a.Tuples {
			tuples = append(tuples, bgp.NewCapAddPathTuple(ToFamily(t.Family), bgp.BGPAddPathMode(t.Mode)))
		}
		return bgp.NewCapAddPath(tuples), nil
	case *api.Capability_EnhancedRouteRefresh:
		return bgp.NewCapEnhancedRouteRefresh(), nil
	case *api.Capability_LongLivedGracefulRestart:
		a := cap.LongLivedGracefulRestart
		tuples := make([]*bgp.CapLongLivedGracefulRestartTuple, 0, len(a.Tuples))
		for _, t := range a.Tuples {
			var forward bool
			if t.Flags&0x80 > 0 {
				forward = true
			}
			tuples = append(tuples, bgp.NewCapLongLivedGracefulRestartTuple(ToFamily(t.Family), forward, t.Time))
		}
		return bgp.NewCapLongLivedGracefulRestart(tuples), nil
	case *api.Capability_RouteRefreshCisco:
		return bgp.NewCapRouteRefreshCisco(), nil
	case *api.Capability_Fqdn:
		a := cap.Fqdn
		return bgp.NewCapFQDN(a.HostName, a.DomainName), nil
	case *api.Capability_SoftwareVersion:
		a := cap.SoftwareVersion
		return bgp.NewCapSoftwareVersion(a.SoftwareVersion), nil
	case *api.Capability_Unknown:
		a := cap.Unknown
		return bgp.NewCapUnknown(bgp.BGPCapabilityCode(a.Code), a.Value), nil
	}
	return nil, fmt.Errorf("invalid capability type to unmarshal: %T", a.GetCap())
}

func UnmarshalCapabilities(values []*api.Capability) ([]bgp.ParameterCapabilityInterface, error) {
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
