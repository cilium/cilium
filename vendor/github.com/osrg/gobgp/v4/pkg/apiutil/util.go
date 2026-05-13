// Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
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
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"
	"github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/packet/bgp"
	tspb "google.golang.org/protobuf/types/known/timestamppb"
)

type PeerEventType uint32

const (
	PEER_EVENT_UNKNOWN     PeerEventType = 0
	PEER_EVENT_INIT        PeerEventType = 1
	PEER_EVENT_END_OF_INIT PeerEventType = 2
	PEER_EVENT_STATE       PeerEventType = 3
)

// WatchEventMessages API type
type WatchEventMessage_PeerEvent struct {
	Type PeerEventType
	Peer Peer
}

// ListPathRequest is used by server.ListPath API
type ListPathRequest struct {
	TableType      api.TableType
	Name           string
	Family         bgp.Family
	Prefixes       []*LookupPrefix
	SortType       api.ListPathRequest_SortType
	EnableFiltered bool
}

// AddPathRequest is used by server.AddPath API
type AddPathRequest struct {
	VRFID string
	Paths []*Path
}

// AddPathResponse is used by server.AddPath API
type AddPathResponse struct {
	UUID  uuid.UUID
	Error error
}

type DeletePathRequest struct {
	VRFID        string
	UUIDs        []uuid.UUID
	DeleteAll    bool
	DeleteFamily *bgp.Family
	Paths        []*Path
}

type LookupOption uint8

const (
	LOOKUP_EXACT LookupOption = iota
	LOOKUP_LONGER
	LOOKUP_SHORTER
)

// LookupOptionFromAPI converts a protobuf TableLookupPrefix_Type to a
// LookupOption. A direct cast is wrong because the proto enum reserves 0 for
// UNSPECIFIED and starts meaningful values at 1, while LookupOption's iota
// starts at 0 (EXACT).
func LookupOptionFromAPI(t api.TableLookupPrefix_Type) LookupOption {
	switch t {
	case api.TableLookupPrefix_TYPE_LONGER:
		return LOOKUP_LONGER
	case api.TableLookupPrefix_TYPE_SHORTER:
		return LOOKUP_SHORTER
	default:
		return LOOKUP_EXACT
	}
}

type LookupPrefix struct {
	Prefix string
	RD     string
	LookupOption
}

// used by server.WatchEventMessages API
type Path struct {
	Family             bgp.Family
	Nlri               bgp.NLRI                     `json:"nlri"`
	Age                int64                        `json:"age"`
	Best               bool                         `json:"best"`
	Attrs              []bgp.PathAttributeInterface `json:"attrs"`
	Stale              bool                         `json:"stale"`
	Withdrawal         bool                         `json:"withdrawal,omitempty"`
	PeerASN            uint32                       `json:"peer-asn,omitempty"`
	PeerID             netip.Addr                   `json:"peer-id,omitzero"`
	PeerAddress        netip.Addr                   `json:"peer-address,omitzero"`
	IsFromExternal     bool                         `json:"is-from-external,omitempty"`
	NoImplicitWithdraw bool                         `json:"no-implicit-withdraw,omitempty"`
	IsNexthopInvalid   bool                         `json:"is-nexthop-invalid,omitempty"`
	// the following fields are used only repoted by GetList() API
	SendMaxFiltered bool            `json:"send-max-filtered,omitempty"` // true if the path has been filtered out due to max path count reached
	Filtered        bool            `json:"filtered,omitempty"`
	Validation      *api.Validation `json:"validation,omitempty"`
	RemoteID        uint32
	LocalID         uint32
}

type PeerConf struct {
	PeerASN           uint32
	LocalASN          uint32
	NeighborAddress   netip.Addr
	NeighborInterface string
}
type PeerState struct {
	PeerASN           uint32
	LocalASN          uint32
	NeighborAddress   netip.Addr
	SessionState      bgp.FSMState
	AdminState        api.PeerState_AdminState
	RouterID          netip.Addr
	RemoteCap         []bgp.ParameterCapabilityInterface
	DisconnectReason  api.PeerState_DisconnectReason
	DisconnectMessage string
}
type Transport struct {
	LocalAddress netip.Addr
	LocalPort    uint32
	RemotePort   uint32
}

type Peer struct {
	Conf      PeerConf
	State     PeerState
	Transport Transport
}

type Destination struct {
	Paths []*Path
}

func (d *Destination) MarshalJSON() ([]byte, error) {
	return json.Marshal(d.Paths)
}

func NewDestination(dst *api.Destination) *Destination {
	l := make([]*Path, 0, len(dst.Paths))
	for _, p := range dst.Paths {
		src, _ := netip.ParseAddr(p.SourceId)
		neighbor, _ := netip.ParseAddr(p.NeighborIp)
		nlri, _ := GetNativeNlri(p)
		attrs, _ := GetNativePathAttributes(p)
		l = append(l, &Path{
			Nlri:            nlri,
			Age:             p.Age.AsTime().Unix(),
			Best:            p.Best,
			Attrs:           attrs,
			Stale:           p.Stale,
			SendMaxFiltered: p.SendMaxFiltered,
			Withdrawal:      p.IsWithdraw,
			PeerID:          src,
			PeerAddress:     neighbor,
		})
	}
	return &Destination{Paths: l}
}

func NewPath(family bgp.Family, nlri bgp.NLRI, isWithdraw bool, attrs []bgp.PathAttributeInterface, age time.Time) (*api.Path, error) {
	n, err := MarshalNLRI(nlri)
	if err != nil {
		return nil, err
	}
	a, err := MarshalPathAttributes(attrs)
	if err != nil {
		return nil, err
	}
	return &api.Path{
		Nlri:       n,
		Pattrs:     a,
		Age:        tspb.New(age),
		IsWithdraw: isWithdraw,
		Family:     ToApiFamily(family.Afi(), family.Safi()),
	}, nil
}

func GetNativeNlri(p *api.Path) (bgp.NLRI, error) {
	if p.Family == nil {
		return nil, fmt.Errorf("family cannot be nil")
	}
	if len(p.NlriBinary) > 0 {
		return bgp.NLRIFromSlice(ToFamily(p.Family), p.NlriBinary)
	}
	return UnmarshalNLRI(ToFamily(p.Family), p.Nlri)
}

func GetNativePathAttributes(p *api.Path) ([]bgp.PathAttributeInterface, error) {
	pattrsLen := len(p.PattrsBinary)
	if pattrsLen > 0 {
		pattrs := make([]bgp.PathAttributeInterface, 0, pattrsLen)
		for _, attr := range p.PattrsBinary {
			a, err := bgp.GetPathAttribute(attr)
			if err != nil {
				return nil, err
			}
			err = a.DecodeFromBytes(attr)
			if err != nil {
				return nil, err
			}
			pattrs = append(pattrs, a)
		}
		return pattrs, nil
	}
	return UnmarshalPathAttributes(p.Pattrs)
}

func ToFamily(f *api.Family) bgp.Family {
	return bgp.NewFamily(uint16(f.Afi), uint8(f.Safi))
}

func ToApiFamily(afi uint16, safi uint8) *api.Family {
	return &api.Family{
		Afi:  api.Family_Afi(afi),
		Safi: api.Family_Safi(safi),
	}
}
