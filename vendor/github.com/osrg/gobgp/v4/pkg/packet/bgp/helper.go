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

package bgp

import (
	"net/netip"
)

func NewTestBGPOpenMessage() *BGPMessage {
	p1 := NewOptionParameterCapability(
		[]ParameterCapabilityInterface{NewCapRouteRefresh()})
	p2 := NewOptionParameterCapability(
		[]ParameterCapabilityInterface{NewCapMultiProtocol(RF_IPv4_UC)})
	g := &CapGracefulRestartTuple{4, 2, 3}
	p3 := NewOptionParameterCapability(
		[]ParameterCapabilityInterface{NewCapGracefulRestart(false, true, 100,
			[]*CapGracefulRestartTuple{g})})
	p4 := NewOptionParameterCapability(
		[]ParameterCapabilityInterface{NewCapFourOctetASNumber(100000)})
	p5 := NewOptionParameterCapability(
		[]ParameterCapabilityInterface{NewCapAddPath([]*CapAddPathTuple{NewCapAddPathTuple(RF_IPv4_UC, BGP_ADD_PATH_BOTH)})})
	msg, _ := NewBGPOpenMessage(11033, 303, netip.MustParseAddr("100.4.10.3"),
		[]OptionParameterInterface{p1, p2, p3, p4, p5})
	return msg
}

func NewTestBGPUpdateMessage() *BGPMessage {
	w1, _ := NewIPAddrPrefix(netip.MustParsePrefix("121.1.3.2/23"))
	w2, _ := NewIPAddrPrefix(netip.MustParsePrefix("100.33.3.0/17"))
	w := []NLRI{w1, w2}

	aspath2 := []AsPathParamInterface{
		NewAs4PathParam(2, []uint32{1000000}),
		NewAs4PathParam(1, []uint32{1000001, 1002}),
		NewAs4PathParam(2, []uint32{1003, 100004}),
	}

	aspath3 := []*As4PathParam{
		NewAs4PathParam(2, []uint32{1000000}),
		NewAs4PathParam(1, []uint32{1000001, 1002}),
		NewAs4PathParam(2, []uint32{1003, 100004}),
	}

	isTransitive := true

	ex3, _ := NewIPv4AddressSpecificExtended(EC_SUBTYPE_ROUTE_TARGET, netip.MustParseAddr("192.2.1.2"), 3000, isTransitive)
	ecommunities := []ExtendedCommunityInterface{
		NewTwoOctetAsSpecificExtended(EC_SUBTYPE_ROUTE_TARGET, 10003, 3<<20, isTransitive),
		NewFourOctetAsSpecificExtended(EC_SUBTYPE_ROUTE_TARGET, 1<<20, 300, isTransitive),
		ex3,
		NewOpaqueExtended(false, []byte{1, 2, 3, 4, 5, 6, 7}),
		NewValidationExtended(VALIDATION_STATE_INVALID),
		NewUnknownExtended(99, []byte{0, 1, 2, 3, 4, 5, 6, 7}),
		NewESILabelExtended(1000, true),
		NewESImportRouteTarget("11:22:33:44:55:66"),
		NewMacMobilityExtended(123, false),
	}

	vpn1, _ := NewLabeledVPNIPAddrPrefix(netip.MustParsePrefix("192.0.9.0/24"), *NewMPLSLabelStack(1, 2, 3),
		NewRouteDistinguisherTwoOctetAS(256, 10000))
	rd, _ := NewRouteDistinguisherIPAddressAS(netip.MustParseAddr("10.0.1.1"), 10001)
	vpn2, _ := NewLabeledVPNIPAddrPrefix(netip.MustParsePrefix("192.10.8.0/24"), *NewMPLSLabelStack(5, 6, 7, 8), rd)
	prefixes1 := []NLRI{vpn1, vpn2}

	nlri, _ := NewIPAddrPrefix(netip.MustParsePrefix("fe80:1234:1234:5667:8967:af12:8912:1023/128"))
	prefixes2 := []NLRI{nlri}

	vpn3, _ := NewLabeledVPNIPAddrPrefix(netip.MustParsePrefix("fe80:1234:1234:5667:8967:af12:1203:33a1/128"), *NewMPLSLabelStack(5, 6), NewRouteDistinguisherFourOctetAS(5, 6))
	prefixes3 := []NLRI{vpn3}

	mpls, _ := NewLabeledIPAddrPrefix(netip.MustParsePrefix("192.168.0.0/25"), *NewMPLSLabelStack(5, 6, 7))
	prefixes4 := []NLRI{mpls}

	r2, _ := NewEVPNMacIPAdvertisementRoute(NewRouteDistinguisherFourOctetAS(5, 6), EthernetSegmentIdentifier{ESI_ARBITRARY, make([]byte, 9)}, 3, "01:23:45:67:89:ab", netip.MustParseAddr("192.2.1.2"), []uint32{3, 4})
	r3, _ := NewEVPNMulticastEthernetTagRoute(NewRouteDistinguisherFourOctetAS(5, 6), 3, netip.MustParseAddr("192.2.1.2"))
	r4, _ := NewEVPNEthernetSegmentRoute(NewRouteDistinguisherFourOctetAS(5, 6), EthernetSegmentIdentifier{ESI_ARBITRARY, make([]byte, 9)}, netip.MustParseAddr("192.2.1.1"))
	r5, _ := NewEVPNIPPrefixRoute(NewRouteDistinguisherFourOctetAS(5, 6), EthernetSegmentIdentifier{ESI_ARBITRARY, make([]byte, 9)}, 5, 24, netip.MustParseAddr("192.2.1.0"), netip.MustParseAddr("192.3.1.1"), 5)
	prefixes5 := []NLRI{
		NewEVPNEthernetAutoDiscoveryRoute(NewRouteDistinguisherFourOctetAS(5, 6), EthernetSegmentIdentifier{ESI_ARBITRARY, make([]byte, 9)}, 2, 2),
		r2,
		r3,
		r4,
		r5,
	}

	prefixes6 := []NLRI{NewVPLSNLRI(NewRouteDistinguisherFourOctetAS(5, 6), 101, 100, 10, 1000)}

	panh, _ := NewPathAttributeNextHop(netip.MustParseAddr("129.1.1.2"))
	paag1, _ := NewPathAttributeAggregator(uint16(30002), netip.MustParseAddr("129.0.2.99"))
	paag2, _ := NewPathAttributeAggregator(uint32(30002), netip.MustParseAddr("129.0.2.99"))
	paag3, _ := NewPathAttributeAggregator(uint32(300020), netip.MustParseAddr("129.0.2.99"))
	paag4, _ := NewPathAttributeAs4Aggregator(10000, netip.MustParseAddr("112.22.2.1"))
	paorig, _ := NewPathAttributeOriginatorId(netip.MustParseAddr("10.10.0.1"))
	pacluster, _ := NewPathAttributeClusterList([]netip.Addr{netip.MustParseAddr("10.10.0.2"), netip.MustParseAddr("10.10.0.3")})
	p := []PathAttributeInterface{
		NewPathAttributeOrigin(3),
		NewPathAttributeAsPath(aspath2),
		panh,
		NewPathAttributeMultiExitDisc(1 << 20),
		NewPathAttributeLocalPref(1 << 22),
		NewPathAttributeAtomicAggregate(),
		paag1,
		paag2,
		paag3,
		NewPathAttributeCommunities([]uint32{1, 3}),
		paorig,
		pacluster,
		NewPathAttributeExtendedCommunities(ecommunities),
		NewPathAttributeAs4Path(aspath3),
		paag4,
	}
	toList := func(l []NLRI) []PathNLRI {
		r := make([]PathNLRI, 0, len(l))
		for _, p := range l {
			r = append(r, PathNLRI{NLRI: p})
		}
		return r
	}

	// Create MP_REACH_NLRI attributes with error handling
	mp1, _ := NewPathAttributeMpReachNLRI(RF_IPv4_VPN, toList(prefixes1), netip.MustParseAddr("112.22.2.0"))
	mp2, _ := NewPathAttributeMpReachNLRI(RF_IPv6_UC, toList(prefixes2), netip.MustParseAddr("1023::"))
	mp3, _ := NewPathAttributeMpReachNLRI(RF_IPv6_VPN, toList(prefixes3), netip.MustParseAddr("fe80::"))
	mp4, _ := NewPathAttributeMpReachNLRI(RF_IPv4_MPLS, toList(prefixes4), netip.MustParseAddr("129.1.1.1"))
	mp5, _ := NewPathAttributeMpReachNLRI(RF_EVPN, toList(prefixes5), netip.MustParseAddr("129.1.1.1"))
	mp6, _ := NewPathAttributeMpReachNLRI(RF_VPLS, toList(prefixes6), netip.MustParseAddr("135.1.1.1"))
	mpUnreach1, _ := NewPathAttributeMpUnreachNLRI(RF_IPv4_VPN, toList(prefixes1))
	p = append(p, mp1, mp2, mp3, mp4, mp5, mp6, mpUnreach1,
		// NewPathAttributeMpReachNLRI("112.22.2.0", []NLRI{}),
		// NewPathAttributeMpUnreachNLRI([]NLRI{}),
		NewPathAttributeUnknown(BGP_ATTR_FLAG_TRANSITIVE, 100, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}),
	)
	prefix, _ := NewIPAddrPrefix(netip.MustParsePrefix("13.2.3.1/24"))
	n := []NLRI{prefix}
	return NewBGPUpdateMessage(toList(w), p, toList(n))
}
