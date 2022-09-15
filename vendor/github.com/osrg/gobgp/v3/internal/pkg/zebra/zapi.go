// Copyright (C) 2014, 2015 Nippon Telegraph and Telephone Corporation.
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

package zebra

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/osrg/gobgp/v3/pkg/log"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
)

const (
	// MinZapiVer is minimum zebra api version which is referred in zclient
	MinZapiVer uint8 = 2
	// MaxZapiVer is maximum zebra api version which is referredd in zclient
	MaxZapiVer uint8 = 6
	// DefaultVrf is default vrf id is referredd in zclient and server
	DefaultVrf = 0
)

const (
	headerMarker      uint8 = 255
	frrHeaderMarker   uint8 = 254
	interfaceNameSize       = 20
	maxPathNum              = 64
	maxMplsLabel            = 16
)

// Internal Interface Status.
type interfaceStatus uint8

const (
	interfaceActive        interfaceStatus = 0x01
	interfaceSub           interfaceStatus = 0x02
	interfaceLinkDetection interfaceStatus = 0x04
	interfaceVrfLoopback   interfaceStatus = 0x08
)

// Interface Link Layer Types.
//
//go:generate stringer -type=linkType
type linkType uint32

const (
	linkTypeUnknown linkType = iota
	linkTypeEther
	linkTypeEEther
	linkTypeAX25
	linkTypePRONET
	linkTypeIeee802
	linkTypeARCNET
	linkTypeAPPLETLK
	linkTypeDLCI
	linkTypeATM
	linkTypeMetricOM
	linkTypeIeee1394
	linkTypeEUI64
	linkTypeINFINIBAND
	linkTypeSLIP
	linkTypeCSLIP
	linkTypeSLIP6
	linkTypeCSLIP6
	linkTypeRSRVD
	linkTypeADAPT
	linkTypeROSE
	linkTypeX25
	linkTypePPP
	linkTypeCHDLC
	linkTypeLAPB
	linkTypeRAWHDLC
	linkTypeIPIP
	linkTypeIPIP6
	linkTypeFRAD
	linkTypeSKIP
	linkTypeLOOPBACK
	linkTypeLOCALTLK
	linkTypeFDDI
	linkTypeSIT
	linkTypeIPDDP
	linkTypeIPGRE
	linkTypeIP6GRE
	linkTypePIMREG
	linkTypeHIPPI
	linkTypeECONET
	linkTypeIRDA
	linkTypeFCPP
	linkTypeFCAL
	linkTypeFCPL
	linkTypeFCFABRIC
	linkTypeIeee802Tr
	linkTypeIeee80211
	linkTypeIeee80211RadioTap
	linkTypeIeee802154
	linkTypeIeee802154Phy
)

// HeaderSize returns suitable header size from version
func HeaderSize(version uint8) uint16 {
	switch version {
	case 3, 4:
		return 8
	case 5, 6:
		return 10
	}
	return 6 // version == 2
}

// HeaderMarker returns suitable header marker from version
func HeaderMarker(version uint8) uint8 {
	if version > 3 {
		return frrHeaderMarker
	}
	return headerMarker
}

func (t interfaceStatus) String() string {
	ss := make([]string, 0, 3)
	if t&interfaceActive > 0 {
		ss = append(ss, "Active")
	}
	if t&interfaceSub > 0 {
		ss = append(ss, "Sub")
	}
	if t&interfaceLinkDetection > 0 {
		ss = append(ss, "LinkDetection")
	}
	if t&interfaceVrfLoopback > 0 {
		ss = append(ss, "VrfLoopback")
	}
	return strings.Join(ss, "|")
}

// Interface Connected Address Flags
type interfaceAddressFlag uint8

const (
	interfaceAddressSecondary  interfaceAddressFlag = 0x01
	interfaceAddressPeer       interfaceAddressFlag = 0x02
	interfaceAddressUnnumbered interfaceAddressFlag = 0x04
)

func (t interfaceAddressFlag) String() string {
	ss := make([]string, 0, 3)
	if t&interfaceAddressSecondary > 0 {
		ss = append(ss, "SECONDARY")
	}
	if t&interfaceAddressPeer > 0 {
		ss = append(ss, "PEER")
	}
	if t&interfaceAddressUnnumbered > 0 {
		ss = append(ss, "UNNUMBERED")
	}
	return strings.Join(ss, "|")
}

// Address Family IDentifier.
//
//go:generate stringer -type=afi
type afi uint8

const (
	afiIP    afi = 1
	afiIP6   afi = 2
	afiEther afi = 3
	afiMax   afi = 4
)

// Safi is Subsequent Address Family IDentifier.
//
//go:generate stringer -type=Safi
type Safi uint8

// Safi definition in Zebra of FRRouting 4.x, 5.x, 6.x, 7.x, and 8.x(lib/zebra.h)
const (
	safiUnspec Safi = iota // added in FRRouting version 7.2 (Zapi 6)
	SafiUnicast
	safiMulticast
	safiMplsVpn
	safiEncap
	safiEvpn
	safiLabeledUnicast
	safiFlowspec // added in FRRouting version 5 (Zapi 5)
	safiMax
)

// Safi definition in Zebra of Quagga and FRRouting 3.x
const (
	zapi4SafiMplsVpn Safi = iota + safiMulticast + 1 // SafiRESERVED_3 in quagga
	zapi3SafiMplsVpn                                 // SafiRESERVED_4 in FRRouting 3.x
	zapi4SafiEncap
	zapi4SafiEvpn
	zapi3SafiEncap // SafiMax in FRRouting 3.x
)

var zapi3SafiMap = map[Safi]Safi{
	zapi3SafiMplsVpn: safiMplsVpn,
	zapi3SafiEncap:   safiEncap,
}
var zapi4SafiMap = map[Safi]Safi{
	zapi4SafiMplsVpn: safiMplsVpn,
	zapi4SafiEncap:   safiEncap,
	zapi4SafiEvpn:    safiEvpn,
}
var safiRouteFamilyIPv4Map = map[Safi]bgp.RouteFamily{
	safiUnspec:         bgp.RF_OPAQUE,
	SafiUnicast:        bgp.RF_IPv4_UC,
	safiMulticast:      bgp.RF_IPv4_MC,
	safiMplsVpn:        bgp.RF_IPv4_VPN,
	safiEncap:          bgp.RF_IPv4_ENCAP,
	safiLabeledUnicast: bgp.RF_IPv4_MPLS,
	safiFlowspec:       bgp.RF_FS_IPv4_UC,
}
var safiRouteFamilyIPv6Map = map[Safi]bgp.RouteFamily{
	safiUnspec:         bgp.RF_OPAQUE,
	SafiUnicast:        bgp.RF_IPv6_UC,
	safiMulticast:      bgp.RF_IPv6_MC,
	safiMplsVpn:        bgp.RF_IPv6_VPN,
	safiEncap:          bgp.RF_IPv6_ENCAP,
	safiLabeledUnicast: bgp.RF_IPv6_MPLS,
	safiFlowspec:       bgp.RF_FS_IPv6_UC,
}

// APIType is referred in zclient_test.
//
//go:generate stringer -type=APIType
type APIType uint16

// For FRRouting version 8.1 (ZAPI version 6)
const (
	interfaceAdd           APIType = iota // 0 // same ID in frr3, 4, 5, 6, 7.0, 7.1. 7.2. 7.3, 7.4, 7.5, 8.0, 8.1, 8.2
	interfaceDelete                       // same ID in frr3, 4, 5, 6, 7.0, 7.1. 7.2. 7.3, 7.4, 7.5, 8.0, 8.1, 8.2
	interfaceAddressAdd                   // same ID in frr3, 4, 5, 6, 7.0, 7.1. 7.2. 7.3, 7.4, 7.5, 8.0, 8.1, 8.2
	interfaceAddressDelete                // same ID in frr3, 4, 5, 6, 7.0, 7.1. 7.2. 7.3, 7.4, 7.5, 8.0, 8.1, 8.2
	interfaceUp                           // same ID in frr3, 4, 5, 6, 7.0, 7.1. 7.2. 7.3, 7.4, 7.5, 8.0, 8.1, 8.2
	interfaceDown                         // same ID in frr3, 4, 5, 6, 7.0, 7.1. 7.2. 7.3, 7.4, 7.5, 8.0, 8.1, 8.2
	_interfaceSetMaster
	_interfaceSetProtoDown // Add in frr 7.2
	RouteAdd               // RouteAdd is referred in zclient_test
	RouteDelete            // RouteDelete is referred in zclient_test
	_routeNotifyOwner      // 10
	redistributeAdd
	_redistributeDelete
	_redistributeDefaultAdd
	_redistributeDefaultDelete
	routerIDAdd
	_routerIDDelete
	routerIDUpdate
	hello
	_capabilities   // added in frr5
	nexthopRegister // 20
	nexthopUnregister
	nexthopUpdate
	_interfaceNBRAddressAdd
	_interfaceNBRAddressDelete
	_interfaceBFDDestUpdate
	_importRouteRegister   // 25 in frr6, 26 in frr7.x, frr8&8.1, deleted in frr8.2
	_importRouteUnregister // 26 in frr6, 27 in frr7.x, frr8&8.1, deleted in frr8.2
	_importCheckUpdate     // 27 in frr6, 28 in frr7.x, frr8&8.1, deleted in frr8.2
	_bfdDestRegister
	_bfdDestDeregister // 30
	_bfdDestUpdate
	_bfdDestReplay
	redistributeRouteAdd // 33 // 30 in frr8.2
	redistributeRouteDel
	_vrfUnregister
	_vrfAdd
	_vrfDelete
	vrfLabel // added in frr5
	_interfaceVRFUpdate
	_bfdClientRegister // 40
	_bfdClientDeregister
	_interfaceEnableRADV
	_interfaceDisableRADV // 43 // 50 in frr8.2
	ipv4NexthopLookupMRIB
	_interfaceLinkParams
	_mplsLabelsAdd
	_mplsLabelsDelete
	_mplsLabelsReplace    // added in frr7.3
	_srPolicySet          // added in frr7.5
	_srPolicyDelete       // 50 // added in frr7.5
	_srPolicyNotifyStatus // added in frr7.5
	_ipmrRouteStats
	labelManagerConnect      // 53 // 50 in frr8.2
	labelManagerConnectAsync // added in frr5
	getLabelChunk
	releaseLabelChunk
	_fecRegister
	_fecUnregister
	_fecUpdate
	_advertiseDefaultGW // 60
	_advertiseSviMACIP  // added in frr7.1
	_advertiseSubnet
	_advertiseAllVNI // 63 // 60 in frr8.2
	_localESAdd
	_localESDel
	_remoteESVTEPAdd // added in frr7.5
	_remoteESVTEPDel // added in frr7.5
	_localESEVIAdd   // added in frr7.5
	_localESEVIDel   // added in frr7.5
	_vniAdd          // 70
	_vniDel
	_l3VNIAdd
	_l3VNIDel // 73 // 70 in frr8.2
	_remoteVTEPAdd
	_remoteVTEPDel
	_macIPAdd
	_macIPDel
	_ipPrefixRouteAdd
	_ipPrefixRouteDel
	_remoteMACIPAdd // 80
	_remoteMACIPDel
	_duplicateAddrDetection
	_pwAdd // 83 // 80 in frr8.2
	_pwDelete
	_pwSet
	_pwUnset
	_pwStatusUpdate
	_ruleAdd
	_ruleDelete
	_ruleNotifyOwner // 90
	_tableManagerConnect
	_getTableChunk
	_releaseTableChunk // 93 // 90 in frr8.2
	_ipSetCreate
	_ipSetDestroy
	_ipSetEntryAdd
	_ipSetEntryDelete
	_ipSetNotifyOwner
	_ipSetEntryNotifyOwner
	_ipTableAdd // 100
	_ipTableDelete
	_ipTableNotifyOwner
	_vxlanFloodControl // 103 // 100 in frr8.2
	_vxlanSgAdd
	_vxlanSgDel
	_vxlanSgReplay
	_mlagProcessUp                  // added in frr7.3
	_mlagProcessDown                // added in frr7.3
	_mlagClientRegister             // added in frr7.3
	_mlagClientUnregister           // 110 // added in frr7.3
	_mlagClientForwardMsg           // added in frr7.3
	_nhgAdd                         // added in frr8
	_nhgDel                         // 113 // 110 in frr8.2 // added in frr8
	_nhgNotifyOwner                 // added in frr8
	_nhgEvpnRemoteNhAdd             // added in frr8
	_nhgEvpnRemoteNhDel             // added in frr8
	_srv6LocatorAdd                 // added in frr8.1
	_srv6LocatorDelete              // added in frr8.1
	_srv6ManagerGetLocatorChunk     // added in frr8.1
	_srv6ManagerReleaseLocatorChunk // 120 //added in frr8.1
	zebraError                      // added in frr7.3
	_clientCapabilities             // added in frr7.4
	_opaqueMessage                  // 123 // 120 in frr8.2 // added in frr7.5
	_opaqueRegister                 // added in frr7.5
	_opaqueUnregister               // added in frr7.5
	_neighDiscover                  // added in frr7.5
	_RouteNotifyRequest             // added in frr8
	_ClientCloseNotify              // added in frr8
	_NhrpNeighAdded                 // added in frr8
	_NhrpNeighRemoved               // 130 // added in frr8
	_NhrpNeighGet                   // added in frr8
	_NhrpNeighRegister              // added in frr8
	_NhrpNeighUnregister            // 133// 130 in frr8.2 // added in frr8
	_NeighIPAdd                     // added in frr8
	_NeighIPDel                     // added in frr8
	_ConfigureArp                   // added in frr8
	_GreGet                         // added in frr8
	_GreUpdate                      // added in frr8
	_GreSourceSet                   // added in frr8
	// BackwardIPv6RouteAdd is referred in zclient_test
	BackwardIPv6RouteAdd // quagga, frr3, frr4, frr5
	// BackwardIPv6RouteDelete is referred in zclient_test
	BackwardIPv6RouteDelete // quagga, frr3, frr4, frr5
)

// Difference default version (frr8.1) and older version
const (
	zapi6Frr8dot2MinDifferentAPIType APIType = 26 //frr8.2(zapi6)
	zapi6Frr7dot3MinDifferentAPIType APIType = 49 //frr7.3(zapi6)
	zapi6Frr7dot2MinDifferentAPIType APIType = 48 //frr7.2(zapi6)
	zapi6Frr6MinDifferentAPIType     APIType = 7  //frr6&7.0&7.1(zapi6)
	zapi5ClMinDifferentAPIType       APIType = 19 //cumuluslinux3.7.7, zebra4.0+cl3u13(zapi5)
	zapi5MinDifferentAPIType         APIType = 7  //frr4&5(zapi5), frr6&7.0&7.1(zapi6)
	zapi4MinDifferentAPIType         APIType = 6
	zapi3MinDifferentAPIType         APIType = 0
)

func minDifferentAPIType(version uint8, software Software) APIType {
	if version < 4 {
		return zapi3MinDifferentAPIType
	} else if version == 4 {
		return zapi4MinDifferentAPIType
	} else if version == 5 && software.name == "cumulus" {
		return zapi5ClMinDifferentAPIType
	} else if version == 5 ||
		(version == 6 && software.name == "frr" && software.version < 7.2) {
		return zapi5MinDifferentAPIType
	} else if version == 6 && software.name == "frr" && software.version == 7.2 {
		return zapi6Frr7dot2MinDifferentAPIType
	} else if version == 6 && software.name == "frr" && software.version < 7.5 {
		return zapi6Frr7dot3MinDifferentAPIType
	}
	return zapi6Frr8dot2MinDifferentAPIType
}

const (
	zapi6Frr8dot2RedistributeRouteAdd     APIType = 30
	zapi6Frr8dot2RedistributeRouteDel     APIType = 31
	zapi6Frr8dot2VrfLabel                 APIType = 35
	zapi6Frr8dot2Ipv4NexthopLookupMRIB    APIType = 41
	zapi6Frr8dot2LabelManagerConnect      APIType = 50
	zapi6Frr8dot2LabelManagerConnectAsync APIType = 51
	zapi6Frr8dot2GetLabelChunk            APIType = 52
	zapi6Frr8dot2ReleaseLabelChunk        APIType = 53
)

var apiTypeZapi6Frr8dot2Map = map[APIType]APIType{ // frr8.2
	redistributeRouteAdd:     zapi6Frr8dot2RedistributeRouteAdd,
	redistributeRouteDel:     zapi6Frr8dot2RedistributeRouteDel,
	vrfLabel:                 zapi6Frr8dot2VrfLabel,
	ipv4NexthopLookupMRIB:    zapi6Frr8dot2Ipv4NexthopLookupMRIB,
	labelManagerConnect:      zapi6Frr8dot2LabelManagerConnect,
	labelManagerConnectAsync: zapi6Frr8dot2LabelManagerConnectAsync,
	getLabelChunk:            zapi6Frr8dot2GetLabelChunk,
	releaseLabelChunk:        zapi6Frr8dot2ReleaseLabelChunk,
}

const (
	zapi6Frr7dot3LabelManagerConnect      APIType = 50 // difference from frr8.1
	zapi6Frr7dot3LabelManagerConnectAsync APIType = 51 // difference from frr8.1
	zapi6Frr7dot3GetLabelChunk            APIType = 52 // difference from frr8.1
	zapi6Frr7dot3ReleaseLabelChunk        APIType = 53 // difference from frr8.1
)

var apiTypeZapi6Frr7dot3Map = map[APIType]APIType{
	labelManagerConnect:      zapi6Frr7dot3LabelManagerConnect,
	labelManagerConnectAsync: zapi6Frr7dot3LabelManagerConnectAsync,
	getLabelChunk:            zapi6Frr7dot3GetLabelChunk,
	releaseLabelChunk:        zapi6Frr7dot3ReleaseLabelChunk,
}

const (
	zapi6Frr7dot2LabelManagerConnect      APIType = 49 // difference from frr8.1
	zapi6Frr7dot2LabelManagerConnectAsync APIType = 50 // difference from frr8.1
	zapi6Frr7dot2GetLabelChunk            APIType = 51 // difference from frr8.1
	zapi6Frr7dot2ReleaseLabelChunk        APIType = 52 // difference from frr8.1
)

var apiTypeZapi6Frr7dot2Map = map[APIType]APIType{
	labelManagerConnect:      zapi6Frr7dot2LabelManagerConnect,
	labelManagerConnectAsync: zapi6Frr7dot2LabelManagerConnectAsync,
	getLabelChunk:            zapi6Frr7dot2GetLabelChunk,
	releaseLabelChunk:        zapi6Frr7dot2ReleaseLabelChunk,
}

const ( // frr7.0, 7.1
	zapi6Frr7RouteAdd                 APIType = 7
	zapi6Frr7RouteDelete              APIType = 8
	zapi6Frr7RedistributAdd           APIType = 10
	zapi6Frr7RouterIDAdd              APIType = 14
	zapi6Frr7RouterIDUpdate           APIType = 16
	zapi6Frr7Hello                    APIType = 17
	zapi6Frr7NexthopRegister          APIType = 19
	zapi6Frr7NexthopUnregister        APIType = 20
	zapi6Frr7NexthopUpdate            APIType = 21
	zapi6Frr7RedistributeRouteAdd     APIType = 32
	zapi6Frr7RedistributeRouteDel     APIType = 33
	zapi6Frr7VrfLabel                 APIType = 37
	zapi6Frr7Ipv4NexthopLookupMRIB    APIType = 43
	zapi6Frr7LabelManagerConnect      APIType = 48
	zapi6Frr7LabelManagerConnectAsync APIType = 49
	zapi6Frr7GetLabelChunk            APIType = 50
	zapi6Frr7ReleaseLabelChunk        APIType = 51
)

var apiTypeZapi6Frr7Map = map[APIType]APIType{ // frr7.0, 7.1
	RouteAdd:                 zapi6Frr7RouteAdd,
	RouteDelete:              zapi6Frr7RouteDelete,
	redistributeAdd:          zapi6Frr7RedistributAdd,
	routerIDAdd:              zapi6Frr7RouterIDAdd,
	routerIDUpdate:           zapi6Frr7RouterIDUpdate,
	hello:                    zapi6Frr7Hello,
	nexthopRegister:          zapi6Frr7NexthopRegister,
	nexthopUnregister:        zapi6Frr7NexthopUnregister,
	nexthopUpdate:            zapi6Frr7NexthopUpdate,
	redistributeRouteAdd:     zapi6Frr7RedistributeRouteAdd,
	redistributeRouteDel:     zapi6Frr7RedistributeRouteDel,
	vrfLabel:                 zapi6Frr7VrfLabel,
	ipv4NexthopLookupMRIB:    zapi6Frr7Ipv4NexthopLookupMRIB,
	labelManagerConnect:      zapi6Frr7LabelManagerConnect,
	labelManagerConnectAsync: zapi6Frr7LabelManagerConnectAsync,
	getLabelChunk:            zapi6Frr7GetLabelChunk,
	releaseLabelChunk:        zapi6Frr7ReleaseLabelChunk,
}

var apiTypeZapi6Frr6Map = map[APIType]APIType{
	RouteAdd:                 zapi6Frr7RouteAdd,                     // same as frr7.0&7.1
	RouteDelete:              zapi6Frr7RouteDelete,                  // same as frr7.0&7.1
	redistributeAdd:          zapi6Frr7RedistributAdd,               // same as frr7.0&7.1
	routerIDAdd:              zapi6Frr7RouterIDAdd,                  // same as frr7.0&7.1
	routerIDUpdate:           zapi6Frr7RouterIDUpdate,               // same as frr7.0&7.1
	hello:                    zapi6Frr7Hello,                        // same as frr7.0&7.1
	nexthopRegister:          zapi6Frr7NexthopRegister,              // same as frr7.0&7.1
	nexthopUnregister:        zapi6Frr7NexthopUnregister,            // same as frr7.0&7.1
	nexthopUpdate:            zapi6Frr7NexthopUpdate,                // same as frr7.0&7.1
	redistributeRouteAdd:     redistributeRouteAdd,                  // same as frr7.2&7.3
	redistributeRouteDel:     redistributeRouteDel,                  // same as frr7.2&7.3
	vrfLabel:                 vrfLabel,                              // same as frr7.2&7.3
	ipv4NexthopLookupMRIB:    ipv4NexthopLookupMRIB,                 // same as frr7.2&7.3
	labelManagerConnect:      zapi6Frr7dot2LabelManagerConnect,      // same as frr7.2
	labelManagerConnectAsync: zapi6Frr7dot2LabelManagerConnectAsync, // same as frr7.2
	getLabelChunk:            zapi6Frr7dot2GetLabelChunk,            // same as frr7.2
	releaseLabelChunk:        zapi6Frr7dot2ReleaseLabelChunk,        // same as frr7.2
}

const ( // For Cumulus Linux 3.7.7, zebra 4.0+cl3u13  (ZAPI version 5)
	zapi5ClIpv4NexthopLookupMRIB APIType = 42
	zapi5ClLabelManagerConnect   APIType = 47
	zapi5ClGetLabelChunk         APIType = 48
	zapi5ClReleaseLabelChunk     APIType = 49
)

var apiTypeZapi5ClMap = map[APIType]APIType{
	nexthopRegister:      zapi6Frr7NexthopRegister,      // same as frr7.0&7.1
	nexthopUnregister:    zapi6Frr7NexthopUnregister,    // same as frr7.0&7.1
	nexthopUpdate:        zapi6Frr7NexthopUpdate,        // same as frr7.0&7.1
	redistributeRouteAdd: zapi6Frr7RedistributeRouteAdd, // same as frr7.0&7.1
	redistributeRouteDel: zapi6Frr7RedistributeRouteDel, // same as frr7.0&7.1
	vrfLabel:             zapi6Frr7VrfLabel,             // same as frr7.0&7.1
	labelManagerConnect:  zapi5ClLabelManagerConnect,
	getLabelChunk:        zapi5ClGetLabelChunk,
	releaseLabelChunk:    zapi5ClReleaseLabelChunk,
}

const (
	zapi5RedistributAdd               APIType = 14
	zapi5RouterIDAdd                  APIType = 18
	zapi5RouterIDUpdate               APIType = 20
	zapi5Hello                        APIType = 21
	zapi5Frr5NexthopRegister          APIType = 23
	zapi5Frr5NexthopUnregister        APIType = 24
	zapi5Frr5NexthopUpdate            APIType = 25
	zapi5Frr5RedistributeRouteAdd     APIType = 37
	zapi5Frr5RedistributeRouteDel     APIType = 38
	zapi5Frr5VrfLabel                 APIType = 42
	zapi5Frr5Ipv4NexthopLookupMRIB    APIType = 47
	zapi5Frr5LabelManagerConnect      APIType = 52
	zapi5Frr5LabelManagerConnectAsync APIType = 53
	zapi5Frr5GetLabelChunk            APIType = 54
	zapi5Frr5ReleaseLabelChunk        APIType = 55
)

var apiTypeZapi5Frr5Map = map[APIType]APIType{
	RouteAdd:                 zapi6Frr7RouteAdd,    // same as frr7.0&7.1
	RouteDelete:              zapi6Frr7RouteDelete, // same as frr7.0&7.1
	redistributeAdd:          zapi5RedistributAdd,
	routerIDAdd:              zapi5RouterIDAdd,
	routerIDUpdate:           zapi5RouterIDUpdate,
	hello:                    zapi5Hello,
	nexthopRegister:          zapi5Frr5NexthopRegister,
	nexthopUnregister:        zapi5Frr5NexthopUnregister,
	nexthopUpdate:            zapi5Frr5NexthopUpdate,
	redistributeRouteAdd:     zapi5Frr5RedistributeRouteAdd,
	redistributeRouteDel:     zapi5Frr5RedistributeRouteDel,
	vrfLabel:                 zapi5Frr5VrfLabel,
	ipv4NexthopLookupMRIB:    zapi5Frr5Ipv4NexthopLookupMRIB,
	labelManagerConnect:      zapi5Frr5LabelManagerConnect,
	labelManagerConnectAsync: zapi5Frr5LabelManagerConnectAsync,
	getLabelChunk:            zapi5Frr5GetLabelChunk,
	releaseLabelChunk:        zapi5Frr5ReleaseLabelChunk,
}

const (
	zapi5Frr4NexthopRegister       APIType = 22
	zapi5Frr4NexthopUnregister     APIType = 23
	zapi5Frr4NexthopUpdate         APIType = 24
	zapi5Frr4RedistributeRouteAdd  APIType = 36
	zapi5Frr4RedistributeRouteDel  APIType = 37
	zapi5Frr4Ipv4NexthopLookupMRIB APIType = 45
	zapi5Frr4LabelManagerConnect   APIType = 50
	zapi5Frr4GetLabelChunk         APIType = 51
	zapi5Frr4ReleaseLabelChunk     APIType = 52
)

var apiTypeZapi5Frr4Map = map[APIType]APIType{
	RouteAdd:              zapi6Frr7RouteAdd,    // same as frr7.0&7.1
	RouteDelete:           zapi6Frr7RouteDelete, // same as frr7.0&7.1
	redistributeAdd:       zapi5RedistributAdd,
	routerIDAdd:           zapi5RouterIDAdd,
	routerIDUpdate:        zapi5RouterIDUpdate,
	hello:                 zapi5Hello,
	nexthopRegister:       zapi5Frr4NexthopRegister,
	nexthopUnregister:     zapi5Frr4NexthopUnregister,
	nexthopUpdate:         zapi5Frr4NexthopUpdate,
	redistributeRouteAdd:  zapi5Frr4RedistributeRouteAdd,
	redistributeRouteDel:  zapi5Frr4RedistributeRouteDel,
	ipv4NexthopLookupMRIB: zapi5Frr4Ipv4NexthopLookupMRIB,
	labelManagerConnect:   zapi5Frr4LabelManagerConnect,
	getLabelChunk:         zapi5Frr4GetLabelChunk,
	releaseLabelChunk:     zapi5Frr4ReleaseLabelChunk,
}

const (
	zapi4IPv4RouteAdd        APIType = 6 // deleted in zapi6
	zapi4IPv4RouteDelete     APIType = 7 // deleted in zapi6
	zapi4IPv6RouteAdd        APIType = 8 // deleted in zapi6
	zapi4IPv6RouteDelete     APIType = 9 // deleted in zapi6
	zapi4RedistributAdd      APIType = 10
	zapi4RouterIDAdd         APIType = 14
	zapi4RouterIDUpdate      APIType = 16
	zapi4Hello               APIType = 17
	zapi4NexthopRegister     APIType = 18
	zapi4NexthopUnregister   APIType = 19
	zapi4NexthopUpdate       APIType = 20
	zapi4RedistributeIPv4Add APIType = 32 // deleted in zapi6
	zapi4RedistributeIPv4Del APIType = 33 // deleted in zapi6
	zapi4RedistributeIPv6Add APIType = 34 // deleted in zapi6
	zapi4RedistributeIPv6Del APIType = 35 // deleted in zapi6
	zapi4LabelManagerConnect APIType = 52
	zapi4GetLabelChunk       APIType = 53
	zapi4ReleaseLabelChunk   APIType = 54
)

var apiTypeZapi4Map = map[APIType]APIType{
	RouteAdd:                zapi4IPv4RouteAdd,    // deleted in zapi5
	RouteDelete:             zapi4IPv4RouteDelete, // deleted in zapi5
	redistributeAdd:         zapi4RedistributAdd,
	routerIDAdd:             zapi4RouterIDAdd,
	routerIDUpdate:          zapi4RouterIDUpdate,
	hello:                   zapi4Hello,
	nexthopRegister:         zapi4NexthopRegister,
	nexthopUnregister:       zapi4NexthopUnregister,
	nexthopUpdate:           zapi4NexthopUpdate,
	redistributeRouteAdd:    zapi4RedistributeIPv4Add,       // deleted in zapi5
	redistributeRouteDel:    zapi4RedistributeIPv4Del,       // deleted in zapi5
	ipv4NexthopLookupMRIB:   zapi6Frr7Ipv4NexthopLookupMRIB, // same as frr7.0&7.1
	labelManagerConnect:     zapi4LabelManagerConnect,
	getLabelChunk:           zapi4GetLabelChunk,
	releaseLabelChunk:       zapi4ReleaseLabelChunk,
	BackwardIPv6RouteAdd:    zapi4IPv6RouteAdd,
	BackwardIPv6RouteDelete: zapi4IPv6RouteDelete,
}

const (
	zapi3InterfaceAdd           APIType = 1
	zapi3InterfaceDelete        APIType = 2
	zapi3InterfaceAddressAdd    APIType = 3
	zapi3InterfaceAddressDelete APIType = 4
	zapi3InterfaceUp            APIType = 5
	zapi3InterfaceDown          APIType = 6
	zapi3IPv4RouteAdd           APIType = 7  // deleted in zapi5
	zapi3IPv4RouteDelete        APIType = 8  // deleted in zapi5
	zapi3IPv6RouteAdd           APIType = 9  // deleted in zapi5
	zapi3IPv6RouteDelete        APIType = 10 // deleted in zapi5
	zapi3RedistributeAdd        APIType = 11
	zapi3IPv4NexthopLookup      APIType = 15 // zapi3(quagga) only
	zapi3IPv6NexthopLookup      APIType = 16 // zapi3(quagga) only
	zapi3IPv4ImportLookup       APIType = 17 // zapi3(quagga) only
	zapi3RouterIDAdd            APIType = 20
	zapi3RouterIDUpdate         APIType = 22
	zapi3Hello                  APIType = 23
	zapi3Ipv4NexthopLookupMRIB  APIType = 24
	zapi3NexthopRegister        APIType = 27
	zapi3NexthopUnregister      APIType = 28
	zapi3NexthopUpdate          APIType = 29
)

var apiTypeZapi3Map = map[APIType]APIType{
	interfaceAdd:            zapi3InterfaceAdd,
	interfaceDelete:         zapi3InterfaceDelete,
	interfaceAddressAdd:     zapi3InterfaceAddressAdd,
	interfaceAddressDelete:  zapi3InterfaceAddressDelete,
	interfaceUp:             zapi3InterfaceUp,
	interfaceDown:           zapi3InterfaceDown,
	RouteAdd:                zapi3IPv4RouteAdd,    // deleted in zapi5
	RouteDelete:             zapi3IPv4RouteDelete, // deleted in zapi5
	redistributeAdd:         zapi3RedistributeAdd,
	routerIDAdd:             zapi3RouterIDAdd,
	routerIDUpdate:          zapi3RouterIDUpdate,
	hello:                   zapi3Hello,
	nexthopRegister:         zapi3NexthopRegister,
	nexthopUnregister:       zapi3NexthopUnregister,
	nexthopUpdate:           zapi3NexthopUpdate,
	BackwardIPv6RouteAdd:    zapi3IPv6RouteAdd,
	BackwardIPv6RouteDelete: zapi3IPv6RouteDelete,
}

func (t APIType) doesNeedConversion(version uint8, software Software) bool {
	if (version == 6 && software.name == "frr" &&
		software.version >= 7.5 && software.version < 8.2) ||
		t < minDifferentAPIType(version, software) {
		return false
	}
	return true
}
func apiTypeMap(version uint8, software Software) map[APIType]APIType {
	if version == 6 && software.name == "frr" && software.version >= 7.3 && software.version < 7.5 {
		return apiTypeZapi6Frr7dot3Map
	} else if version == 6 && software.name == "frr" && software.version == 7.2 {
		return apiTypeZapi6Frr7dot2Map
	} else if version == 6 && software.name == "frr" && software.version >= 7 && software.version < 7.2 {
		return apiTypeZapi6Frr7Map
	} else if version == 6 && software.name == "frr" && software.version >= 6 && software.version < 7 {
		return apiTypeZapi6Frr6Map
	} else if version == 5 {
		if software.name == "frr" && software.version == 4 {
			return apiTypeZapi5Frr4Map
		} else if software.name == "cumulus" {
			return apiTypeZapi5ClMap
		}
		return apiTypeZapi5Frr5Map
	} else if version == 4 {
		return apiTypeZapi4Map
	} else if version < 4 {
		return apiTypeZapi3Map
	}
	return apiTypeZapi6Frr8dot2Map
}

// ToEach is referred in zclient_test
func (t APIType) ToEach(version uint8, software Software) APIType {
	if !t.doesNeedConversion(version, software) {
		return t
	}
	apiMap := apiTypeMap(version, software)
	backward, ok := apiMap[t]
	if !ok {
		backward = zebraError // fail to convert and error value
	}
	return backward // success to convert
}
func (t APIType) toCommon(version uint8, software Software) APIType {
	if !t.doesNeedConversion(version, software) {
		return t
	}
	apiMap := apiTypeMap(version, software)
	for common, backward := range apiMap {
		if backward == t {
			return common // success to convert
		}
	}
	return zebraError // fail to convert and error value
}

func (t APIType) addressFamily(version uint8) uint8 {
	if version == 4 {
		switch t {
		case zapi4IPv4RouteAdd, zapi4IPv4RouteDelete, zapi4RedistributeIPv4Add, zapi4RedistributeIPv4Del, zapi6Frr7Ipv4NexthopLookupMRIB:
			return syscall.AF_INET
		case zapi4IPv6RouteAdd, zapi4IPv6RouteDelete, zapi4RedistributeIPv6Add, zapi4RedistributeIPv6Del:
			return syscall.AF_INET6
		}
	} else if version < 4 {
		switch t {
		case zapi3IPv4RouteAdd, zapi3IPv4RouteDelete, zapi3IPv4NexthopLookup, zapi3IPv4ImportLookup, zapi3Ipv4NexthopLookupMRIB:
			return syscall.AF_INET
		case zapi3IPv6RouteAdd, zapi3IPv6RouteDelete, zapi3IPv6NexthopLookup:
			return syscall.AF_INET6
		}
	}
	return syscall.AF_UNSPEC
}

// RouteType is referred in zclient.
//
//go:generate stringer -type=RouteType
type RouteType uint8

// For FRRouting version 7 (ZAPI version 6).
const (
	routeSystem RouteType = iota //0
	routeKernel
	routeConnect
	RouteStatic
	routeRIP
	routeRIPNG
	routeOSPF
	routeOSPF6
	routeISIS
	RouteBGP
	routePIM   // 10
	routeEIGRP // FRRRouting version 4 (Zapi5) adds.
	routeNHRP
	routeHSLS
	routeOLSR
	routeTABLE
	routeLDP
	routeVNC
	routeVNCDirect
	routeVNCDirectRH
	routeBGPDirect
	routeBGPDirectEXT
	routeBABEL
	routeSHARP
	routePBR        // FRRRouting version 5 (Zapi5) adds.
	routeBFD        // FRRRouting version 6 (Zapi6) adds.
	routeOpenfabric // FRRRouting version 7 (Zapi6) adds.
	routeVRRP       // FRRRouting version 7.2 (Zapi6) adds.
	routeNHG        // FRRRouting version 7.3 (Zapi6) adds.
	routeSRTE       // FRRRouting version 7.5 (Zapi6) adds.
	routeAll
	routeMax // max value for error
)
const (
	zapi5Frr4RouteAll     RouteType = 24
	zapi5Frr5RouteAll     RouteType = 25
	zapi6Frr6RouteAll     RouteType = 26
	zapi6Frr7RouteAll     RouteType = 27
	zapi6Frr7dot2RouteAll RouteType = 28
	zapi6Frr7dot3RouteAll RouteType = 29
)

func getRouteAll(version uint8, software Software) RouteType {
	if version == 5 {
		if software.name == "frr" && software.version == 4 {
			return zapi5Frr4RouteAll
		}
		return zapi5Frr5RouteAll
	} else if version == 6 {
		if software.name == "frr" && software.version == 6 {
			return zapi6Frr6RouteAll
		} else if software.name == "frr" && software.version >= 7 && software.version < 7.2 {
			return zapi6Frr7RouteAll
		} else if software.name == "frr" && software.version >= 7.2 && software.version < 7.3 {
			return zapi6Frr7dot2RouteAll
		} else if software.name == "frr" && software.version >= 7.3 && software.version < 7.5 {
			return zapi6Frr7dot3RouteAll
		}
	}
	return routeAll
}

// For FRRouting version 3.0 except common route type.
const (
	zapi4RouteNHRP RouteType = iota + routePIM + 1
	zapi4RouteHSLS
	zapi4RouteOLSR
	zapi4RouteTABLE
	zapi4RouteLDP
	zapi4RouteVNC
	zapi4RouteVNCDirect
	zapi4RouteVNCDirectRH
	zapi4RouteBGPDixrect
	zapi4RouteBGPDirectEXT
	zapi4RouteAll
)

var routeTypeZapi4Map = map[RouteType]RouteType{
	routeNHRP:         zapi4RouteNHRP,
	routeHSLS:         zapi4RouteHSLS,
	routeOLSR:         zapi4RouteOLSR,
	routeTABLE:        zapi4RouteTABLE,
	routeLDP:          zapi4RouteLDP,
	routeVNC:          zapi4RouteVNC,
	routeVNCDirect:    zapi4RouteVNCDirect,
	routeVNCDirectRH:  zapi4RouteVNCDirectRH,
	routeBGPDirect:    zapi4RouteBGPDixrect,
	routeBGPDirectEXT: zapi4RouteBGPDirectEXT,
	routeAll:          zapi4RouteAll,
}

// For Quagga except common route type.
const (
	zapi3RouteHSLS RouteType = iota + routePIM + 1
	zapi3RouteOLSR
	zapi3RouteBABEL
	zapi3RouteNHRP // quagga 1.2.4
)

var routeTypeZapi3Map = map[RouteType]RouteType{
	routeHSLS:  zapi3RouteHSLS,
	routeOLSR:  zapi3RouteOLSR,
	routeBABEL: zapi3RouteBABEL,
	routeNHRP:  zapi3RouteNHRP,
}

func (t RouteType) toEach(version uint8) RouteType {
	if t <= routePIM || version > 4 { // not need to convert
		return t
	}
	routeTypeMap := routeTypeZapi4Map
	if version < 4 {
		routeTypeMap = routeTypeZapi3Map
	}
	backward, ok := routeTypeMap[t]
	if ok {
		return backward // success to convert
	}
	return routeMax // fail to convert and error value
}

var routeTypeValueMap = map[string]RouteType{
	"system":                   routeSystem,
	"kernel":                   routeKernel,
	"connect":                  routeConnect, // hack for backward compatibility
	"directly-connected":       routeConnect,
	"static":                   RouteStatic,
	"rip":                      routeRIP,
	"ripng":                    routeRIPNG,
	"ospf":                     routeOSPF,
	"ospf3":                    routeOSPF6,
	"isis":                     routeISIS,
	"bgp":                      RouteBGP,
	"pim":                      routePIM,
	"eigrp":                    routeEIGRP, // added in frr4(zapi5)
	"nhrp":                     routeNHRP,
	"hsls":                     routeHSLS,
	"olsr":                     routeOLSR,
	"table":                    routeTABLE,
	"ldp":                      routeLDP,
	"vnc":                      routeVNC,
	"vnc-direct":               routeVNCDirect,
	"vnc-rn":                   routeVNCDirectRH,
	"bgp-direct":               routeBGPDirect,
	"bgp-direct-to-nve-groups": routeBGPDirectEXT,
	"babel":                    routeBABEL,
	"sharp":                    routeSHARP,
	"pbr":                      routePBR,
	"bfd":                      routeBFD,
	"openfabric":               routeOpenfabric, // added in frr7.0(zapi6)
	"vrrp":                     routeVRRP,       // added in frr7.2(zapi6)
	"nhg":                      routeNHG,        // added in frr7.3(zapi6)
	"srte":                     routeSRTE,       // added in frr7.5(zapi6)
	"wildcard":                 routeAll,
}

// RouteTypeFromString converts from string to route type
func RouteTypeFromString(typ string, version uint8, software Software) (RouteType, error) {
	t, ok := routeTypeValueMap[typ]
	if !ok { // failed to lookup RouteType from string
		return t, fmt.Errorf("unknown route type: %s in version: %d (%s)", typ, version, software.string())
	}
	t = t.toEach(version) //when lookup failes return routeMax
	if t > getRouteAll(version, software) {
		return t, fmt.Errorf("unknown route type: %d in version: %d (%s)", t, version, software.string())
	}
	return t, nil // Success
}

func addressByteLength(family uint8) (int, error) {
	switch family {
	case syscall.AF_INET:
		return net.IPv4len, nil
	case syscall.AF_INET6:
		return net.IPv6len, nil
	}
	return 0, fmt.Errorf("unknown address family: %d", family)
}

func ipFromFamily(family uint8, buf []byte) net.IP {
	switch family {
	case syscall.AF_INET:
		return net.IP(buf).To4()
	case syscall.AF_INET6:
		return net.IP(buf).To16()
	}
	return nil
}

// MESSAGE_FLAG is 32bit in frr7.5 and after frr7.5, 8bit in frr 7.4 and before frr7.4
// MessageFlag is the type of API Message Flags.
type MessageFlag uint32

const ( // For FRRouting version 4, 5 and 6 (ZAPI version 5 and 6).
	// MessageNexthop is referred in zclient
	MessageNexthop MessageFlag = 0x01
	// MessageDistance is referred in zclient_test
	MessageDistance MessageFlag = 0x02
	// MessageMetric is referred in zclient
	MessageMetric MessageFlag = 0x04
	messageTag    MessageFlag = 0x08
	// MessageMTU is referred in zclient_test
	MessageMTU    MessageFlag = 0x10
	messageSRCPFX MessageFlag = 0x20
	// MessageLabel is referred in zclient
	MessageLabel          MessageFlag = 0x40  // deleted in frr7.3
	messageBackupNexthops MessageFlag = 0x40  // added in frr7.4
	messageNhg            MessageFlag = 0x80  // added in frr8
	messageTableID        MessageFlag = 0x100 // frr8: 0x100, frr5&6&7.x: 0x80
	messageSRTE           MessageFlag = 0x200 // frr8: 0x200, frr7.5: 0x100
	messageOpaque         MessageFlag = 0x400 // introduced in frr8
)

const ( // For FRRouting.
	messageIFIndex       MessageFlag = 0x02
	zapi4MessageDistance MessageFlag = 0x04
	zapi4MessageMetric   MessageFlag = 0x08
	zapi4MessageTag      MessageFlag = 0x10
	zapi4MessageMTU      MessageFlag = 0x20
	zapi4MessageSRCPFX   MessageFlag = 0x40
)

const ( // For Quagga.
	zapi3MessageMTU MessageFlag = 0x10
	zapi3MessageTag MessageFlag = 0x20
)

// ToEach is referred in zclient
func (f MessageFlag) ToEach(version uint8, software Software) MessageFlag {
	if version > 4 { //zapi version 5, 6
		if f > messageNhg && (version == 5 ||
			(version == 6 && software.name == "frr" && software.version < 8)) { // except frr8
			return f >> 1
		}
		return f
	}
	if version < 4 { //zapi version 3, 2
		switch f {
		case MessageMTU:
			return zapi3MessageMTU
		case messageTag:
			return zapi3MessageTag
		}
	}
	switch f { //zapi version 4
	case MessageDistance, MessageMetric, messageTag, MessageMTU, messageSRCPFX:
		return f << 1
	}
	return f
}
func (f MessageFlag) string(version uint8, software Software) string {
	var ss []string
	if f&MessageNexthop > 0 {
		ss = append(ss, "NEXTHOP")
	}
	if version < 4 && f&messageIFIndex > 0 {
		ss = append(ss, "IFINDEX")
	}
	if f&MessageDistance.ToEach(version, software) > 0 {
		ss = append(ss, "DISTANCE")
	}
	if f&MessageMetric.ToEach(version, software) > 0 {
		ss = append(ss, "METRIC")
	}
	if f&MessageMTU.ToEach(version, software) > 0 {
		ss = append(ss, "MTU")
	}
	if f&messageTag.ToEach(version, software) > 0 {
		ss = append(ss, "TAG")
	}
	if version > 3 && f&messageSRCPFX.ToEach(version, software) > 0 {
		ss = append(ss, "SRCPFX")
	}
	if version == 6 && software.name == "frr" && software.version >= 7.4 && f&messageBackupNexthops > 0 { // added in frr7.4, frr7.5
		ss = append(ss, "BACKUP_NEXTHOPS")
	} else if version > 4 && f&MessageLabel > 0 {
		ss = append(ss, "LABEL")
	}
	if version > 6 && software.name == "frr" && software.version >= 8 && f&messageNhg > 0 { // added in frr8
		ss = append(ss, "NHG")
	}
	if version > 5 && f&messageTableID > 0 {
		ss = append(ss, "TABLEID")
	}
	if version == 6 && software.name == "frr" && software.version >= 7.5 && f&messageSRTE > 0 { // added in frr7.5
		ss = append(ss, "SRTE")
	}
	if version > 6 && software.name == "frr" && software.version >= 8 && f&messageOpaque > 0 { // added in frr8
		ss = append(ss, "OPAQUE")
	}
	return strings.Join(ss, "|")
}

// Flag is Message Flag which is referred in zclient
type Flag uint64

const ( // For FRRouting version 7 (zebra API version 6), these are defined in lib/zclient.h
	// FlagAllowRecursion is referred in zclient, and it is renamed from ZEBRA_FLAG_INTERNAL (https://github.com/FRRouting/frr/commit/4e8b02f4df5d6bcfde6390955b8feda2a17dc9bd)
	FlagAllowRecursion Flag = 0x01 // quagga, frr3, frr4, frr5, frr6, frr7
	flagSelfRoute      Flag = 0x02 // quagga, frr3, frr4, frr5, frr6, frr7
	// FlagIBGP is referred in zclient
	FlagIBGP Flag = 0x04
	// FlagSelected referred in zclient_test
	FlagSelected      Flag = 0x08
	flagFIBOverride   Flag = 0x10
	flagEvpnRoute     Flag = 0x20
	flagRRUseDistance Flag = 0x40
	flagOnlink        Flag = 0x80  // frr7.0 only, this vale is deleted in frr7.1
	flagTrapped       Flag = 0x80  // added in frr8
	flagOffloaded     Flag = 0x100 // added in frr8
	flagOffloadFailed Flag = 0x200 // added in frr8
)

// For Quagga (ZAPI v2, v3), FRR v3 (ZAPI v4), FRR v4, v5 (ZAPI v5), FRR v6 (ZAPI v6) for backward compatibility
const (
	flagBlackhole Flag = 0x04  // quagga, frr3
	flagStatic    Flag = 0x40  // quagga, frr3, frr4, frr5, frr6
	flagReject    Flag = 0x80  // quagga, frr3
	flagScopeLink Flag = 0x100 // frr4, frr5, frr6
)

// ToEach is referred in zclient
func (f Flag) ToEach(version uint8, software Software) Flag {
	if (version == 6 && software.name == "frr" && software.version >= 7) || (f < FlagIBGP) || f > flagRRUseDistance {
		return f
	}
	switch f {
	case FlagIBGP, FlagSelected: // 0x04->0x08,0x08->0x10(quagga, frr3,4,5,6)
		return f << 1
	case flagEvpnRoute, flagRRUseDistance: // 0x20->0x400,0x40->0x800(frr4,5,6)
		return f << 5
	case flagFIBOverride:
		if version < 4 {
			return f << 1 // 0x10->0x20(quagga)
		}
		return f << 5 // 0x10->0x200(frr3, frr4, frr5, frr6)
	}
	return f
}

// String is referred in zclient
func (f Flag) String(version uint8, software Software) string {
	var ss []string
	// common flag
	if f&FlagAllowRecursion > 0 {
		ss = append(ss, "FLAG_ALLOW_RECURSION")
	}
	if f&flagSelfRoute > 0 {
		ss = append(ss, "FLAG_SELFROUTE")
	}
	if f&FlagIBGP.ToEach(version, software) > 0 {
		ss = append(ss, "FLAG_IBGP")
	}
	if f&FlagSelected.ToEach(version, software) > 0 {
		ss = append(ss, "FLAG_SELECTED")
	}
	if f&flagEvpnRoute.ToEach(version, software) > 0 {
		ss = append(ss, "FLAG_EVPN_ROUTE")
	}
	if f&flagRRUseDistance.ToEach(version, software) > 0 {
		ss = append(ss, "FLAG_RR_USE_DISTANCE")
	}
	if f&flagFIBOverride.ToEach(version, software) > 0 {
		ss = append(ss, "FLAG_FIB_OVERRIDE")
	}
	if version == 6 && software.name == "frr" && software.version >= 7 && f&flagOnlink > 0 { // frr7.0 only
		ss = append(ss, "FLAG_ONLINK")
	}
	if version == 6 && software.name == "frr" && software.version >= 8 && f&flagTrapped > 0 { // added in frr8
		ss = append(ss, "FLAG_TRAPPED")
	}
	if f&flagOffloaded > 0 { // added in frr8
		ss = append(ss, "FLAG_OFFLOADED")
	}
	if f&flagOffloadFailed > 0 { // added in frr8
		ss = append(ss, "FLAG_OFFLOADFAILED")
	}
	if (version < 6 || (version == 6 && software.name == "frr" && software.version < 7)) && f&flagStatic > 0 {
		ss = append(ss, "FLAG_STATIC") // quagga, frr3, frr4, frr5, frr6
	}
	if version < 5 && f&flagBlackhole > 0 { // quagga, frr3
		ss = append(ss, "FLAG_BLACKHOLE")
	}
	if version < 5 && f&flagReject > 0 { // quagga, frr3
		ss = append(ss, "FLAG_REJECT")
	}
	if (version == 5 || (version == 6 && software.name == "frr" && software.version < 7)) && f&flagScopeLink > 0 {
		ss = append(ss, "FLAG_SCOPE_LINK") // frr4, frr5, frr6
	}
	return strings.Join(ss, "|")
}

// Nexthop Types.
//
//go:generate stringer -type=nexthopType
type nexthopType uint8

// For FRRouting.
const (
	_                      nexthopType = iota
	nexthopTypeIFIndex                 // 1
	nexthopTypeIPv4                    // 2
	nexthopTypeIPv4IFIndex             // 3
	nexthopTypeIPv6                    // 4
	nexthopTypeIPv6IFIndex             // 5
	nexthopTypeBlackhole               // 6
)

// For Quagga.
const (
	nexthopTypeIFName              nexthopType = iota + 2 // 2
	backwardNexthopTypeIPv4                               // 3
	backwardNexthopTypeIPv4IFIndex                        // 4
	nexthopTypeIPv4IFName                                 // 5
	backwardNexthopTypeIPv6                               // 6
	backwardNexthopTypeIPv6IFIndex                        // 7
	nexthopTypeIPv6IFName                                 // 8
	backwardNexthopTypeBlackhole                          // 9
)

var nexthopTypeMap = map[nexthopType]nexthopType{
	nexthopTypeIPv4:        backwardNexthopTypeIPv4,        // 2 -> 3
	nexthopTypeIPv4IFIndex: backwardNexthopTypeIPv4IFIndex, // 3 -> 4
	nexthopTypeIPv6:        backwardNexthopTypeIPv6,        // 4 -> 6
	nexthopTypeIPv6IFIndex: backwardNexthopTypeIPv6IFIndex, // 5 -> 7
	nexthopTypeBlackhole:   backwardNexthopTypeBlackhole,   // 6 -> 9
}

func (t nexthopType) toEach(version uint8) nexthopType {
	if version > 3 { // frr
		return t
	}
	if t == nexthopTypeIFIndex || t > nexthopTypeBlackhole { // 1 (common), 7, 8, 9 (out of map range)
		return t
	}
	backward, ok := nexthopTypeMap[t]
	if ok {
		return backward // converted value
	}
	return nexthopType(0) // error for conversion
}

func (t nexthopType) ipToIPIFIndex() nexthopType {
	// process of nexthopTypeIPv[4|6] is same as nexthopTypeIPv[4|6]IFIndex
	// in IPRouteBody of frr7.3 and NexthoUpdate of frr
	if t == nexthopTypeIPv4 {
		return nexthopTypeIPv4IFIndex
	} else if t == nexthopTypeIPv6 {
		return nexthopTypeIPv6IFIndex
	}
	return t
}
func (t nexthopType) ifNameToIFIndex() nexthopType { // quagga
	if t == nexthopTypeIFName {
		return nexthopTypeIFIndex
	} else if t == nexthopTypeIPv4IFName {
		return backwardNexthopTypeIPv4IFIndex
	} else if t == nexthopTypeIPv6IFName {
		return backwardNexthopTypeIPv6IFIndex
	}
	return t
}

// Nexthop Flags.
//
//go:generate stringer -type=nexthopFlag
type nexthopFlag uint8

const (
	nexthopFlagActive      nexthopFlag = 0x01 // This nexthop is alive.
	nexthopFlagFIB         nexthopFlag = 0x02 // FIB nexthop.
	nexthopFlagRecursive   nexthopFlag = 0x04 // Recursive nexthop.
	nexthopFlagOnlink      nexthopFlag = 0x08 // Nexthop should be installed onlink.
	nexthopFlagDuplicate   nexthopFlag = 0x10 // nexthop duplicates (frr8, 7.5, 7.4)
	nexthopFlagRnhFiltered nexthopFlag = 0x20 // nexthop duplicates (frr8, 7.5, 7.4)
	nexthopFlagHasBackup   nexthopFlag = 0x40 // nexthop duplicates (frr8, 7.5, 7.4)
	nexthopFlagSRTE        nexthopFlag = 0x80 // nexthop duplicates (frr8, 7.5)
)
const (
	// Already matched vs a nexthop (frr7.3, 7.2, 7.1, 7, 6, 5, 4, 3) (zapi version >= 4)
	zapi6Frr7dot3nexthopFlagMatched nexthopFlag = 0x10
	// nexthop duplicates (frr7.3, 7.2, 7.1)
	zapi6Frr7dot3nexthopFlagDuplicate nexthopFlag = 0x20
	// nexthop duplicates (frr7.3, 7.2, 7.1)
	zapi6Frr7dot3nexthopFlagRnhFiltered nexthopFlag = 0x40
)
const (
	// rmap filtered (frr7, 6, 5, 4, 3)(zapi version >= 4)
	zapi6Frr7nexthopFlagFiltered nexthopFlag = 0x20
	// nexthop duplicates (frr7, 6, 5, 4)(version >= 5)
	zapi6Frr7nexthopFlagDuplicate nexthopFlag = 0x40
	// Evpn remote vtep nexthop (frr7, 6, 5, 4)(version >= 5)
	zapi6Frr7nexthopFlagEvpnRvtep nexthopFlag = 0x80
)

// Interface PTM Enable Configuration.
//
//go:generate stringer -type=ptmEnable
type ptmEnable uint8

const (
	ptmEnableOff    ptmEnable = 0
	ptmEnableOn     ptmEnable = 1
	ptmEnableUnspec ptmEnable = 2
)

// PTM Status.
//
//go:generate stringer -type=ptmStatus
type ptmStatus uint8

const (
	ptmStatusDown    ptmStatus = 0
	ptmStatusUp      ptmStatus = 1
	ptmStatusUnknown ptmStatus = 2
)

const (
	defaultZebraSoftwareName    string  = "frr"
	defaultZapi5SoftwareVersion float64 = 5   // FRR software version for Zapi5
	defaultZapi6SoftwareVersion float64 = 8.1 // FRR software version for Zapi6
)

// Software is zebra software (quagga, frr, cumulus) which is referred in zclient
type Software struct {
	name    string
	version float64
}

// string returns combined string with name and version in Software structure
func (software *Software) string() string {
	return fmt.Sprintf("%s%f", software.name, software.version)
}

// NewSoftware is constructor of Software strucuture
func NewSoftware(version uint8, softwareName string) Software {
	regex := regexp.MustCompile(`([a-z]*)(\d*\.?\d*)`)
	regexResult := regex.FindAllStringSubmatch(softwareName, -1)
	software := Software{regexResult[0][1], defaultZapi6SoftwareVersion}
	var err error
	software.version, err = strconv.ParseFloat(regexResult[0][2], 64)
	if err != nil || (software.name != "cumulus" && version >= 5) {
		software.name = defaultZebraSoftwareName
		if version == 5 && software.version < 4 && software.version >= 6 {
			software.version = defaultZapi5SoftwareVersion
		} else if version == 6 && software.version < 6 {
			software.version = defaultZapi6SoftwareVersion
		}
	}
	return software
}

// Client is zebra client which is referred in zclient
type Client struct {
	outgoing      chan *Message
	incoming      chan *Message
	redistDefault RouteType
	conn          net.Conn
	Version       uint8
	Software      Software
	logger        log.Logger
}

// NewClient returns a Client instance (Client constructor)
func NewClient(logger log.Logger, network, address string, typ RouteType, version uint8, software Software, mplsLabelRangeSize uint32) (*Client, error) {
	conn, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	outgoing := make(chan *Message)
	incoming := make(chan *Message, 64)
	if version < MinZapiVer {
		version = MinZapiVer
	} else if version > MaxZapiVer {
		version = MaxZapiVer
	}
	c := &Client{
		outgoing:      outgoing,
		incoming:      incoming,
		redistDefault: typ,
		conn:          conn,
		Version:       version,
		Software:      software,
		logger:        logger,
	}

	go func() {
		for {
			m, more := <-outgoing
			if more {
				b, err := m.serialize(software)
				if err != nil {
					logger.Warn(fmt.Sprintf("failed to serialize: %v", m),
						log.Fields{
							"Topic": "Zebra"})
					continue
				}

				_, err = conn.Write(b)
				if err != nil {
					logger.Error("failed to write",
						log.Fields{
							"Topic": "Zebra",
							"Error": err})
					closeChannel(outgoing)
					return
				}
			} else {
				logger.Debug("finish outgoing loop",
					log.Fields{"Topic": "Zebra"})
				return
			}
		}
	}()

	// Send Hello/RouterIDAdd messages to negotiate the Zebra message version.
	c.SendHello()
	c.SendRouterIDAdd()

	if mplsLabelRangeSize > 0 && c.SupportMpls() {
		c.sendLabelManagerConnect(true)
	}

	receiveSingleMsg := func() (*Message, error) {
		headerBuf, err := readAll(conn, int(HeaderSize(version)))
		if err != nil {
			logger.Error("failed to read header",
				log.Fields{
					"Topic": "Zebra",
					"Error": err})
			return nil, err
		}

		hd := &Header{}
		err = hd.decodeFromBytes(headerBuf)
		if c.Version != hd.Version {
			logger.Warn(fmt.Sprintf("ZAPI version mismatch. configured version: %d, version of received message:%d", c.Version, hd.Version),
				log.Fields{
					"Topic": "Zebra"})
			return nil, errors.New("ZAPI version mismatch")
		}
		if err != nil {
			logger.Error("failed to decode header",
				log.Fields{
					"Topic": "Zebra",
					"Data":  headerBuf,
					"Error": err})
			return nil, err
		}

		bodyBuf, err := readAll(conn, int(hd.Len-HeaderSize(version)))
		if err != nil {
			logger.Error("failed to read body",
				log.Fields{
					"Topic":  "Zebra",
					"Header": hd,
					"Error":  err})
			return nil, err
		}

		m, err := parseMessage(hd, bodyBuf, software)
		if err != nil {
			// Just outputting warnings (not error message) and ignore this
			// error considering the case that body parser is not implemented yet.
			logger.Warn("failed to decode body",
				log.Fields{
					"Topic":  "Zebra",
					"Header": hd,
					"Data":   bodyBuf,
					"Error":  err})
			return nil, nil
		}
		logger.Debug("read message from zebra",
			log.Fields{
				"Topic":   "Zebra",
				"Message": m})

		return m, nil
	}

	// Try to receive the first message from Zebra.
	if m, err := receiveSingleMsg(); err != nil {
		c.close()
		// Return error explicitly in order to retry connection.
		return nil, err
	} else if m != nil {
		incoming <- m
	}

	// Start receive loop only when the first message successfully received.
	go func() {
		defer close(incoming)
		for {
			if m, err := receiveSingleMsg(); err != nil {
				return
			} else if m != nil {
				incoming <- m
			}
		}
	}()

	return c, nil
}

func readAll(conn net.Conn, length int) ([]byte, error) {
	buf := make([]byte, length)
	_, err := io.ReadFull(conn, buf)
	return buf, err
}

// Receive return incoming channel message
func (c *Client) Receive() chan *Message {
	return c.incoming
}

func (c *Client) send(m *Message) {
	defer func() {
		if err := recover(); err != nil {
			c.logger.Debug("recovered",
				log.Fields{
					"Topic": "Zebra",
					"Error": err})
		}
	}()
	c.logger.Debug("send command to zebra",
		log.Fields{
			"Topic":  "Zebra",
			"Header": m.Header,
			"Body":   m.Body})
	c.outgoing <- m
}

func (c *Client) sendCommand(command APIType, vrfID uint32, body Body) error {
	m := &Message{
		Header: Header{
			Len:     HeaderSize(c.Version),
			Marker:  HeaderMarker(c.Version),
			Version: c.Version,
			VrfID:   vrfID,
			Command: command.ToEach(c.Version, c.Software),
		},
		Body: body,
	}
	c.send(m)
	return nil
}

// SendHello sends HELLO message to zebra daemon.
func (c *Client) SendHello() error {
	if c.redistDefault > 0 {
		body := &helloBody{
			redistDefault: c.redistDefault,
			instance:      0,
		}
		return c.sendCommand(hello, DefaultVrf, body)
	}
	return nil
}

// SendRouterIDAdd sends ROUTER_ID_ADD message to zebra daemon.
func (c *Client) SendRouterIDAdd() error {
	bodies := make([]*routerIDUpdateBody, 0)
	for _, afi := range []afi{afiIP, afiIP6} {
		bodies = append(bodies, &routerIDUpdateBody{
			afi: afi,
		})
	}
	for _, body := range bodies {
		c.sendCommand(routerIDAdd, DefaultVrf, body)
	}
	return nil
}

// SendInterfaceAdd sends INTERFACE_ADD message to zebra daemon.
func (c *Client) SendInterfaceAdd() error {
	return c.sendCommand(interfaceAdd, DefaultVrf, nil)
}

// SendRedistribute sends REDISTRIBUTE message to zebra daemon.
func (c *Client) SendRedistribute(t RouteType, vrfID uint32) error {
	if c.redistDefault != t {
		bodies := make([]*redistributeBody, 0)
		if c.Version <= 3 {
			bodies = append(bodies, &redistributeBody{
				redist: t,
			})
		} else { // Version >= 4
			for _, afi := range []afi{afiIP, afiIP6} {
				bodies = append(bodies, &redistributeBody{
					afi:      afi,
					redist:   t,
					instance: 0,
				})
			}
		}

		for _, body := range bodies {
			c.sendCommand(redistributeAdd, vrfID, body)
		}
	}
	return nil
}

// SendIPRoute sends ROUTE message to zebra daemon.
func (c *Client) SendIPRoute(vrfID uint32, body *IPRouteBody, isWithdraw bool) error {
	routeFamily := body.RouteFamily(c.logger, c.Version, c.Software)
	if vrfID == DefaultVrf && (routeFamily == bgp.RF_IPv4_VPN || routeFamily == bgp.RF_IPv6_VPN) {
		return fmt.Errorf("RF_IPv4_VPN or RF_IPv6_VPN are not suitable for Default VRF (default forwarding table)")
	}
	command := RouteAdd
	if isWithdraw {
		command = RouteDelete
	}
	if c.Version < 5 && familyFromPrefix(body.Prefix.Prefix) == syscall.AF_INET6 {
		command = BackwardIPv6RouteAdd
		if isWithdraw {
			command = BackwardIPv6RouteDelete
		}
	}
	return c.sendCommand(command, vrfID, body)
}

// SendNexthopRegister sends NEXTHOP_REGISTER message to zebra daemon.
func (c *Client) SendNexthopRegister(vrfID uint32, body *NexthopRegisterBody, isWithdraw bool) error {
	// Note: NexthopRegister and NexthopUnregister messages are not
	// supported in Zebra protocol version<3.
	if c.Version < 3 {
		return fmt.Errorf("NexthopRegister/NexthopUnregister are not supported in version: %d", c.Version)
	}
	command := nexthopRegister
	if isWithdraw {
		command = nexthopUnregister
	}
	return c.sendCommand(command, vrfID, body)
}

// SupportMpls is referred in zclient. It returns bool value.
func (c *Client) SupportMpls() bool {
	// Note: frr3&4 have LABEL_MANAGER_CONNECT& GET_LABEL_CHUNK. However
	// Routes will not be installed via zebra of frr3&4 after call these APIs.
	if c.Version < 5 || (c.Software.name == "frr" && c.Software.version == 4) {
		return false // if frr4 or earlier are used
	}
	return true // if frr5 or later are used
}

// Ref: zread_label_manager_connect in zebra/zserv.c of FRR3 (ZAPI4)
// Ref: zread_label_manager_connect in zebra/zapi_msg.c of FRR5&6 (ZAPI5&6)
func (c *Client) sendLabelManagerConnect(async bool) error {
	if c.Version < 4 {
		return fmt.Errorf("LabelManagerConnect is not supported in zebra API version: %d", c.Version)
	}
	command := labelManagerConnectAsync
	// FRR version 4 (ZAPI version 5) and FRR version 3 (ZAPI version 4)
	if !async || c.Version == 4 || (c.Version == 5 && c.Software.name == "frr" && c.Software.version < 5) {
		command = labelManagerConnect
	}
	return c.sendCommand(
		command, 0,
		&labelManagerConnectBody{
			redistDefault: RouteBGP,
			instance:      0,
		})
}

// SendGetLabelChunk sends GET_LABEL_CHUNK message to zebra daemon.
func (c *Client) SendGetLabelChunk(body *GetLabelChunkBody) error {
	if c.Version < 4 {
		return fmt.Errorf("GetLabelChunk is not supported in version: %d", c.Version)
	}
	body.instance = 0
	body.proto = uint8(RouteBGP)
	return c.sendCommand(getLabelChunk, 0, body)
}

// SendVrfLabel sends VRF_LABEL message to zebra daemon.
func (c *Client) SendVrfLabel(label uint32, vrfID uint32) error {
	// ZAPIv5 has ZEBRA_VRF_LABEL, however frr4 (ZAPIv5) doesn't have it.
	if c.Version < 5 || (c.Version == 5 && c.Software.name == "frr" && c.Software.version < 5) {
		return fmt.Errorf("VrfLabel is not supported in zebra API version: %d software: %s", c.Version, c.Software.string())
	}
	body := &vrfLabelBody{
		label:     label,
		afi:       afiIP,
		labelType: lspBGP,
	}
	return c.sendCommand(vrfLabel, vrfID, body)
}

// for avoiding double close
func closeChannel(ch chan *Message) bool {
	select {
	case _, ok := <-ch:
		if ok {
			close(ch)
			return true
		}
	default:
	}
	return false
}

func (c *Client) close() error {
	closeChannel(c.outgoing)
	return c.conn.Close()
}

// SetLabelFlag is referred in zclient, this func sets label flag
func (c Client) SetLabelFlag(msgFlags *MessageFlag, nexthop *Nexthop) {
	if c.Version == 6 && c.Software.name == "frr" {
		nexthop.flags |= zapiNexthopFlagLabel
	} else if c.Version > 4 {
		*msgFlags |= MessageLabel
	}
}

// Header is header of zebra message.
type Header struct {
	Len     uint16
	Marker  uint8
	Version uint8
	VrfID   uint32 // ZAPI v4: 16bits, v5: 32bits
	Command APIType
}

func (h *Header) serialize() ([]byte, error) {
	buf := make([]byte, HeaderSize(h.Version))
	binary.BigEndian.PutUint16(buf[0:2], h.Len)
	buf[2] = h.Marker
	buf[3] = h.Version
	switch h.Version {
	case 2:
		binary.BigEndian.PutUint16(buf[4:6], uint16(h.Command))
	case 3, 4:
		binary.BigEndian.PutUint16(buf[4:6], uint16(h.VrfID))
		binary.BigEndian.PutUint16(buf[6:8], uint16(h.Command))
	case 5, 6:
		binary.BigEndian.PutUint32(buf[4:8], uint32(h.VrfID))
		binary.BigEndian.PutUint16(buf[8:10], uint16(h.Command))
	default:
		return nil, fmt.Errorf("unsupported ZAPI version: %d", h.Version)
	}
	return buf, nil
}

func (h *Header) decodeFromBytes(data []byte) error {
	if uint16(len(data)) < 4 {
		return fmt.Errorf("not all ZAPI message header")
	}
	h.Len = binary.BigEndian.Uint16(data[0:2])
	h.Marker = data[2]
	h.Version = data[3]
	if uint16(len(data)) < HeaderSize(h.Version) {
		return fmt.Errorf("not all ZAPI message header")
	}
	switch h.Version {
	case 2:
		h.Command = APIType(binary.BigEndian.Uint16(data[4:6]))
	case 3, 4:
		h.VrfID = uint32(binary.BigEndian.Uint16(data[4:6]))
		h.Command = APIType(binary.BigEndian.Uint16(data[6:8]))
	case 5, 6:
		h.VrfID = binary.BigEndian.Uint32(data[4:8])
		h.Command = APIType(binary.BigEndian.Uint16(data[8:10]))
	default:
		return fmt.Errorf("unsupported ZAPI version: %d", h.Version)
	}
	return nil
}

// Body is an interface for zebra messages.
type Body interface {
	decodeFromBytes([]byte, uint8, Software) error
	serialize(uint8, Software) ([]byte, error)
	string(uint8, Software) string
}

type unknownBody struct {
	Data []byte
}

func (b *unknownBody) decodeFromBytes(data []byte, version uint8, software Software) error {
	b.Data = data
	return nil
}

func (b *unknownBody) serialize(version uint8, software Software) ([]byte, error) {
	return b.Data, nil
}

func (b *unknownBody) string(version uint8, software Software) string {
	return fmt.Sprintf("data: %v", b.Data)
}

type helloBody struct {
	redistDefault RouteType
	instance      uint16
	sessionID     uint32 // frr7.4, 7.5, 8, 8.1, 8.2
	receiveNotify uint8
	synchronous   uint8 // frr7.4, 7.5, 8, 8.1, 8.2
}

// Ref: zread_hello in zebra/zserv.c of Quagga1.2&FRR3 (ZAPI3&4)
// Ref: zread_hello in zebra/zapi_msg.c of FRR5&FRR6&FRR7&FRR7.1&FRR7.2&FRR7.3&FRR7.4&FRR7.5&FRR8 (ZAPI5&6)
func (b *helloBody) decodeFromBytes(data []byte, version uint8, software Software) error {
	b.redistDefault = RouteType(data[0])
	if version > 3 { //frr
		b.instance = binary.BigEndian.Uint16(data[1:3])
		if version == 6 && software.name == "frr" && software.version >= 7.4 {
			b.sessionID = binary.BigEndian.Uint32(data[3:7])
			b.receiveNotify = data[7]
			b.synchronous = data[8]
		} else if version > 4 {
			b.receiveNotify = data[3]
		}
	}
	return nil
}

// Ref: zebra_hello_send in lib/zclient.c of Quagga1.2&FRR3&FRR5&FRR6&FRR7&FRR7.1&FRR7.2&FRR7.3 (ZAPI3&4&5&6)
// Ref: zclient_send_hello in lib/zclient.c of FRR7.4&FRR7.5&FRR8 (ZAPI6)
func (b *helloBody) serialize(version uint8, software Software) ([]byte, error) {
	if version < 4 {
		return []byte{uint8(b.redistDefault)}, nil
	}
	var buf []byte
	if version == 6 && software.name == "frr" && software.version >= 7.4 {
		buf = make([]byte, 9)
	} else if version > 4 {
		buf = make([]byte, 4)
	} else if version == 4 {
		buf = make([]byte, 3)
	}
	buf[0] = uint8(b.redistDefault)
	binary.BigEndian.PutUint16(buf[1:3], b.instance)
	if version == 6 && software.name == "frr" && software.version >= 7.4 {
		binary.BigEndian.PutUint32(buf[3:7], b.sessionID)
		buf[7] = b.receiveNotify
		buf[8] = b.synchronous
	} else if version > 4 {
		buf[3] = b.receiveNotify
	}
	return buf, nil
}

func (b *helloBody) string(version uint8, software Software) string {
	return fmt.Sprintf(
		"route_type: %s, instance :%d, sessionID: %d, receiveNotify: %d, synchronous: %d",
		b.redistDefault.String(), b.instance, b.sessionID, b.receiveNotify, b.synchronous)
}

type redistributeBody struct {
	afi      afi
	redist   RouteType
	instance uint16
}

// Ref: zebra_redistribute_add in zebra/redistribute.c of Quagga1.2&FRR3&FRR4&FRR5&FRR6&FRR7.x&FRR8 (ZAPI3&4&5&6)
func (b *redistributeBody) decodeFromBytes(data []byte, version uint8, software Software) error {
	if version < 4 {
		b.redist = RouteType(data[0])
	} else { // version >= 4
		b.afi = afi(data[0])
		b.redist = RouteType(data[1])
		b.instance = binary.BigEndian.Uint16(data[2:4])
	}
	return nil
}

// Ref: zebra_redistribute_send in lib/zclient.c of Quagga1.2&FRR3&FRR4&FRR5&FRR6&FRR7.x&FRR8 (ZAPI3&4&5&6)
func (b *redistributeBody) serialize(version uint8, software Software) ([]byte, error) {
	if version < 4 {
		return []byte{uint8(b.redist)}, nil
	}
	buf := make([]byte, 4)
	buf[0] = uint8(b.afi)
	buf[1] = uint8(b.redist)
	binary.BigEndian.PutUint16(buf[2:4], b.instance)
	return buf, nil
}

func (b *redistributeBody) string(version uint8, software Software) string {
	return fmt.Sprintf(
		"afi: %s, route_type: %s, instance :%d",
		b.afi.String(), b.redist.String(), b.instance)
}

type linkParam struct {
	status      uint32
	teMetric    uint32
	maxBw       float32
	maxRsvBw    float32
	unrsvBw     [8]float32
	bwClassNum  uint32
	adminGroup  uint32
	remoteAS    uint32
	remoteIP    net.IP
	aveDelay    uint32
	minDelay    uint32
	maxDelay    uint32
	delayVar    uint32
	pktLoss     float32
	residualBw  float32
	availableBw float32
	useBw       float32
}

type interfaceUpdateBody struct {
	name         string
	index        uint32
	status       interfaceStatus
	flags        uint64
	ptmEnable    ptmEnable
	ptmStatus    ptmStatus
	metric       uint32
	speed        uint32
	mtu          uint32
	mtu6         uint32
	bandwidth    uint32
	linkIfindex  uint32
	linktype     linkType
	hardwareAddr net.HardwareAddr
	linkParam    linkParam
}

// Ref: zebra_interface_if_set_value in lib/zclient.c of Quagga1.2&FRR3&FRR4&FRR5&FRR6&FRR7.x&FRR8 (ZAPI3&4&5&6)
func (b *interfaceUpdateBody) decodeFromBytes(data []byte, version uint8, software Software) error {
	if len(data) < interfaceNameSize+33 {
		return fmt.Errorf("lack of bytes. need %d but %d", interfaceNameSize+29, len(data))
	}

	b.name = strings.Trim(string(data[:interfaceNameSize]), "\u0000")
	data = data[interfaceNameSize:]
	b.index = binary.BigEndian.Uint32(data[0:4])
	b.status = interfaceStatus(data[4])
	b.flags = binary.BigEndian.Uint64(data[5:13])
	if version > 3 {
		b.ptmEnable = ptmEnable(data[13])
		b.ptmStatus = ptmStatus(data[14])
		b.metric = binary.BigEndian.Uint32(data[15:19])
		b.speed = binary.BigEndian.Uint32(data[19:23])
		data = data[23:]
	} else {
		b.metric = binary.BigEndian.Uint32(data[13:17])
		data = data[17:]
	}
	b.mtu = binary.BigEndian.Uint32(data[0:4])
	b.mtu6 = binary.BigEndian.Uint32(data[4:8])
	b.bandwidth = binary.BigEndian.Uint32(data[8:12])
	data = data[12:]

	//frr 7.2 and later versions have link Ifindex
	if version == 6 && software.name == "frr" && software.version >= 7.2 {
		b.linkIfindex = binary.BigEndian.Uint32(data[:4])
		data = data[4:]
	}
	if version > 2 {
		b.linktype = linkType(binary.BigEndian.Uint32(data[:4]))
		data = data[4:]
	}
	l := binary.BigEndian.Uint32(data[:4]) // STREAM_GETL(s, ifp->hw_addr_len)
	if l > 0 {
		if len(data) < 4+int(l) {
			return fmt.Errorf("lack of bytes in remain data. need %d but %d", 4+l, len(data))
		}
		b.hardwareAddr = data[4 : 4+l] // STREAM_GET(ifp->hw_addr, s, MIN(ifp->hw_addr_len, INTERFACE_HWADDR_MAX));
	}
	if version > 2 {
		linkParam := data[4+l] // stream_getc(s)
		if linkParam > 0 {     // link_params_set_value
			data = data[5+l:]
			b.linkParam.status = binary.BigEndian.Uint32(data[0:4])
			b.linkParam.teMetric = binary.BigEndian.Uint32(data[4:8])
			b.linkParam.maxBw = math.Float32frombits(binary.BigEndian.Uint32(data[8:12]))
			b.linkParam.maxRsvBw = math.Float32frombits(binary.BigEndian.Uint32(data[12:16]))
			b.linkParam.bwClassNum = binary.BigEndian.Uint32(data[16:20])
			for i := uint32(0); i < b.linkParam.bwClassNum; i++ {
				b.linkParam.unrsvBw[i] = math.Float32frombits(binary.BigEndian.Uint32(data[20+i*4 : 24+i*4]))
			}
			data = data[20+b.linkParam.bwClassNum*4:]
			b.linkParam.adminGroup = binary.BigEndian.Uint32(data[0:4])
			b.linkParam.remoteAS = binary.BigEndian.Uint32(data[4:8])
			b.linkParam.remoteIP = data[8:12]
			b.linkParam.aveDelay = binary.BigEndian.Uint32(data[12:16])
			b.linkParam.minDelay = binary.BigEndian.Uint32(data[16:20])
			b.linkParam.maxDelay = binary.BigEndian.Uint32(data[20:24])
			b.linkParam.delayVar = binary.BigEndian.Uint32(data[24:28])
			b.linkParam.pktLoss = math.Float32frombits(binary.BigEndian.Uint32(data[28:32]))
			b.linkParam.residualBw = math.Float32frombits(binary.BigEndian.Uint32(data[32:36]))
			b.linkParam.availableBw = math.Float32frombits(binary.BigEndian.Uint32(data[36:40]))
			b.linkParam.useBw = math.Float32frombits(binary.BigEndian.Uint32(data[40:44]))
		}
	}
	return nil
}

func (b *interfaceUpdateBody) serialize(version uint8, software Software) ([]byte, error) {
	return []byte{}, nil
}

func (b *interfaceUpdateBody) string(version uint8, software Software) string {
	s := fmt.Sprintf(
		"name: %s, idx: %d, status: %s, flags: %s, ptm_enable: %s, ptm_status: %s, metric: %d, speed: %d, mtu: %d, mtu6: %d, bandwidth: %d, linktype: %s",
		b.name, b.index, b.status.String(), intfflag2string(b.flags), b.ptmEnable.String(), b.ptmStatus.String(), b.metric, b.speed, b.mtu, b.mtu6, b.bandwidth, b.linktype.String())
	if len(b.hardwareAddr) > 0 {
		return s + fmt.Sprintf(", mac: %s", b.hardwareAddr.String())
	}
	return s
}

type interfaceAddressUpdateBody struct {
	index       uint32
	flags       interfaceAddressFlag
	prefix      net.IP
	length      uint8
	destination net.IP
}

// Ref: zebra_interface_address_read in lib/zclient.c of Quagga1.2&FRR3&FRR4&FRR5&FRR6&FRR7.x&FRR8 (ZAPI3&4&5&6)
func (b *interfaceAddressUpdateBody) decodeFromBytes(data []byte, version uint8, software Software) error {
	b.index = binary.BigEndian.Uint32(data[:4]) //STREAM_GETL(s, ifindex)
	b.flags = interfaceAddressFlag(data[4])     //STREAM_GETC(s, ifc_flags)
	family := data[5]                           //STREAM_GETC(s, d.family)
	addrlen, err := addressByteLength(family)
	if err != nil {
		return err
	}
	b.prefix = data[6 : 6+addrlen]                //zclient_stream_get_prefix //STREAM_GET(&p->u.prefix, s, plen);
	b.length = data[6+addrlen]                    //zclient_stream_get_prefix //STREAM_GETC(s, c);
	b.destination = data[7+addrlen : 7+addrlen*2] //STREAM_GET(&d.u.prefix, s, plen)
	return nil
}

func (b *interfaceAddressUpdateBody) serialize(version uint8, software Software) ([]byte, error) {
	return []byte{}, nil
}

func (b *interfaceAddressUpdateBody) string(version uint8, software Software) string {
	return fmt.Sprintf(
		"idx: %d, flags: %s, addr: %s/%d",
		b.index, b.flags.String(), b.prefix.String(), b.length)
}

type routerIDUpdateBody struct {
	length uint8
	prefix net.IP
	afi    afi
}

// Ref: zebra_router_id_update_read in lib/zclient.c of Quagga1.2&FRR3&FRR5 (ZAPI3&4&5)
func (b *routerIDUpdateBody) decodeFromBytes(data []byte, version uint8, software Software) error {
	family := data[0]

	addrlen, err := addressByteLength(family)
	if err != nil {
		return err
	}
	b.prefix = data[1 : 1+addrlen] //zclient_stream_get_prefix
	b.length = data[1+addrlen]     //zclient_stream_get_prefix
	return nil
}

// Ref: zclient_send_router_id_update in lib/zclient.c of FRR7.5
func (b *routerIDUpdateBody) serialize(version uint8, software Software) ([]byte, error) {
	if version == 6 && software.name == "frr" && software.version >= 7.5 {
		return []byte{0x00, uint8(b.afi)}, nil //stream_putw(s, afi);

	}
	return []byte{}, nil
}

func (b *routerIDUpdateBody) string(version uint8, software Software) string {
	return fmt.Sprintf("id: %s/%d", b.prefix.String(), b.length)
}

// zapiNexthopFlag is defined in lib/zclient.h of FRR
const (
	zapiNexthopFlagOnlink    uint8 = 0x01 // frr7.1, 7.2, 7.3, 7.4, 7.5, 8.0
	zapiNexthopFlagLabel     uint8 = 0x02 // frr7.3, 7.4, 7.5, 8.0
	zapiNexthopFlagWeight    uint8 = 0x04 // frr7.3, 7.4, 7.5, 8.0
	zapiNexthopFlagHasBackup uint8 = 0x08 // frr7.4, 7.5, 8.0
	zapiNexthopFlagSeg6      uint8 = 0x10 // frr8.1
	zapiNexthopFlagSeg6Local uint8 = 0x20 // frr8.1
)

// Flag for nexthop processing. It is gobgp's internal flag.
type nexthopProcessFlag uint8

const (
	nexthopHasType                nexthopProcessFlag = 0x01
	nexthopHasVrfID               nexthopProcessFlag = 0x02
	nexthopHasFlag                nexthopProcessFlag = 0x04
	nexthopHasOnlink              nexthopProcessFlag = 0x08
	nexthopProcessIPToIPIFindex   nexthopProcessFlag = 0x10
	nexthopProcessIFnameToIFindex nexthopProcessFlag = 0x20 // for quagga
)

func nexthopProcessFlagForIPRouteBody(version uint8, software Software, isDecode bool) nexthopProcessFlag {
	if version < 5 {
		if isDecode {
			return nexthopProcessFlag(0) // frr3&quagga don't have type&vrfid
		}
		return nexthopHasType // frr3&quagga need type for encode(serialize)
	}
	processFlag := (nexthopHasVrfID | nexthopHasType) // frr4, 5, 6, 7
	if version == 6 && software.name == "frr" {
		if software.version >= 7.3 {
			processFlag |= (nexthopHasFlag | nexthopProcessIPToIPIFindex)
		} else if software.version >= 7.1 {
			processFlag |= nexthopHasOnlink
		}
	}
	return processFlag
}

// Ref: struct seg6local_context in lib/srv6.h of FRR8.1
type seg6localContext struct {
	nh4   net.IP //struct in_addr nh4
	nh6   net.IP //struct in_addr nh6
	table uint32
}

func (s6lc seg6localContext) encode() []byte {
	var buf []byte
	buf = append(buf, s6lc.nh4.To4()...)
	buf = append(buf, s6lc.nh6.To16()...)
	tmpbuf := make([]byte, 4)
	binary.BigEndian.PutUint32(tmpbuf, s6lc.table)
	buf = append(buf, tmpbuf...)
	return buf
}
func (s6lc *seg6localContext) decode(data []byte) int {
	offset := 0
	s6lc.nh4 = net.IP(data[offset : offset+4]).To4()
	offset += 4
	s6lc.nh6 = net.IP(data[offset : offset+16]).To16()
	offset += 16
	s6lc.table = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4
	return offset
}

// Ref: struct zapi_nexthop in lib/zclient.h of FRR5&FRR6&FRR7.x&FRR8, FRR8.1 (ZAPI5&6)
// Nexthop is referred in zclient
type Nexthop struct {
	Type            nexthopType      //FRR5, FRR6, FRR7.x, FRR8, FRR8.1
	VrfID           uint32           //FRR5, FRR6, FRR7.x, FRR8, FRR8.1
	Ifindex         uint32           // Ifindex is referred in zclient_test
	flags           uint8            //FRR7.1, FRR7.2 FRR7.3, FRR7.4, FRR7.5, FRR8, FRR8.1
	Gate            net.IP           //union { union g_addr gate;
	blackholeType   uint8            //        enum blackhole_type bh_type;}
	LabelNum        uint8            //FRR5, FRR6, FRR7.x, FRR8, FRR8.1
	MplsLabels      []uint32         //FRR5, FRR6, FRR7.x, FRR8, FRR8.1
	rmac            [6]byte          //FRR6, FRR7.x, FRR8, FRR8.1
	weight          uint32           //FRR7.3, FRR7.4, FRR7.5, FRR8, FRR8.1
	backupNum       uint8            //FRR7.4, FRR7.5, FRR8, FRR8.1
	backupIndex     []uint8          //FRR7.5, FRR8, FRR8.1
	srteColor       uint32           //FRR7.5, FRR8, FRR8.1
	seg6localAction uint32           //FRR8.1
	seg6localCtx    seg6localContext // FRR8.1
	seg6Segs        net.IP           //strcut in6_addr // FRR8.1
}

func (n Nexthop) string() string {
	s := make([]string, 0)
	s = append(s, fmt.Sprintf(
		"type: %s, vrf_id: %d, ifindex: %d, flags: %d, gate: %s, blackholeType: %d, label_num: %d, weight: %d, backupNum: %d, srteColor: %d",
		n.Type.String(), n.VrfID, n.Ifindex, n.flags, n.Gate.String(),
		n.blackholeType, n.LabelNum, n.weight, n.backupNum, n.srteColor))
	for i := uint8(0); i < n.LabelNum; i++ {
		s = append(s, fmt.Sprintf(" label[%d]: %d", i, n.MplsLabels[i]))
	}
	for i := uint8(0); i < n.backupNum; i++ {
		s = append(s, fmt.Sprintf(" backupIndex[%d]: %d", i, n.backupIndex[i]))
	}
	return strings.Join(s, ", ")
}
func (n Nexthop) gateToType(version uint8) nexthopType {
	if n.Gate.To4() != nil {
		if version > 4 && n.Ifindex > 0 {
			return nexthopTypeIPv4IFIndex
		}
		return nexthopTypeIPv4.toEach(version)
	} else if n.Gate.To16() != nil {
		if version > 4 && n.Ifindex > 0 {
			return nexthopTypeIPv6IFIndex
		}
		return nexthopTypeIPv6.toEach(version)
	} else if n.Ifindex > 0 {
		return nexthopTypeIFIndex.toEach(version)
	} else if version > 4 {
		return nexthopTypeBlackhole
	}
	return nexthopType(0)
}

// Ref: zapi_nexthop_encode in lib/zclient.h of FRR7.3&FRR7.4&FRR7.5&FRR8
func (n Nexthop) encode(version uint8, software Software, processFlag nexthopProcessFlag, message MessageFlag, apiFlag Flag) []byte {
	var buf []byte
	if processFlag&nexthopHasVrfID > 0 {
		tmpbuf := make([]byte, 4)
		binary.BigEndian.PutUint32(tmpbuf, n.VrfID)
		buf = append(buf, tmpbuf...) //frr: stream_putl(s, api_nh->vrf_id);
	}
	if processFlag&nexthopHasType > 0 {
		if n.Type == nexthopType(0) {
			n.Type = n.gateToType(version)
		}
		buf = append(buf, uint8(n.Type)) //frr: stream_putc(s, api_nh->type);
	}
	if processFlag&nexthopHasFlag > 0 {
		if n.LabelNum > 0 {
			n.flags |= zapiNexthopFlagLabel
		}
		if n.weight > 0 {
			n.flags |= zapiNexthopFlagWeight
		}
		if n.backupNum > 0 {
			n.flags |= zapiNexthopFlagHasBackup
		}
	}
	if processFlag&nexthopHasFlag > 0 || processFlag&nexthopHasOnlink > 0 {
		// frr7.1, 7.2 has onlink, 7.3 has flag
		buf = append(buf, n.flags) //frr: stream_putc(s, nh_flags);
	}

	nhType := n.Type
	if processFlag&nexthopProcessIPToIPIFindex > 0 {
		nhType = nhType.ipToIPIFIndex()
	}
	if processFlag&nexthopProcessIFnameToIFindex > 0 {
		nhType = nhType.ifNameToIFIndex()
	}
	if nhType == nexthopTypeIPv4.toEach(version) ||
		nhType == nexthopTypeIPv4IFIndex.toEach(version) {
		//frr: stream_put_in_addr(s, &api_nh->gate.ipv4);
		buf = append(buf, n.Gate.To4()...)
	} else if nhType == nexthopTypeIPv6.toEach(version) ||
		nhType == nexthopTypeIPv6IFIndex.toEach(version) {
		//frr: stream_write(s, (uint8_t *)&api_nh->gate.ipv6, 16);
		buf = append(buf, n.Gate.To16()...)
	}
	if nhType == nexthopTypeIFIndex ||
		nhType == nexthopTypeIPv4IFIndex.toEach(version) ||
		nhType == nexthopTypeIPv6IFIndex.toEach(version) {
		tmpbuf := make([]byte, 4)
		binary.BigEndian.PutUint32(tmpbuf, n.Ifindex)
		buf = append(buf, tmpbuf...) //frr: stream_putl(s, api_nh->ifindex);
	}
	if nhType == nexthopTypeBlackhole.toEach(version) { //case NEXTHOP_TYPE_BLACKHOLE:
		//frr: stream_putc(s, api_nh->bh_type);
		buf = append(buf, uint8(n.blackholeType))
	}
	if n.flags&zapiNexthopFlagLabel > 0 || (message&MessageLabel > 0 &&
		version == 5 ||
		(version == 6 && software.name == "frr" &&
			software.version >= 6 && software.version < 7.3)) {
		tmpbuf := make([]byte, 1+4*n.LabelNum)
		tmpbuf[0] = n.LabelNum //frr: stream_putc(s, api_nh->label_num);
		for i := uint8(0); i < n.LabelNum; i++ {
			// frr uses stream_put for mpls label array.
			// stream_put is unaware of byteorder coversion.
			// Therefore LittleEndian is used instead of BigEndian.
			binary.LittleEndian.PutUint32(tmpbuf[i*4+1:], n.MplsLabels[i])
		}
		//frr: stream_put(s, &api_nh->labels[0], api_nh->label_num * sizeof(mpls_label_t));
		buf = append(buf, tmpbuf...)
	}
	if n.flags&zapiNexthopFlagWeight > 0 && n.weight > 0 {
		tmpbuf := make([]byte, 4)
		binary.BigEndian.PutUint32(tmpbuf, uint32(n.weight))
		buf = append(buf, tmpbuf...) //frr: stream_putl(s, api_nh->weight);
	}
	if apiFlag&flagEvpnRoute.ToEach(version, software) > 0 {
		//frr: stream_put(s, &(api_nh->rmac), sizeof(struct ethaddr));
		buf = append(buf, n.rmac[:]...)
	}
	// added in frr7.5 (Color for Segment Routing TE.)
	if message&messageSRTE > 0 && (version == 6 && software.name == "frr" && software.version >= 7.5) {
		tmpbuf := make([]byte, 4)
		binary.BigEndian.PutUint32(tmpbuf, uint32(n.srteColor))
		buf = append(buf, tmpbuf...) //frr: stream_putl(s, api_nh->srte_color);
	}
	// added in frr7.4 (Index of backup nexthop)
	if n.flags&zapiNexthopFlagHasBackup > 0 {
		tmpbuf := make([]byte, 1+1*n.backupNum)
		tmpbuf[0] = n.backupNum //frr: stream_putc(s, api_nh->backup_num);
		for i := uint8(0); i < n.backupNum; i++ {
			tmpbuf[i+1] = n.backupIndex[i]
		}
		buf = append(buf, tmpbuf...)
	}
	// added in frr8.1
	if n.flags&zapiNexthopFlagSeg6 > 0 {
		tmpbuf := make([]byte, 4)
		binary.BigEndian.PutUint32(tmpbuf, uint32(n.seg6localAction))
		buf = append(buf, tmpbuf...) // stream_putl(s, api_nh->seg6local_action);
		//frr: stream_write(s, &api_nh->seg6local_ctx, sizeof(struct seg6local_context));
		buf = append(buf, n.seg6localCtx.encode()...)
	}
	// added in frr8.1
	if n.flags&zapiNexthopFlagSeg6Local > 0 {
		//frr: stream_write(s, &api_nh->seg6_segs, sizeof(struct in6_addr));
		buf = append(buf, n.seg6Segs.To16()...)
	}
	return buf
}

// Ref: zapi_nexthop_decode in lib/zclient.h of FRR7.3&FRR7.4&FRR7.5&FRR8
func (n *Nexthop) decode(data []byte, version uint8, software Software, family uint8, processFlag nexthopProcessFlag, message MessageFlag, apiFlag Flag, nhType nexthopType) (int, error) {
	offset := 0
	if processFlag&nexthopHasVrfID > 0 {
		//frr: STREAM_GETL(s, api_nh->vrf_id);
		n.VrfID = binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
	}

	n.Type = nhType // data does not have nexthop type
	if processFlag&nexthopHasType > 0 {
		n.Type = nexthopType(data[offset]) //frr: STREAM_GETC(s, api_nh->type);
		offset++
	}

	n.flags = uint8(0)
	if processFlag&nexthopHasFlag > 0 || processFlag&nexthopHasOnlink > 0 {
		n.flags = uint8(data[offset]) //frr: STREAM_GETC(s, api_nh->flags);
		offset++
	}

	nhType = n.Type
	if processFlag&nexthopProcessIPToIPIFindex > 0 {
		nhType = nhType.ipToIPIFIndex()
	}
	if processFlag&nexthopProcessIFnameToIFindex > 0 {
		nhType = nhType.ifNameToIFIndex()
	}
	if family == syscall.AF_INET {
		n.Gate = net.ParseIP("0.0.0.0")
	} else if family == syscall.AF_INET6 {
		n.Gate = net.ParseIP("::")
	}
	if nhType == nexthopTypeIPv4.toEach(version) ||
		nhType == nexthopTypeIPv4IFIndex.toEach(version) {
		//frr: STREAM_GET(&api_nh->gate.ipv4.s_addr, s, IPV4_MAX_BYTELEN);
		n.Gate = net.IP(data[offset : offset+4]).To4()
		offset += 4
	} else if nhType == nexthopTypeIPv6.toEach(version) ||
		nhType == nexthopTypeIPv6IFIndex.toEach(version) {
		//frr: STREAM_GET(&api_nh->gate.ipv6, s, 16);
		n.Gate = net.IP(data[offset : offset+16]).To16()
		offset += 16
	}
	if nhType == nexthopTypeIFIndex ||
		nhType == nexthopTypeIPv4IFIndex.toEach(version) ||
		nhType == nexthopTypeIPv6IFIndex.toEach(version) {
		//frr: STREAM_GETL(s, api_nh->ifindex);
		n.Ifindex = binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
	}
	if nhType == nexthopTypeBlackhole.toEach(version) { //case NEXTHOP_TYPE_BLACKHOLE:
		n.blackholeType = data[offset] //frr: STREAM_GETC(s, api_nh->bh_type);
		offset++
	}
	if n.flags&zapiNexthopFlagLabel > 0 || (message&MessageLabel > 0 &&
		(version == 5 || version == 6 && software.name == "frr" &&
			software.version >= 6 && software.version < 7.3)) {
		n.LabelNum = uint8(data[offset]) //frr: STREAM_GETC(s, api_nh->label_num);
		offset++
		if n.LabelNum > maxMplsLabel {
			n.LabelNum = maxMplsLabel
		}
		if n.LabelNum > 0 {
			n.MplsLabels = make([]uint32, n.LabelNum)
			for i := uint8(0); i < n.LabelNum; i++ {
				// frr uses stream_put which is unaware of byteorder for mpls label array.
				// Therefore LittleEndian is used instead of BigEndian.
				//frr: STREAM_GET(&api_nh->labels[0], s, api_nh->label_num * sizeof(mpls_label_t));
				n.MplsLabels[i] = binary.LittleEndian.Uint32(data[offset : offset+4])
				offset += 4
			}
		}
	}
	if n.flags&zapiNexthopFlagWeight > 0 {
		//frr: STREAM_GETL(s, api_nh->weight);
		n.weight = binary.BigEndian.Uint32(data[offset:])
		offset += 4
	}
	if apiFlag&flagEvpnRoute.ToEach(version, software) > 0 {
		//frr: STREAM_GET(&(api_nh->rmac), s, sizeof(struct ethaddr));
		copy(n.rmac[0:], data[offset:offset+6])
		offset += 6
	}
	// added in frr7.5 (Color for Segment Routing TE.)
	if message&messageSRTE > 0 &&
		(version == 6 && software.name == "frr" && software.version >= 7.5) {
		//frr: STREAM_GETL(s, api_nh->srte_color);
		n.srteColor = binary.BigEndian.Uint32(data[offset:])
		offset += 4
	}
	// added in frr7.4 (Index of backup nexthop)
	if n.flags&zapiNexthopFlagHasBackup > 0 {
		n.backupNum = data[offset] //frr: STREAM_GETC(s, api_nh->backup_num);
		offset++
		if n.backupNum > 0 {
			n.backupIndex = make([]uint8, n.backupNum)
			for i := uint8(0); i < n.backupNum; i++ {
				//frr STREAM_GETC(s, api_nh->backup_idx[i]);
				n.backupIndex[i] = data[offset]
				offset++
			}
		}
	}
	// added in frr8.1
	if n.flags&zapiNexthopFlagSeg6 > 0 {
		n.seg6localAction = binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
		offset += n.seg6localCtx.decode(data[offset : offset+24])
	}
	// added in frr8.1
	if n.flags&zapiNexthopFlagSeg6Local > 0 {
		n.seg6Segs = net.IP(data[offset : offset+16]).To16()
		offset += 16
	}
	return offset, nil
}

// decodeNexthops is referred from decodeFromBytes of NexthopUpdateBody and IPRouteBody
func decodeNexthops(nexthops *[]Nexthop, data []byte, version uint8, software Software, family uint8, numNexthop uint16, processFlag nexthopProcessFlag, message MessageFlag, apiFlag Flag, nhType nexthopType) (int, error) {
	offset := 0
	*nexthops = make([]Nexthop, numNexthop)
	for i := uint16(0); i < numNexthop; i++ {
		size, err := (&((*nexthops)[i])).decode(data[offset:], version, software, family, processFlag, message, apiFlag, nhType)
		if err != nil {
			return offset, err
		}
		offset += size
	}
	return offset, nil
}

// Prefix referred in zclient is struct for network prefix and relate information
type Prefix struct {
	Family    uint8
	PrefixLen uint8
	Prefix    net.IP
}

func familyFromPrefix(prefix net.IP) uint8 {
	if prefix.To4() != nil {
		return syscall.AF_INET
	} else if prefix.To16() != nil {
		return syscall.AF_INET6
	}
	return syscall.AF_UNSPEC
}

const messageOpaqueLenth uint16 = 1024

type opaque struct {
	length uint16
	data   [messageOpaqueLenth]uint8
}

// Ref: struct zapi_route in lib/zclient.h of FRR4&FRR5&FRR6&FRR7.x&RR8 (ZAPI5&6)
// IPRouteBody is struct for IPRotue (zapi_route)
type IPRouteBody struct {
	Type           RouteType   // FRR4&FRR5&FRR6&FRR7.x&FRR8
	instance       uint16      // FRR4&FRR5&FRR6&FRR7.x&FRR8
	Flags          Flag        // FRR4&FRR5&FRR6&FRR7.x&FRR8
	Message        MessageFlag // FRR4&FRR5&FRR6&FRR7.x&FRR8
	Safi           Safi        // FRR4&FRR5&FRR6&FRR7.x&FRR8
	Prefix         Prefix      // FRR4&FRR5&FRR6&FRR7.x&FRR8
	srcPrefix      Prefix      // FRR4&FRR5&FRR6&FRR7.x&FRR8
	Nexthops       []Nexthop   // FRR4&FRR5&FRR6&FRR7.x&FRR8
	backupNexthops []Nexthop   // added in frr7.4, FRR7.4&FRR7.5&FRR8
	nhgid          uint32      // added in frr8
	Distance       uint8       // FRR4&FRR5&FRR6&FRR7.x&FRR8
	Metric         uint32      // FRR4&FRR5&FRR6&FRR7.x&FRR8
	tag            uint32      // FRR4&FRR5&FRR6&FRR7.x&FRR8
	Mtu            uint32      // FRR4&FRR5&FRR6&FRR7.x&FRR8
	tableID        uint32      // FRR5&FRR6&FRR7.x&FRR8 (nh_vrf_id in FRR4)
	srteColor      uint32      // added in frr7.5, FRR7.5&FRR8
	opaque         opaque      // added in frr8
	API            APIType     // API is referred in zclient_test
	//vrfID        uint32    // lib/zebra.h:typedef uint32_t vrf_id_t;
}

func (b *IPRouteBody) safi(logger log.Logger, version uint8, software Software) Safi {
	// frr 7.2 and later versions have safiUnspec, older versions don't have safiUnspec
	if b.Safi == safiUnspec && (version < 6 ||
		(version == 6 && software.name == "frr" && software.version < 7.2)) {
		return SafiUnicast //safiUnspec is regarded as safiUnicast in older versions
	}
	if b.Safi <= safiMulticast || version > 4 { // not need to convert
		return b.Safi
	}
	safiMap := zapi4SafiMap
	if version < 4 {
		safiMap = zapi3SafiMap
	}
	safi, ok := safiMap[b.Safi]
	if !ok {
		safi = safiUnspec // failed to convert
	}
	logger.Debug("zebra converts safi",
		log.Fields{
			"Topic": "Zebra",
			"Body":  b,
			"Old":   b.Safi.String(),
			"New":   safi.String()})
	return safi // success to convert
}

// RouteFamily is referred in zclient
func (b *IPRouteBody) RouteFamily(logger log.Logger, version uint8, software Software) bgp.RouteFamily {
	if b == nil {
		return bgp.RF_OPAQUE // fail
	}
	safi := b.safi(logger, version, software)
	if safi == safiEvpn {
		return bgp.RF_EVPN // success
	}
	family := b.Prefix.Family
	if family == syscall.AF_UNSPEC {
		family = familyFromPrefix(b.Prefix.Prefix)
	}
	if family == syscall.AF_UNSPEC { // familyFromPrefix returs AF_UNSPEC
		return bgp.RF_OPAQUE // fail
	}
	safiRouteFamilyMap := safiRouteFamilyIPv4Map // syscall.AF_INET
	if family == syscall.AF_INET6 {
		safiRouteFamilyMap = safiRouteFamilyIPv6Map
	}
	rf, ok := safiRouteFamilyMap[safi]
	if !ok {
		return bgp.RF_OPAQUE // fail
	}
	logger.Debug("zebra converts safi",
		log.Fields{
			"Topic": "Zebra",
			"Body":  b,
			"Safi":  safi.String(),
			"Rf":    rf.String()})

	return rf // success
}

// IsWithdraw is referred in zclient
func (b *IPRouteBody) IsWithdraw(version uint8, software Software) bool {
	api := b.API.toCommon(version, software)
	switch api {
	case RouteDelete, redistributeRouteDel, BackwardIPv6RouteDelete:
		return true
	}
	if version == 4 && b.API == zapi4RedistributeIPv6Del {
		return true
	}
	return false
}

// Ref: zapi_ipv4_route in lib/zclient.c  of Quagga1.2.x&FRR3.x(ZAPI3&4)
// Ref: zapi_route_encode in lib/zclient.c of FRR4&FRR5&FRR6&FRR7.x&FRR8 (ZAPI5&6)
func (b *IPRouteBody) serialize(version uint8, software Software) ([]byte, error) {
	var buf []byte
	numNexthop := len(b.Nexthops)

	bufInitSize := 12 //type(1)+instance(2)+flags(4)+message(4)+safi(1), frr7.4&newer
	switch version {
	case 2, 3:
		bufInitSize = 5
	case 4:
		bufInitSize = 10
	case 5:
		bufInitSize = 9 //type(1)+instance(2)+flags(4)+message(1)+safi(1)
	case 6:
		if software.name == "frr" && software.version < 7.4 { // frr6, 7, 7.2, 7.3
			bufInitSize = 9 //type(1)+instance(2)+flags(4)+message(1)+safi(1)
		}
	}
	buf = make([]byte, bufInitSize)

	buf[0] = uint8(b.Type.toEach(version)) //frr: stream_putc(s, api->type);
	if version < 4 {
		buf[1] = uint8(b.Flags)
		buf[2] = uint8(b.Message)
		binary.BigEndian.PutUint16(buf[3:5], uint16(b.Safi))
	} else { // version >= 4
		//frr: stream_putw(s, api->instance);
		binary.BigEndian.PutUint16(buf[1:3], uint16(b.instance))
		//frr: stream_putl(s, api->flags);
		binary.BigEndian.PutUint32(buf[3:7], uint32(b.Flags))
		if version == 6 && software.name == "frr" && software.version >= 7.5 {
			//frr7.5 and newer: stream_putl(s, api->message);
			binary.BigEndian.PutUint32(buf[7:11], uint32(b.Message))
			buf[11] = uint8(b.Safi) //stream_putc(s, api->safi);
		} else {
			//frr 7.4 and older: stream_putc(s, api->message);
			buf[7] = uint8(b.Message)
			if version > 4 {
				buf[8] = uint8(b.Safi) //frr: stream_putc(s, api->safi);
			} else { // version 2,3 and 4 (quagga, frr3)
				binary.BigEndian.PutUint16(buf[8:10], uint16(b.Safi))
			}
		}
	}
	// only zapi version 5 (frr4.0.x) have evpn routes
	if version == 5 && b.Flags&flagEvpnRoute.ToEach(version, software) > 0 {
		// size of struct ethaddr is 6 octets defined by ETH_ALEN
		buf = append(buf, b.Nexthops[numNexthop-1].rmac[:6]...)
	}
	if version > 4 { // version 5, 6 (after frr4)
		if b.Prefix.Family == syscall.AF_UNSPEC {
			b.Prefix.Family = familyFromPrefix(b.Prefix.Prefix)
		}
		//frr: stream_putc(s, api->prefix.family);
		buf = append(buf, b.Prefix.Family)
	}
	byteLen := (int(b.Prefix.PrefixLen) + 7) / 8
	buf = append(buf, b.Prefix.PrefixLen) //frr: stream_putc(s, api->prefix.prefixlen);
	//frr: stream_write(s, (uint8_t *)&api->prefix.u.prefix, psize);
	buf = append(buf, b.Prefix.Prefix[:byteLen]...)

	if version > 3 && b.Message&messageSRCPFX.ToEach(version, software) > 0 {
		byteLen = (int(b.srcPrefix.PrefixLen) + 7) / 8
		//frr: stream_putc(s, api->src_prefix.prefixlen);
		buf = append(buf, b.srcPrefix.PrefixLen)
		//frr: stream_write(s, (uint8_t *)&api->prefix.u.prefix, psize);
		buf = append(buf, b.srcPrefix.Prefix[:byteLen]...)
	}

	// NHG(Nexthop Group) is added in frr8
	//frr: if (CHECK_FLAG(api->message, ZAPI_MESSAGE_NHG))
	if version == 6 && software.name == "frr" && software.version >= 8 &&
		b.Message&messageNhg.ToEach(version, software) > 0 {
		//frr: stream_putl(s, api->nhgid);
		tmpbuf := make([]byte, 4)
		binary.BigEndian.PutUint32(tmpbuf, b.nhgid)
		buf = append(buf, tmpbuf...)
	}

	processFlag := nexthopProcessFlagForIPRouteBody(version, software, false)
	if b.Message&MessageNexthop > 0 {
		if version < 5 {
			if b.Flags&flagBlackhole > 0 {
				buf = append(buf, []byte{1, uint8(nexthopTypeBlackhole.toEach(version))}...)
			} else {
				buf = append(buf, uint8(numNexthop))
			}
		} else { // version >= 5
			tmpbuf := make([]byte, 2)
			binary.BigEndian.PutUint16(tmpbuf, uint16(numNexthop))
			buf = append(buf, tmpbuf...) //frr: stream_putw(s, api->nexthop_num);
		}
		for _, nexthop := range b.Nexthops {
			buf = append(buf, nexthop.encode(version, software, processFlag, b.Message, b.Flags)...)
		}
	}
	// MESSAGE_BACKUP_NEXTHOPS is added in frr7.4
	if version == 6 && software.name == "frr" && software.version >= 7.4 &&
		b.Message&messageBackupNexthops > 0 {
		tmpbuf := make([]byte, 2)
		binary.BigEndian.PutUint16(tmpbuf, uint16(len(b.backupNexthops)))
		buf = append(buf, tmpbuf...) //frr: stream_putw(s, api->backup_nexthop_num);
		for _, nexthop := range b.backupNexthops {
			buf = append(buf, nexthop.encode(version, software, processFlag, b.Message, b.Flags)...)
		}
	}
	if b.Message&MessageDistance.ToEach(version, software) > 0 {
		buf = append(buf, b.Distance)
	}
	if b.Message&MessageMetric.ToEach(version, software) > 0 {
		tmpbuf := make([]byte, 4)
		binary.BigEndian.PutUint32(tmpbuf, b.Metric)
		buf = append(buf, tmpbuf...)
	}
	if b.Message&messageTag.ToEach(version, software) > 0 {
		tmpbuf := make([]byte, 4)
		binary.BigEndian.PutUint32(tmpbuf, b.tag)
		buf = append(buf, tmpbuf...)
	}
	if b.Message&MessageMTU.ToEach(version, software) > 0 {
		tmpbuf := make([]byte, 4)
		binary.BigEndian.PutUint32(tmpbuf, b.Mtu)
		buf = append(buf, tmpbuf...)
	}
	if b.Message&messageTableID.ToEach(version, software) > 0 {
		tmpbuf := make([]byte, 4)
		binary.BigEndian.PutUint32(tmpbuf, b.tableID)
		buf = append(buf, tmpbuf...)
	}
	if b.Message&messageOpaque.ToEach(version, software) > 0 {
		tmpbuf := make([]byte, 2)
		binary.BigEndian.PutUint16(tmpbuf, b.opaque.length)
		buf = append(buf, tmpbuf...)           //frr: stream_putw(s, api->opaque.length);
		buf = append(buf, b.opaque.data[:]...) //frr: stream_write(s, api->opaque.data, api->opaque.length);
	}
	return buf, nil
}

// decodeMessageNexthopFromBytes is referred in IPRouteBody's decodeFromBytes
func (b *IPRouteBody) decodeMessageNexthopFromBytes(data []byte, version uint8, software Software, isBackup bool) (int, error) {
	pos := 0
	rest := len(data)
	message := MessageNexthop
	nexthops := &b.Nexthops
	messageString := "MessageNexthop"
	if isBackup {
		message = messageBackupNexthops
		nexthops = &b.backupNexthops
		messageString = "messageBackupNexthops"
	}
	if b.Message&message > 0 {
		numNexthop := uint16(0)
		numNexthopDataSize := 2
		processFlag := nexthopProcessFlagForIPRouteBody(version, software, true)
		nhType := nexthopType(0)
		if message == MessageNexthop && version < 5 { // frr3 and quagga
			numNexthopDataSize = 1
			nhType = nexthopTypeIPv4.toEach(version)
			if b.Prefix.Family == syscall.AF_INET6 {
				nhType = nexthopTypeIPv6.toEach(version)
			}
		}
		if pos+numNexthopDataSize > rest {
			return pos, fmt.Errorf("%s message length invalid pos:%d rest:%d", messageString, pos, rest)
		}
		if numNexthopDataSize == 2 {
			//frr: STREAM_GETW(s, api->nexthop_num);
			numNexthop = binary.BigEndian.Uint16(data[pos : pos+2])
		} else if message == MessageNexthop && numNexthopDataSize == 1 {
			numNexthop = uint16(data[pos])
		}
		pos += numNexthopDataSize

		nexthopsByteLen, err := decodeNexthops(nexthops, data[pos:], version, software, b.Prefix.Family, numNexthop, processFlag, b.Message, b.Flags, nhType)
		if err != nil {
			return pos, err
		}
		pos += nexthopsByteLen
	}
	return pos, nil
}

// Ref: zebra_read_ipv4 in bgpd/bgp_zebra.c of Quagga1.2.x&FRR3.x(ZAPI3&4)
// Ref: zapi_route_decode in lib/zclient.c of FRR5&FRR6&FRR7.x&FRR8 (ZAPI5&6)
func (b *IPRouteBody) decodeFromBytes(data []byte, version uint8, software Software) error {
	if b == nil {
		return fmt.Errorf("IPRouteBody is nil")
	}
	//frr: STREAM_GETC(s, api->type);
	b.Type = RouteType(data[0])
	if b.Type > getRouteAll(version, software) { //ver5 and later work, fix for older
		return fmt.Errorf("unknown route type: %d in version: %d (%s)", b.Type, version, software.string())
	}

	if version <= 3 {
		b.Flags = Flag(data[1])
		data = data[2:]
	} else { // version >= 4
		//frr: STREAM_GETW(s, api->instance);
		b.instance = binary.BigEndian.Uint16(data[1:3])
		//frr: STREAM_GETL(s, api->flags);
		b.Flags = Flag(binary.BigEndian.Uint32(data[3:7]))
		data = data[7:]
	}
	if version == 6 && software.name == "frr" && software.version >= 7.5 {
		//frr7.5: STREAM_GETL(s, api->message);
		b.Message = MessageFlag(binary.BigEndian.Uint32(data[0:4]))
		data = data[4:]
	} else {
		b.Message = MessageFlag(data[0]) //frr: STREAM_GETC(s, api->message);
		data = data[1:]
	}
	b.Safi = Safi(SafiUnicast)
	b.Prefix.Family = b.API.addressFamily(version) // return AF_UNSPEC if version > 4
	var evpnNexthop Nexthop
	if version > 4 {
		b.Safi = Safi(data[0]) //frr: STREAM_GETC(s, api->safi);
		if b.Safi > safiMax {  //frr5 and later work, ToDo: fix for older version
			return fmt.Errorf("unknown safi type: %d in version: %d (%s)", b.Type, version, software.string())
		}
		data = data[1:]

		// zapi version 5 only
		if version == 5 && b.Flags&flagEvpnRoute.ToEach(version, software) > 0 {
			// size of struct ethaddr is 6 octets defined by ETH_ALEN
			copy(evpnNexthop.rmac[0:6], data[0:6])
			data = data[6:]
		}

		b.Prefix.Family = data[0] //frr: STREAM_GETC(s, api->prefix.family);
		data = data[1:]
	}

	addrByteLen, err := addressByteLength(b.Prefix.Family)
	if err != nil {
		return err
	}

	addrBitLen := uint8(addrByteLen * 8)

	b.Prefix.PrefixLen = data[0] //frr: STREAM_GETC(s, api->prefix.prefixlen);
	if b.Prefix.PrefixLen > addrBitLen {
		return fmt.Errorf("prefix length %d is greater than %d", b.Prefix.PrefixLen, addrBitLen)
	}
	data = data[1:]
	pos := 0
	rest := len(data)

	buf := make([]byte, addrByteLen)
	byteLen := int((b.Prefix.PrefixLen + 7) / 8)
	if pos+byteLen > rest {
		return fmt.Errorf("message length invalid pos:%d rest:%d", pos, rest)
	}
	//frr: STREAM_GET(&api->prefix.u.prefix, s, PSIZE(api->prefix.prefixlen));
	copy(buf, data[pos:pos+byteLen])
	b.Prefix.Prefix = ipFromFamily(b.Prefix.Family, buf)
	pos += byteLen

	if version > 3 && b.Message&messageSRCPFX.ToEach(version, software) > 0 {
		if pos+1 > rest {
			return fmt.Errorf("MessageSRCPFX message length invalid pos:%d rest:%d", pos, rest)
		}
		//frr: STREAM_GETC(s, api->src_prefix.prefixlen);
		b.srcPrefix.PrefixLen = data[pos]
		if b.srcPrefix.PrefixLen > addrBitLen {
			return fmt.Errorf("prefix length is greater than %d", addrByteLen*8)
		}
		pos++
		buf = make([]byte, addrByteLen)
		byteLen = int((b.srcPrefix.PrefixLen + 7) / 8)
		if pos+byteLen > rest {
			return fmt.Errorf("MessageSRCPFX message length invalid pos:%d rest:%d", pos, rest)
		}
		//frr: STREAM_GET(&api->src_prefix.prefix, s, PSIZE(api->src_prefix.prefixlen));
		copy(buf, data[pos:pos+byteLen])
		b.srcPrefix.Prefix = ipFromFamily(b.Prefix.Family, buf)
		pos += byteLen
	}

	// NHG(Nexthop Group) is added in frr8
	//frr: if (CHECK_FLAG(api->message, ZAPI_MESSAGE_NHG))
	if version == 6 && software.name == "frr" && software.version >= 8 { // added in frr8
		if b.Message&messageNhg.ToEach(version, software) > 0 {
			//frr: STREAM_GETL(s, api->nhgid);
			b.nhgid = binary.BigEndian.Uint32(data[pos : pos+4])
			pos += 4
		}
	}

	b.Nexthops = []Nexthop{}
	if b.Message&MessageNexthop.ToEach(version, software) > 0 {
		offset, err := b.decodeMessageNexthopFromBytes(data[pos:], version, software, false)
		if err != nil {
			return err
		}
		pos += offset
	}

	b.backupNexthops = []Nexthop{} // backupNexthops is added in frr7.4
	if b.Message&messageBackupNexthops.ToEach(version, software) > 0 {
		offset, err := b.decodeMessageNexthopFromBytes(data[pos:], version, software, true)
		if err != nil {
			return err
		}
		pos += offset
	}

	// version 5 only, In version 6, EvpnRoute is processed in MessageNexthop
	if version == 5 && b.Flags&flagEvpnRoute.ToEach(version, software) > 0 {
		b.Nexthops = append(b.Nexthops, evpnNexthop)
	}

	if version < 5 && b.Message&messageIFIndex > 0 { // version 4, 3, 2
		if pos+1 > rest {
			return fmt.Errorf("MessageIFIndex message length invalid pos:%d rest:%d", pos, rest)
		}
		numIfIndex := uint8(data[pos])
		pos++
		for i := 0; i < int(numIfIndex); i++ {
			if pos+4 > rest {
				return fmt.Errorf("MessageIFIndex message length invalid pos:%d rest:%d", pos, rest)
			}
			var nexthop Nexthop
			nexthop.Ifindex = binary.BigEndian.Uint32(data[pos : pos+4])
			nexthop.Type = nexthopTypeIFIndex
			b.Nexthops = append(b.Nexthops, nexthop)
			pos += 4
		}
	}

	if b.Message&MessageDistance.ToEach(version, software) > 0 {
		if pos+1 > rest {
			return fmt.Errorf("MessageDistance message length invalid pos:%d rest:%d", pos, rest)
		}
		b.Distance = data[pos] //frr: STREAM_GETC(s, api->distance);
		pos++
	}
	if b.Message&MessageMetric.ToEach(version, software) > 0 {
		if pos+4 > rest {
			return fmt.Errorf("MessageMetric message length invalid pos:%d rest:%d", pos, rest)
		}
		//frr: STREAM_GETL(s, api->metric);
		b.Metric = binary.BigEndian.Uint32(data[pos : pos+4])
		pos += 4
	}
	if b.Message&messageTag.ToEach(version, software) > 0 {
		if pos+4 > rest {
			return fmt.Errorf("MessageTag message length invalid pos:%d rest:%d", pos, rest)
		}
		//frr: STREAM_GETL(s, api->tag);
		b.tag = binary.BigEndian.Uint32(data[pos : pos+4])
		pos += 4
	}
	//frr3 and quagga does not have MESSAGE_MTU
	if b.Message&MessageMTU.ToEach(version, software) > 0 {
		if pos+4 > rest {
			return fmt.Errorf("MessageMTU message length invalid pos:%d rest:%d", pos, rest)
		}
		//frr: STREAM_GETL(s, api->mtu);
		b.Mtu = binary.BigEndian.Uint32(data[pos : pos+4])
		pos += 4
	}
	//frr5 and later version have MESSAGE_TABLEID
	if b.Message&messageTableID.ToEach(version, software) > 0 {
		if pos+4 > rest {
			return fmt.Errorf("MessageTableID message length invalid pos:%d rest:%d", pos, rest)
		}
		//frr: STREAM_GETL(s, api->mtu);
		b.Mtu = binary.BigEndian.Uint32(data[pos : pos+4])
		pos += 4
	}

	if version == 6 && software.name == "frr" && software.version >= 8 { // added in frr8
		if b.Message&messageOpaque.ToEach(version, software) > 0 {
			b.opaque.length = binary.BigEndian.Uint16(data[pos : pos+2])
			copy(b.opaque.data[0:b.opaque.length], data[pos+2:pos+2+int(b.opaque.length)])
			pos += 2 + int(b.opaque.length)
		}
	}

	if pos != rest {
		return fmt.Errorf("message length invalid (last) pos:%d rest:%d, message:%#x", pos, rest, b.Message)
	}
	return nil
}

func (b *IPRouteBody) string(version uint8, software Software) string {
	s := fmt.Sprintf(
		"type: %s, instance: %d, flags: %s, message: %d(%s), safi: %s, prefix: %s/%d, src_prefix: %s/%d",
		b.Type.String(), b.instance, b.Flags.String(version, software), b.Message,
		b.Message.string(version, software), b.Safi.String(), b.Prefix.Prefix.String(), b.Prefix.PrefixLen,
		b.srcPrefix.Prefix.String(), b.srcPrefix.PrefixLen)
	for i, nh := range b.Nexthops {
		s += fmt.Sprintf(", nexthops[%d]: %s", i, nh.string())
	}
	return s + fmt.Sprintf(
		", nhgid:%d, distance: %d, metric: %d, mtu: %d, tag: %d",
		b.nhgid, b.Distance, b.Metric, b.Mtu, b.tag)
}

// lookupBody is combination of nexthopLookupBody and imporetLookupBody
type lookupBody struct {
	api          APIType
	prefixLength uint8  // importLookup serialize only
	addr         net.IP //it is same as prefix (it is deleted from importLookup)
	distance     uint8  // nexthopIPv4LookupMRIB only
	metric       uint32
	nexthops     []Nexthop
}

// Quagga only. Ref: zread_ipv4_(nexthop|import_lookup) in zebra/zserv.c
func (b *lookupBody) serialize(version uint8, software Software) ([]byte, error) {
	buf := make([]byte, 0)
	if b.api == zapi3IPv4ImportLookup {
		buf = append(buf, b.prefixLength)
	}
	switch b.api {
	case ipv4NexthopLookupMRIB, zapi3IPv4NexthopLookup, zapi3IPv4ImportLookup:
		buf = append(buf, b.addr.To4()...)
	case zapi3IPv6NexthopLookup:
		buf = append(buf, b.addr.To16()...)
	}
	return buf, nil
}

// Quagga only(except ipv4NexthopLookupMRIB).
// Ref: zsend_ipv[4|6]_(nexthop|import)_lookup in zebra/zserv.c
func (b *lookupBody) decodeFromBytes(data []byte, version uint8, software Software) error {
	family := uint8(syscall.AF_INET)
	if b.api == zapi3IPv6NexthopLookup {
		family = syscall.AF_INET6
	}
	addrByteLen, _ := addressByteLength(family)
	requiredLen := 5 //metric(4), numNexthop(1)
	hasDistance := false
	if b.api == ipv4NexthopLookupMRIB.ToEach(version, software) {
		requiredLen++ //distance
		hasDistance = true
	}
	if len(data) < addrByteLen+requiredLen {
		return fmt.Errorf("message length invalid")
	}
	buf := make([]byte, addrByteLen)
	copy(buf, data[0:addrByteLen])
	pos := addrByteLen
	b.addr = ipFromFamily(family, buf)
	if hasDistance {
		b.distance = data[pos]
		pos++
	}
	b.metric = binary.BigEndian.Uint32(data[pos : pos+4])
	pos += 4
	numNexthop := uint16(data[pos])
	pos++
	b.nexthops = []Nexthop{}
	processFlag := nexthopHasType | nexthopProcessIFnameToIFindex
	nexthopsByteLen, err := decodeNexthops(&b.nexthops, data[pos:], version, software, family, numNexthop, processFlag, MessageFlag(0), Flag(0), nexthopType(0))
	if err != nil {
		return err
	}
	pos += nexthopsByteLen
	return nil
}
func (b *lookupBody) string(version uint8, software Software) string {
	s := fmt.Sprintf(
		"addr/prefixLength: %s/%d, distance:%d, metric: %d",
		b.addr.String(), b.prefixLength, b.distance, b.metric)
	if len(b.nexthops) > 0 {
		for _, nh := range b.nexthops {
			s = s + fmt.Sprintf(", nexthop:{%s}", nh.string())
		}
	}
	return s
}

// RegisteredNexthop is referred in zclient
type RegisteredNexthop struct {
	connected     uint8
	resolveViaDef uint8  // added in frr8.2
	safi          uint16 // added in frr8.2
	Family        uint16
	// Note: Ignores PrefixLength (uint8), because this field should be always:
	// - 32 if Address Family is AF_INET
	// - 128 if Address Family is AF_INET6
	Prefix net.IP
}

func (n *RegisteredNexthop) len() int {
	// Connected (1 byte) + Address Family (2 bytes) + Prefix Length (1 byte) + Prefix (variable)
	if n.Family == uint16(syscall.AF_INET) {
		return 4 + net.IPv4len
	}
	return 4 + net.IPv6len
}

// Ref: sendmsg_nexthop in bgpd/bgp_nht.c of Quagga1.2.x (ZAPI3)
// Ref: sendmsg_zebra_rnh in bgpd/bgp_nht.c of FRR3.x (ZAPI4)
// Ref: zclient_send_rnh in lib/zclient.c of FRR5&FRR6&FRR7.x&FRR8 (ZAPI5&6)
func (n *RegisteredNexthop) serialize(version uint8, software Software) ([]byte, error) {
	bufInitSize := 4
	if version == 6 && software.name == "frr" && software.version >= 8.2 {
		bufInitSize = 7
	}
	buf := make([]byte, bufInitSize)
	// Connected (1 byte)
	buf[0] = byte(n.connected) // stream_putc(s, (connected) ? 1 : 0);
	pos := 1
	if version == 6 && software.name == "frr" && software.version >= 8.2 {
		buf[1] = byte(n.resolveViaDef)
		binary.BigEndian.PutUint16(buf[1:3], uint16(SafiUnicast)) // stream_putw(s, PREFIX_FAMILY(p));
		pos += 3
	}
	// Address Family (2 bytes)
	binary.BigEndian.PutUint16(buf[pos:pos+2], n.Family) // stream_putw(s, PREFIX_FAMILY(p));
	pos += 2
	// Prefix Length (1 byte)
	addrByteLen, err := addressByteLength(uint8(n.Family))
	if err != nil {
		return nil, err
	}

	buf[3] = byte(addrByteLen * 8) // stream_putc(s, p->prefixlen);
	pos += 1
	// Prefix (variable)
	switch n.Family {
	case uint16(syscall.AF_INET):
		buf = append(buf, n.Prefix.To4()...) // stream_put_in_addr(s, &p->u.prefix4);
	case uint16(syscall.AF_INET6):
		buf = append(buf, n.Prefix.To16()...) // stream_put(s, &(p->u.prefix6), 16);
	default:
		return nil, fmt.Errorf("invalid address family: %d", n.Family)
	}

	return buf, nil
}

// Ref: zserv_nexthop_register in zebra/zserv.c of Quagga1.2.x (ZAPI3)
// Ref: zserv_rnh_register in zebra/zserv.c of FRR3.x (ZAPI4)
// Ref: zread_rnh_register in zebra/zapi_msg.c of FRR5&FRR6&FRR7.x&FRR8 (ZAPI5&6)
func (n *RegisteredNexthop) decodeFromBytes(data []byte, version uint8, software Software) error {
	// Connected (1 byte)
	n.connected = uint8(data[0])
	data = data[1:]
	if version == 6 && software.name == "frr" && software.version >= 8.2 {
		n.resolveViaDef = uint8(data[0])            //STREAM_GETC(s, resolve_via_default);
		n.safi = binary.BigEndian.Uint16(data[1:3]) //STREAM_GETW(s, safi);
		data = data[3:]
	}
	// Address Family (2 bytes)
	n.Family = binary.BigEndian.Uint16(data[0:2])
	// Note: Ignores Prefix Length (1 byte)
	addrByteLen := (int(data[2]) + 7) / 8
	// Prefix (variable)
	n.Prefix = ipFromFamily(uint8(n.Family), data[3:3+addrByteLen])

	return nil
}

func (n *RegisteredNexthop) string(version uint8, software Software) string {
	return fmt.Sprintf(
		"connected: %d, resolveViaDef:%d, safi: %d, family: %d, prefix: %s",
		n.connected, n.resolveViaDef, n.safi, n.Family, n.Prefix.String())
}

// NexthopRegisterBody us referred in zclient
type NexthopRegisterBody struct {
	api      APIType
	Nexthops []*RegisteredNexthop
}

// Ref: sendmsg_nexthop in bgpd/bgp_nht.c of Quagga1.2.x (ZAPI3)
// Ref: sendmsg_zebra_rnh in bgpd/bgp_nht.c of FRR3.x (ZAPI4)
// Ref: zclient_send_rnh in lib/zclient.c of FRR5&FRR6&FRR7.x&FRR8 (ZAPI5&6)
func (b *NexthopRegisterBody) serialize(version uint8, software Software) ([]byte, error) {
	buf := make([]byte, 0)

	// List of Registered Nexthops
	for _, nh := range b.Nexthops {
		nhBuf, err := nh.serialize(version, software)
		if err != nil {
			return nil, err
		}
		buf = append(buf, nhBuf...)
	}

	return buf, nil
}

// Ref: zserv_nexthop_register in zebra/zserv.c of Quagga1.2.x (ZAPI3)
// Ref: zserv_rnh_register in zebra/zserv.c of FRR3.x (ZAPI4)
// Ref: zread_rnh_register in zebra/zapi_msg.c of FRR5.x (ZAPI5)
func (b *NexthopRegisterBody) decodeFromBytes(data []byte, version uint8, software Software) error {
	offset := 0
	// List of Registered Nexthops
	b.Nexthops = []*RegisteredNexthop{}
	for len(data[offset:]) > 0 {
		nh := new(RegisteredNexthop)
		err := nh.decodeFromBytes(data[offset:], version, software)
		if err != nil {
			return err
		}
		b.Nexthops = append(b.Nexthops, nh)

		offset += nh.len()
		if len(data) < offset {
			break
		}
	}
	return nil
}

func (b *NexthopRegisterBody) string(version uint8, software Software) string {
	s := make([]string, 0)
	for _, nh := range b.Nexthops {
		s = append(s, fmt.Sprintf("nexthop:{%s}", nh.string(version, software)))
	}
	return strings.Join(s, ", ")
}

// NexthopUpdateBody uses same data structure as IPRoute (zapi_route) after frr4 (Zapi5)
type NexthopUpdateBody IPRouteBody

// Ref: send_client in zebra/zebra_rnh.c of Quagga1.2&FRR3&FRR5(ZAPI3&4$5) and until FRR7.4
// Ref: zebra_send_rnh_update zebra/zebra_rnh.c of FRR7.5&FRR8
func (b *NexthopUpdateBody) serialize(version uint8, software Software) ([]byte, error) {
	var buf []byte
	offset := 0
	// Message (4 bytes) // if (srte_color) stream_putl(s, message);
	if version == 6 && software.name == "frr" && software.version >= 7.5 { // since frr7.5
		buf = make([]byte, 7)
		binary.BigEndian.PutUint32(buf, uint32(b.Message))
		offset += 4
	} else { // until frr7.4
		buf = make([]byte, 3)
	}

	// Address Family (2 bytes)
	binary.BigEndian.PutUint16(buf[offset:], uint16(b.Prefix.Family))
	addrByteLen, err := addressByteLength(b.Prefix.Family)
	if err != nil {
		return nil, err
	}

	buf[offset+2] = byte(addrByteLen * 8) //stream_putc(s, rn->p.prefixlen);
	// Prefix Length (1 byte) + Prefix (variable)
	switch b.Prefix.Family {
	case syscall.AF_INET:
		buf = append(buf, b.Prefix.Prefix.To4()...)
	case syscall.AF_INET6:
		buf = append(buf, b.Prefix.Prefix.To16()...)
	default:
		return nil, fmt.Errorf("invalid address family: %d", b.Prefix.Family)
	}
	// SRTE color // if (srte_color) stream_putl(s, srte_color);
	if b.Message&messageSRTE > 0 { // since frr 7.5
		tmpbuf := make([]byte, 4)
		binary.BigEndian.PutUint32(tmpbuf, b.srteColor)
		buf = append(buf, tmpbuf...)
	}
	if version >= 5 {
		// Type (1 byte) (if version>=5)
		// instance (2 bytes) (if version>=5)
		buf = append(buf, byte(b.Type))
		tmpbuf := make([]byte, 2)
		binary.BigEndian.PutUint16(tmpbuf, b.instance)
		buf = append(buf, tmpbuf...)
	}
	if version >= 4 {
		// Distance (1 byte) (if version>=4)
		buf = append(buf, b.Distance)
	}
	// Metric (4 bytes)
	tmpbuf := make([]byte, 4)
	binary.BigEndian.PutUint32(tmpbuf, b.Metric)
	buf = append(buf, tmpbuf...)
	// Number of Nexthops (1 byte)
	buf = append(buf, uint8(0)) // Temporary code
	// ToDo Processing Route Entry
	return buf, nil
}

// Ref: bgp_parse_nexthop_update in bgpd/bgp_nht.c of Quagga1.2&FRR3 (ZAPI3&4)
// Ref: zapi_nexthop_update_decode in lib/zclient.c of FRR5.x&FRR6&FRR7.x&FRR8 (ZAPI5&6)
func (b *NexthopUpdateBody) decodeFromBytes(data []byte, version uint8, software Software) error {
	if version == 6 && software.name == "frr" && software.version >= 7.5 { // since frr7.5
		//Message //frr7.5: STREAM_GETL(s, nhr->message);
		b.Message = MessageFlag(binary.BigEndian.Uint32(data[0:4]))
		data = data[4:]
		if software.version >= 8.2 { //added in frr8.2
			b.Safi = Safi(binary.BigEndian.Uint16(data[0:2]))
			var match Prefix
			match.Family = uint8(binary.BigEndian.Uint16(data[2:4])) // STREAM_GETC(s, match->prefixlen);
			match.PrefixLen = data[4]                                // STREAM_GETC(s, match->prefixlen);
			addrByteLen, err := addressByteLength(match.Family)
			if err != nil {
				return err
			}
			match.Prefix = ipFromFamily(b.Prefix.Family, data[5:5+addrByteLen])
			data = data[5+addrByteLen:]
		}
	}
	// Address Family (2 bytes) and Prefix Length (1 byte)
	prefixFamily := binary.BigEndian.Uint16(data[0:2])
	b.Prefix.Family = uint8(prefixFamily)
	b.Prefix.PrefixLen = data[2]
	offset := 3

	addrByteLen, err := addressByteLength(b.Prefix.Family)
	if err != nil {
		return err
	}

	b.Prefix.Prefix = ipFromFamily(b.Prefix.Family, data[offset:offset+addrByteLen])
	offset += addrByteLen

	if b.Message&messageSRTE > 0 { // since frr 7.5
		b.srteColor = binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4
	}

	if version > 4 {
		// Route Type (1 byte) and insrance (2 bytes)
		b.Type = RouteType(data[offset])
		b.instance = binary.BigEndian.Uint16(data[offset+1 : offset+3])
		offset += 3
	}
	// Distance (1 byte) (if version>=4)
	if version > 3 {
		b.Distance = data[offset]
		offset++
	}
	// Metric (4 bytes) & Number of Nexthops (1 byte)
	if len(data[offset:]) < 5 {
		return fmt.Errorf("invalid message length: missing metric(4 bytes) or nexthops(1 byte): %d<5", len(data[offset:]))
	}
	b.Metric = binary.BigEndian.Uint32(data[offset : offset+4])
	offset += 4

	numNexthop := uint16(data[offset])
	offset++
	// List of Nexthops
	b.Nexthops = []Nexthop{}

	processFlag := nexthopProcessFlag(nexthopHasType)
	if version == 6 && software.name == "frr" {
		if software.version >= 7.3 {
			processFlag |= (nexthopHasVrfID | nexthopHasFlag | nexthopProcessIPToIPIFindex)
		} else if software.version >= 7 {
			processFlag |= (nexthopHasVrfID | nexthopProcessIPToIPIFindex)
		} else if software.version >= 6 {
			processFlag |= nexthopProcessIPToIPIFindex
		}
	} else if version == 5 && software.name == "frr" && software.version == 5 {
		processFlag |= nexthopProcessIPToIPIFindex
	} else if version < 4 { // quagga
		processFlag |= nexthopProcessIFnameToIFindex
	}

	// since frr7.3, MessageLabel is deleted
	if (version == 6 && software.name == "frr" && software.version < 7.3) ||
		(version == 5 && software.name == "frr" && software.version == 5) {
		b.Message |= MessageLabel
	}

	nexthopsByteLen, err := decodeNexthops(&b.Nexthops, data[offset:], version, software, b.Prefix.Family, numNexthop, processFlag, b.Message, Flag(0), nexthopType(0))
	if err != nil {
		return err
	}
	offset += nexthopsByteLen
	return nil
}

func (b *NexthopUpdateBody) string(version uint8, software Software) string {
	s := fmt.Sprintf(
		"family: %d, prefix: %s, distance: %d, metric: %d",
		b.Prefix.Family, b.Prefix.Prefix.String(), b.Distance, b.Metric)
	for _, nh := range b.Nexthops {
		s = s + fmt.Sprintf(", nexthop:{%s}", nh.string())
	}
	return s
}

type labelManagerConnectBody struct {
	redistDefault RouteType
	instance      uint16
	// The followings are used in response from Zebra
	result uint8 // 0 means success
}

// Ref: lm_label_manager_connect in lib/zclient.c of FRR
func (b *labelManagerConnectBody) serialize(version uint8, software Software) ([]byte, error) {
	buf := make([]byte, 3)
	buf[0] = uint8(b.redistDefault)
	binary.BigEndian.PutUint16(buf[1:3], b.instance)
	return buf, nil
}

func (b *labelManagerConnectBody) decodeFromBytes(data []byte, version uint8, software Software) error {
	size := 1
	if version > 4 && !(software.name == "frr" && software.version == 4) { // FRR4 returns result only.
		size = 4
	}
	if len(data) < size {
		return fmt.Errorf("invalid message length for LabelManagerConnect response: %d<%d",
			len(data), size)
	}
	if version > 4 && !(software.name == "frr" && software.version == 4) {
		b.redistDefault = RouteType(data[0])
		b.instance = binary.BigEndian.Uint16(data[1:3])
		data = data[3:]
	}
	b.result = data[0]
	return nil
}

func (b *labelManagerConnectBody) string(version uint8, software Software) string {
	return fmt.Sprintf(
		"route_type: %s, instance: %d, result: %d",
		b.redistDefault.String(), b.instance, b.result)
}

// GetLabelChunkBody is referred in zclient (Ref: zsend_assign_label_chunk_response)
type GetLabelChunkBody struct {
	proto     uint8  // it is appeared in FRR5.x and 6.x
	instance  uint16 // it is appeared in FRR5.x and 6.x
	keep      uint8
	ChunkSize uint32
	Start     uint32 // The followings are used in response from Zebra
	End       uint32
	base      uint32 // it is added in FRR7.2
}

// Ref: zread_get_label_chunk in zebra/zserv.c of FRR3.x
// Ref: zread_get_label_chunk in zebra/zapi_msg.c of FRR5.x, 6.x, 7,x, and 8
func (b *GetLabelChunkBody) serialize(version uint8, software Software) ([]byte, error) {
	buf := make([]byte, 12)
	pos := 0
	b.base = 0
	if version > 4 && !(software.name == "frr" && software.version == 4) {
		buf[pos] = b.proto
		binary.BigEndian.PutUint16(buf[pos+1:pos+3], b.instance)
		pos += 3
	}
	buf[pos] = b.keep
	binary.BigEndian.PutUint32(buf[pos+1:pos+5], b.ChunkSize)
	pos += 5
	if version == 6 && software.name == "frr" && software.version >= 7.2 {
		binary.BigEndian.PutUint32(buf[pos:pos+4], b.base)
		pos += 4
	}
	return buf[0:pos], nil
}

// Ref: zsend_assign_label_chunk_response in zebra/zserv.c of FRR3.x
// Ref: zsend_assign_label_chunk_response in zebra/zapi_msg.c of FRR5.x, 6.x, 7,x, and 8
func (b *GetLabelChunkBody) decodeFromBytes(data []byte, version uint8, software Software) error {
	size := 9
	if version > 4 && !(software.name == "frr" && software.version == 4) {
		size = 12
	}
	if len(data) < size {
		return fmt.Errorf("invalid message length for GetLabelChunk response: %d<%d",
			len(data), size)
	}
	if version > 4 && !(software.name == "frr" && software.version == 4) {
		b.proto = data[0]
		b.instance = binary.BigEndian.Uint16(data[1:3])
		data = data[3:]
	}
	b.keep = data[0]
	b.Start = binary.BigEndian.Uint32(data[1:5])
	b.End = binary.BigEndian.Uint32(data[5:9])
	return nil
}

func (b *GetLabelChunkBody) string(version uint8, software Software) string {
	return fmt.Sprintf(
		"keep: %d, chunk_size: %d, start: %d, end: %d",
		b.keep, b.ChunkSize, b.Start, b.End)
}

type releaseLabelChunkBody struct {
	proto    uint8  // it is added in FRR5.x
	instance uint16 // it is added in FRR5.x
	start    uint32
	end      uint32
}

// Ref: zread_release_label_chunk in zebra/zapi_msg.c of FRR
func (b *releaseLabelChunkBody) serialize(version uint8, software Software) ([]byte, error) {
	buf := make([]byte, 11)
	pos := 0
	if version > 4 && !(software.name == "frr" && software.version == 4) {
		buf[pos] = b.proto
		binary.BigEndian.PutUint16(buf[pos+1:pos+3], b.instance)
		pos += 3
	}
	binary.BigEndian.PutUint32(buf[pos:pos+4], b.start)
	binary.BigEndian.PutUint32(buf[pos+4:pos+8], b.end)
	pos += 8
	return buf[0:pos], nil
}

func (b *releaseLabelChunkBody) decodeFromBytes(data []byte, version uint8, software Software) error {
	return nil // No response from Zebra
}

func (b *releaseLabelChunkBody) string(version uint8, software Software) string {
	return fmt.Sprintf("start: %d, end: %d", b.start, b.end)
}

//go:generate stringer -type=lspTYPE
type lspTYPE uint8

const (
	lspNone   lspTYPE = iota //defined in FRR3 and over
	lspStatic                //defined in FRR3 and over
	lspLDP                   //defined in FRR3 and over
	lspBGP                   //defined in FRR4 and over
	lspSR                    //defined in FRR4 and over
	lspSHARP                 //defined in FRR5 and over
)

type vrfLabelBody struct {
	label     uint32
	afi       afi
	labelType lspTYPE
}

// Ref: zclient_send_vrf_label in lib/zclient.c of FRR 5.x, 6.x, 7.x, and 8
func (b *vrfLabelBody) serialize(version uint8, software Software) ([]byte, error) {
	buf := make([]byte, 6)
	binary.BigEndian.PutUint32(buf[0:4], b.label)
	buf[4] = uint8(b.afi)
	buf[5] = uint8(b.labelType)
	return buf, nil
}

// Ref: zread_vrf_label in zebra/zapi_msg.c of FRR 5.x, 6.x, 7.x, and 8
func (b *vrfLabelBody) decodeFromBytes(data []byte, version uint8, software Software) error {
	if len(data) < 6 {
		return fmt.Errorf("invalid message length for VRFLabel message: %d<6", len(data))
	}
	b.label = binary.BigEndian.Uint32(data[0:4])
	b.afi = afi(data[4])
	b.labelType = lspTYPE(data[5])
	return nil
}

func (b *vrfLabelBody) string(version uint8, software Software) string {
	return fmt.Sprintf(
		"label: %d, afi: %s LSP type: %s",
		b.label, b.afi, b.labelType)
}

// Message is referred in zclient
type Message struct {
	Header Header
	Body   Body
}

func (m *Message) serialize(software Software) ([]byte, error) {
	var body []byte
	if m.Body != nil {
		var err error
		body, err = m.Body.serialize(m.Header.Version, software)
		if err != nil {
			return nil, err
		}
	}
	m.Header.Len = uint16(len(body)) + HeaderSize(m.Header.Version)
	hdr, err := m.Header.serialize()
	if err != nil {
		return nil, err
	}
	return append(hdr, body...), nil
}

func parseMessage(hdr *Header, data []byte, software Software) (m *Message, err error) {
	m = &Message{Header: *hdr}
	/* TODO:
	   InterfaceNBRAddressAdd, InterfaceNBRAddressDelete,
	   InterfaceBFDDestUpdate, ImportCheckUpdate, BFDDestReplay,
	   InterfaceVRFUpdate, InterfaceLinkParams, PWStatusUpdate
	*/
	command := m.Header.Command.toCommon(m.Header.Version, software)
	switch command {
	case interfaceAdd, interfaceDelete, interfaceUp, interfaceDown:
		m.Body = &interfaceUpdateBody{}
	case interfaceAddressAdd, interfaceAddressDelete:
		m.Body = &interfaceAddressUpdateBody{}
	case routerIDUpdate:
		m.Body = &routerIDUpdateBody{}
	case nexthopUpdate:
		m.Body = &NexthopUpdateBody{}
	case redistributeRouteAdd, redistributeRouteDel: // for frr
		m.Body = &IPRouteBody{API: m.Header.Command}
	case labelManagerConnect: // Note: Synchronous message
		m.Body = &labelManagerConnectBody{}
	case getLabelChunk: // Note: Synchronous message
		m.Body = &GetLabelChunkBody{}
	case releaseLabelChunk: // Note: Synchronous message
		m.Body = &releaseLabelChunkBody{}
	case vrfLabel:
		m.Body = &vrfLabelBody{}
	case RouteAdd, RouteDelete, BackwardIPv6RouteAdd, BackwardIPv6RouteDelete: // for quagga
		m.Body = &IPRouteBody{API: m.Header.Command}
	case ipv4NexthopLookupMRIB:
		m.Body = &lookupBody{api: m.Header.Command}
	default:
		m.Body = &unknownBody{}
		if m.Header.Version == 4 {
			switch m.Header.Command {
			case zapi4RedistributeIPv6Add, zapi4RedistributeIPv6Del: // for frr3
				m.Body = &IPRouteBody{API: m.Header.Command}
			}
		} else if m.Header.Version < 4 {
			switch m.Header.Command {
			case zapi3IPv4NexthopLookup, zapi3IPv6NexthopLookup, zapi3IPv4ImportLookup:
				m.Body = &lookupBody{api: m.Header.Command}
			}
		}
	}
	return m, m.Body.decodeFromBytes(data, m.Header.Version, software)
}
