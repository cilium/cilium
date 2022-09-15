// Copyright (C) 2014 Nippon Telegraph and Telephone Corporation.
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
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

type MarshallingOption struct {
	AddPath    map[RouteFamily]BGPAddPathMode
	Attributes map[BGPAttrType]bool
}

func IsAddPathEnabled(decode bool, f RouteFamily, options []*MarshallingOption) bool {
	for _, opt := range options {
		if opt == nil {
			continue
		}
		if o := opt.AddPath; o != nil {
			if decode && o[f]&BGP_ADD_PATH_RECEIVE > 0 {
				return true
			} else if !decode && o[f]&BGP_ADD_PATH_SEND > 0 {
				return true
			}
		}
	}
	return false
}
func IsAttributePresent(attr BGPAttrType, options []*MarshallingOption) bool {
	for _, opt := range options {
		if opt == nil {
			continue
		}
		if o := opt.Attributes; o != nil {
			_, ok := o[attr]
			return ok
		}
	}
	return false
}

const (
	AFI_IP     = 1
	AFI_IP6    = 2
	AFI_L2VPN  = 25
	AFI_LS     = 16388
	AFI_OPAQUE = 16397
)

const (
	SAFI_UNICAST                  = 1
	SAFI_MULTICAST                = 2
	SAFI_MPLS_LABEL               = 4
	SAFI_ENCAPSULATION            = 7
	SAFI_VPLS                     = 65
	SAFI_EVPN                     = 70
	SAFI_LS                       = 71
	SAFI_SRPOLICY                 = 73
	SAFI_MUP                      = 85
	SAFI_MPLS_VPN                 = 128
	SAFI_MPLS_VPN_MULTICAST       = 129
	SAFI_ROUTE_TARGET_CONSTRAINTS = 132
	SAFI_FLOW_SPEC_UNICAST        = 133
	SAFI_FLOW_SPEC_VPN            = 134
	SAFI_KEY_VALUE                = 241
)

const (
	BGP_ORIGIN_ATTR_TYPE_IGP        uint8 = 0
	BGP_ORIGIN_ATTR_TYPE_EGP        uint8 = 1
	BGP_ORIGIN_ATTR_TYPE_INCOMPLETE uint8 = 2
)

const (
	BGP_ASPATH_ATTR_TYPE_SET        = 1
	BGP_ASPATH_ATTR_TYPE_SEQ        = 2
	BGP_ASPATH_ATTR_TYPE_CONFED_SEQ = 3
	BGP_ASPATH_ATTR_TYPE_CONFED_SET = 4
)

const (
	BGP_ATTR_NHLEN_IPV6_GLOBAL        = 16
	BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL = 32
)

// RFC7153 5.1. Registries for the "Type" Field
// RANGE	REGISTRATION PROCEDURES
// 0x00-0x3F	Transitive First Come First Served
// 0x40-0x7F	Non-Transitive First Come First Served
// 0x80-0x8F	Transitive Experimental Use
// 0x90-0xBF	Transitive Standards Action
// 0xC0-0xCF	Non-Transitive Experimental Use
// 0xD0-0xFF	Non-Transitive Standards Action
type ExtendedCommunityAttrType uint8

const (
	EC_TYPE_TRANSITIVE_TWO_OCTET_AS_SPECIFIC      ExtendedCommunityAttrType = 0x00
	EC_TYPE_TRANSITIVE_IP6_SPECIFIC               ExtendedCommunityAttrType = 0x00 // RFC5701
	EC_TYPE_TRANSITIVE_IP4_SPECIFIC               ExtendedCommunityAttrType = 0x01
	EC_TYPE_TRANSITIVE_FOUR_OCTET_AS_SPECIFIC     ExtendedCommunityAttrType = 0x02
	EC_TYPE_TRANSITIVE_OPAQUE                     ExtendedCommunityAttrType = 0x03
	EC_TYPE_TRANSITIVE_QOS_MARKING                ExtendedCommunityAttrType = 0x04
	EC_TYPE_COS_CAPABILITY                        ExtendedCommunityAttrType = 0x05
	EC_TYPE_EVPN                                  ExtendedCommunityAttrType = 0x06
	EC_TYPE_FLOWSPEC_REDIRECT_MIRROR              ExtendedCommunityAttrType = 0x08
	EC_TYPE_MUP                                   ExtendedCommunityAttrType = 0x0c
	EC_TYPE_NON_TRANSITIVE_TWO_OCTET_AS_SPECIFIC  ExtendedCommunityAttrType = 0x40
	EC_TYPE_NON_TRANSITIVE_LINK_BANDWIDTH         ExtendedCommunityAttrType = 0x40
	EC_TYPE_NON_TRANSITIVE_IP6_SPECIFIC           ExtendedCommunityAttrType = 0x40 // RFC5701
	EC_TYPE_NON_TRANSITIVE_IP4_SPECIFIC           ExtendedCommunityAttrType = 0x41
	EC_TYPE_NON_TRANSITIVE_FOUR_OCTET_AS_SPECIFIC ExtendedCommunityAttrType = 0x42
	EC_TYPE_NON_TRANSITIVE_OPAQUE                 ExtendedCommunityAttrType = 0x43
	EC_TYPE_NON_TRANSITIVE_QOS_MARKING            ExtendedCommunityAttrType = 0x44
	EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL       ExtendedCommunityAttrType = 0x80
	EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL2      ExtendedCommunityAttrType = 0x81 // RFC7674
	EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL3      ExtendedCommunityAttrType = 0x82 // RFC7674
)

// RFC7153 5.2. Registries for the "Sub-Type" Field
// RANGE	REGISTRATION PROCEDURES
// 0x00-0xBF	First Come First Served
// 0xC0-0xFF	IETF Review
type ExtendedCommunityAttrSubType uint8

const (
	EC_SUBTYPE_ROUTE_TARGET            ExtendedCommunityAttrSubType = 0x02 // EC_TYPE: 0x00, 0x01, 0x02
	EC_SUBTYPE_ROUTE_ORIGIN            ExtendedCommunityAttrSubType = 0x03 // EC_TYPE: 0x00, 0x01, 0x02
	EC_SUBTYPE_LINK_BANDWIDTH          ExtendedCommunityAttrSubType = 0x04 // EC_TYPE: 0x40
	EC_SUBTYPE_GENERIC                 ExtendedCommunityAttrSubType = 0x04 // EC_TYPE: 0x02, 0x42
	EC_SUBTYPE_OSPF_DOMAIN_ID          ExtendedCommunityAttrSubType = 0x05 // EC_TYPE: 0x00, 0x01, 0x02
	EC_SUBTYPE_OSPF_ROUTE_ID           ExtendedCommunityAttrSubType = 0x07 // EC_TYPE: 0x01
	EC_SUBTYPE_BGP_DATA_COLLECTION     ExtendedCommunityAttrSubType = 0x08 // EC_TYPE: 0x00, 0x02
	EC_SUBTYPE_SOURCE_AS               ExtendedCommunityAttrSubType = 0x09 // EC_TYPE: 0x00, 0x02
	EC_SUBTYPE_L2VPN_ID                ExtendedCommunityAttrSubType = 0x0A // EC_TYPE: 0x00, 0x01
	EC_SUBTYPE_VRF_ROUTE_IMPORT        ExtendedCommunityAttrSubType = 0x0B // EC_TYPE: 0x01
	EC_SUBTYPE_CISCO_VPN_DISTINGUISHER ExtendedCommunityAttrSubType = 0x10 // EC_TYPE: 0x00, 0x01, 0x02

	EC_SUBTYPE_OSPF_ROUTE_TYPE ExtendedCommunityAttrSubType = 0x06 // EC_TYPE: 0x03
	EC_SUBTYPE_COLOR           ExtendedCommunityAttrSubType = 0x0B // EC_TYPE: 0x03
	EC_SUBTYPE_ENCAPSULATION   ExtendedCommunityAttrSubType = 0x0C // EC_TYPE: 0x03
	EC_SUBTYPE_DEFAULT_GATEWAY ExtendedCommunityAttrSubType = 0x0D // EC_TYPE: 0x03

	EC_SUBTYPE_ORIGIN_VALIDATION ExtendedCommunityAttrSubType = 0x00 // EC_TYPE: 0x43

	EC_SUBTYPE_MUP_DIRECT_SEG ExtendedCommunityAttrSubType = 0x00 // EC_TYPE: 0x0c

	EC_SUBTYPE_FLOWSPEC_TRAFFIC_RATE   ExtendedCommunityAttrSubType = 0x06 // EC_TYPE: 0x80
	EC_SUBTYPE_FLOWSPEC_TRAFFIC_ACTION ExtendedCommunityAttrSubType = 0x07 // EC_TYPE: 0x80
	EC_SUBTYPE_FLOWSPEC_REDIRECT       ExtendedCommunityAttrSubType = 0x08 // EC_TYPE: 0x80
	EC_SUBTYPE_FLOWSPEC_TRAFFIC_REMARK ExtendedCommunityAttrSubType = 0x09 // EC_TYPE: 0x80
	EC_SUBTYPE_L2_INFO                 ExtendedCommunityAttrSubType = 0x0A // EC_TYPE: 0x80
	EC_SUBTYPE_FLOWSPEC_REDIRECT_IP6   ExtendedCommunityAttrSubType = 0x0B // EC_TYPE: 0x80

	EC_SUBTYPE_MAC_MOBILITY ExtendedCommunityAttrSubType = 0x00 // EC_TYPE: 0x06
	EC_SUBTYPE_ESI_LABEL    ExtendedCommunityAttrSubType = 0x01 // EC_TYPE: 0x06
	EC_SUBTYPE_ES_IMPORT    ExtendedCommunityAttrSubType = 0x02 // EC_TYPE: 0x06
	EC_SUBTYPE_ROUTER_MAC   ExtendedCommunityAttrSubType = 0x03 // EC_TYPE: 0x06

	EC_SUBTYPE_UUID_BASED_RT ExtendedCommunityAttrSubType = 0x11
)

type TunnelType uint16

const (
	TUNNEL_TYPE_L2TP3       TunnelType = 1
	TUNNEL_TYPE_GRE         TunnelType = 2
	TUNNEL_TYPE_IP_IN_IP    TunnelType = 7
	TUNNEL_TYPE_VXLAN       TunnelType = 8
	TUNNEL_TYPE_NVGRE       TunnelType = 9
	TUNNEL_TYPE_MPLS        TunnelType = 10
	TUNNEL_TYPE_MPLS_IN_GRE TunnelType = 11
	TUNNEL_TYPE_VXLAN_GRE   TunnelType = 12
	TUNNEL_TYPE_MPLS_IN_UDP TunnelType = 13
	TUNNEL_TYPE_SR_POLICY   TunnelType = 15
	TUNNEL_TYPE_GENEVE      TunnelType = 19
)

func (p TunnelType) String() string {
	switch p {
	case TUNNEL_TYPE_L2TP3:
		return "l2tp3"
	case TUNNEL_TYPE_GRE:
		return "gre"
	case TUNNEL_TYPE_IP_IN_IP:
		return "ip-in-ip"
	case TUNNEL_TYPE_VXLAN:
		return "vxlan"
	case TUNNEL_TYPE_NVGRE:
		return "nvgre"
	case TUNNEL_TYPE_MPLS:
		return "mpls"
	case TUNNEL_TYPE_MPLS_IN_GRE:
		return "mpls-in-gre"
	case TUNNEL_TYPE_VXLAN_GRE:
		return "vxlan-gre"
	case TUNNEL_TYPE_MPLS_IN_UDP:
		return "mpls-in-udp"
	case TUNNEL_TYPE_SR_POLICY:
		return "sr-policy"
	case TUNNEL_TYPE_GENEVE:
		return "geneve"
	default:
		return fmt.Sprintf("TunnelType(%d)", uint8(p))
	}
}

type PmsiTunnelType uint8

const (
	PMSI_TUNNEL_TYPE_NO_TUNNEL      PmsiTunnelType = 0
	PMSI_TUNNEL_TYPE_RSVP_TE_P2MP   PmsiTunnelType = 1
	PMSI_TUNNEL_TYPE_MLDP_P2MP      PmsiTunnelType = 2
	PMSI_TUNNEL_TYPE_PIM_SSM_TREE   PmsiTunnelType = 3
	PMSI_TUNNEL_TYPE_PIM_SM_TREE    PmsiTunnelType = 4
	PMSI_TUNNEL_TYPE_BIDIR_PIM_TREE PmsiTunnelType = 5
	PMSI_TUNNEL_TYPE_INGRESS_REPL   PmsiTunnelType = 6
	PMSI_TUNNEL_TYPE_MLDP_MP2MP     PmsiTunnelType = 7
)

func (p PmsiTunnelType) String() string {
	switch p {
	case PMSI_TUNNEL_TYPE_NO_TUNNEL:
		return "no-tunnel"
	case PMSI_TUNNEL_TYPE_RSVP_TE_P2MP:
		return "rsvp-te-p2mp"
	case PMSI_TUNNEL_TYPE_MLDP_P2MP:
		return "mldp-p2mp"
	case PMSI_TUNNEL_TYPE_PIM_SSM_TREE:
		return "pim-ssm-tree"
	case PMSI_TUNNEL_TYPE_PIM_SM_TREE:
		return "pim-sm-tree"
	case PMSI_TUNNEL_TYPE_BIDIR_PIM_TREE:
		return "bidir-pim-tree"
	case PMSI_TUNNEL_TYPE_INGRESS_REPL:
		return "ingress-repl"
	case PMSI_TUNNEL_TYPE_MLDP_MP2MP:
		return "mldp-mp2mp"
	default:
		return fmt.Sprintf("PmsiTunnelType(%d)", uint8(p))
	}
}

type EncapSubTLVType uint8

const (
	ENCAP_SUBTLV_TYPE_ENCAPSULATION         EncapSubTLVType = 1
	ENCAP_SUBTLV_TYPE_PROTOCOL              EncapSubTLVType = 2
	ENCAP_SUBTLV_TYPE_COLOR                 EncapSubTLVType = 4
	ENCAP_SUBTLV_TYPE_EGRESS_ENDPOINT       EncapSubTLVType = 6
	ENCAP_SUBTLV_TYPE_UDP_DEST_PORT         EncapSubTLVType = 8
	ENCAP_SUBTLV_TYPE_SRPREFERENCE          EncapSubTLVType = 12
	ENCAP_SUBTLV_TYPE_SRBINDING_SID         EncapSubTLVType = 13
	ENCAP_SUBTLV_TYPE_SRENLP                EncapSubTLVType = 14
	ENCAP_SUBTLV_TYPE_SRPRIORITY            EncapSubTLVType = 15
	ENCAP_SUBTLV_TYPE_SRSEGMENT_LIST        EncapSubTLVType = 128
	ENCAP_SUBTLV_TYPE_SRCANDIDATE_PATH_NAME EncapSubTLVType = 129
)

const (
	_ = iota
	BGP_MSG_OPEN
	BGP_MSG_UPDATE
	BGP_MSG_NOTIFICATION
	BGP_MSG_KEEPALIVE
	BGP_MSG_ROUTE_REFRESH
)

const (
	BGP_OPT_CAPABILITY = 2
)

type BGPCapabilityCode uint8

const (
	BGP_CAP_MULTIPROTOCOL               BGPCapabilityCode = 1
	BGP_CAP_ROUTE_REFRESH               BGPCapabilityCode = 2
	BGP_CAP_CARRYING_LABEL_INFO         BGPCapabilityCode = 4
	BGP_CAP_EXTENDED_NEXTHOP            BGPCapabilityCode = 5
	BGP_CAP_GRACEFUL_RESTART            BGPCapabilityCode = 64
	BGP_CAP_FOUR_OCTET_AS_NUMBER        BGPCapabilityCode = 65
	BGP_CAP_ADD_PATH                    BGPCapabilityCode = 69
	BGP_CAP_ENHANCED_ROUTE_REFRESH      BGPCapabilityCode = 70
	BGP_CAP_LONG_LIVED_GRACEFUL_RESTART BGPCapabilityCode = 71
	BGP_CAP_FQDN                        BGPCapabilityCode = 73
	BGP_CAP_ROUTE_REFRESH_CISCO         BGPCapabilityCode = 128
)

var CapNameMap = map[BGPCapabilityCode]string{
	BGP_CAP_MULTIPROTOCOL:               "multiprotocol",
	BGP_CAP_ROUTE_REFRESH:               "route-refresh",
	BGP_CAP_CARRYING_LABEL_INFO:         "carrying-label-info",
	BGP_CAP_GRACEFUL_RESTART:            "graceful-restart",
	BGP_CAP_EXTENDED_NEXTHOP:            "extended-nexthop",
	BGP_CAP_FOUR_OCTET_AS_NUMBER:        "4-octet-as",
	BGP_CAP_ADD_PATH:                    "add-path",
	BGP_CAP_ENHANCED_ROUTE_REFRESH:      "enhanced-route-refresh",
	BGP_CAP_ROUTE_REFRESH_CISCO:         "cisco-route-refresh",
	BGP_CAP_LONG_LIVED_GRACEFUL_RESTART: "long-lived-graceful-restart",
	BGP_CAP_FQDN:                        "fqdn",
}

func (c BGPCapabilityCode) String() string {
	if n, y := CapNameMap[c]; y {
		return n
	}
	return fmt.Sprintf("UnknownCapability(%d)", c)
}

var (
	// Used parsing RouteDistinguisher
	_regexpRouteDistinguisher = regexp.MustCompile(`^((\d+)\.(\d+)\.(\d+)\.(\d+)|((\d+)\.)?(\d+)|([\w]+:[\w:]*:[\w]+)):(\d+)$`)

	// Used for operator and value for the FlowSpec numeric type
	// Example:
	// re.FindStringSubmatch("&==80")
	// >>> ["&==80" "&" "==" "80"]
	_regexpFlowSpecNumericType = regexp.MustCompile(`(&?)(==|=|>|>=|<|<=|!|!=|=!)?(\d+|-\d|true|false)`)

	// - "=!" is used in the old style format of "tcp-flags" and "fragment".
	// - The value field should be one of the followings:
	//     * Decimal value (e.g., 80)
	//     * Combination of the small letters, decimals, "-" and "+"
	//       (e.g., tcp, ipv4, is-fragment+first-fragment)
	//     * Capital letters (e.g., SA)
	_regexpFlowSpecOperator      = regexp.MustCompile(`&|=|>|<|!|[\w\-+]+`)
	_regexpFlowSpecOperatorValue = regexp.MustCompile(`[\w\-+]+`)

	// Note: "(-*)" and "(.*)" catch the invalid flags
	// Example: In this case, "Z" is unsupported flag type.
	// re.FindStringSubmatch("&==-SZU")
	// >>> ["&==-SZU" "&" "==" "-" "S" "ZU"]
	_regexpFlowSpecTCPFlag = regexp.MustCompile("(&?)(==|=|!|!=|=!)?(-*)([FSRPAUCE]+)(.*)")

	// Note: "(.*)" catches the invalid flags
	// re.FindStringSubmatch("&!=+first-fragment+last-fragment+invalid-fragment")
	// >>> ["&!=+first-fragment+last-fragment+invalid-fragment" "&" "!=" "+first-fragment+last-fragment" "+last-fragment" "+" "last" "+invalid-fragment"]
	_regexpFlowSpecFragment = regexp.MustCompile(`(&?)(==|=|!|!=|=!)?(((\+)?(dont|is|first|last|not-a)-fragment)+)(.*)`)

	// re.FindStringSubmatch("192.168.0.0/24")
	// >>> ["192.168.0.0/24" "192.168.0.0" "/24" "24"]
	// re.FindStringSubmatch("192.168.0.1")
	// >>> ["192.168.0.1" "192.168.0.1" "" ""]
	_regexpFindIPv4Prefix = regexp.MustCompile(`^([\d.]+)(/(\d{1,2}))?`)

	// re.FindStringSubmatch("2001:dB8::/64")
	// >>> ["2001:dB8::/64" "2001:dB8::" "/64" "64" "" ""]
	// re.FindStringSubmatch("2001:dB8::/64/8")
	// >>> ["2001:dB8::/64/8" "2001:dB8::" "/64" "64" "/8" "8"]
	// re.FindStringSubmatch("2001:dB8::1")
	// >>> ["2001:dB8::1" "2001:dB8::1" "" "" "" ""]
	_regexpFindIPv6Prefix = regexp.MustCompile(`^([a-fA-F\d:.]+)(/(\d{1,3}))?(/(\d{1,3}))?`)
)

type ParameterCapabilityInterface interface {
	DecodeFromBytes([]byte) error
	Serialize() ([]byte, error)
	Len() int
	Code() BGPCapabilityCode
}

type DefaultParameterCapability struct {
	CapCode  BGPCapabilityCode `json:"code"`
	CapLen   uint8             `json:"-"`
	CapValue []byte            `json:"value,omitempty"`
}

func (c *DefaultParameterCapability) Code() BGPCapabilityCode {
	return c.CapCode
}

func (c *DefaultParameterCapability) DecodeFromBytes(data []byte) error {
	c.CapCode = BGPCapabilityCode(data[0])
	c.CapLen = data[1]
	if len(data) < 2+int(c.CapLen) {
		return NewMessageError(BGP_ERROR_OPEN_MESSAGE_ERROR, BGP_ERROR_SUB_UNSUPPORTED_CAPABILITY, nil, "Not all OptionParameterCapability bytes available")
	}
	if c.CapLen > 0 {
		c.CapValue = data[2 : 2+c.CapLen]
	}
	return nil
}

func (c *DefaultParameterCapability) Serialize() ([]byte, error) {
	c.CapLen = uint8(len(c.CapValue))
	buf := make([]byte, 2+len(c.CapValue))
	buf[0] = uint8(c.CapCode)
	buf[1] = c.CapLen
	copy(buf[2:], c.CapValue)
	return buf, nil
}

func (c *DefaultParameterCapability) Len() int {
	return int(c.CapLen + 2)
}

type CapMultiProtocol struct {
	DefaultParameterCapability
	CapValue RouteFamily
}

func (c *CapMultiProtocol) DecodeFromBytes(data []byte) error {
	c.DefaultParameterCapability.DecodeFromBytes(data)
	data = data[2:]
	if len(data) < 4 {
		return NewMessageError(BGP_ERROR_OPEN_MESSAGE_ERROR, BGP_ERROR_SUB_UNSUPPORTED_CAPABILITY, nil, "Not all CapabilityMultiProtocol bytes available")
	}
	c.CapValue = AfiSafiToRouteFamily(binary.BigEndian.Uint16(data[0:2]), data[3])
	return nil
}

func (c *CapMultiProtocol) Serialize() ([]byte, error) {
	buf := make([]byte, 4)
	afi, safi := RouteFamilyToAfiSafi(c.CapValue)
	binary.BigEndian.PutUint16(buf[0:], afi)
	buf[3] = safi
	c.DefaultParameterCapability.CapValue = buf
	return c.DefaultParameterCapability.Serialize()
}

func (c *CapMultiProtocol) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Code  BGPCapabilityCode `json:"code"`
		Value RouteFamily       `json:"value"`
	}{
		Code:  c.Code(),
		Value: c.CapValue,
	})
}

func NewCapMultiProtocol(rf RouteFamily) *CapMultiProtocol {
	return &CapMultiProtocol{
		DefaultParameterCapability{
			CapCode: BGP_CAP_MULTIPROTOCOL,
		},
		rf,
	}
}

type CapRouteRefresh struct {
	DefaultParameterCapability
}

func NewCapRouteRefresh() *CapRouteRefresh {
	return &CapRouteRefresh{
		DefaultParameterCapability{
			CapCode: BGP_CAP_ROUTE_REFRESH,
		},
	}
}

type CapCarryingLabelInfo struct {
	DefaultParameterCapability
}

func NewCapCarryingLabelInfo() *CapCarryingLabelInfo {
	return &CapCarryingLabelInfo{
		DefaultParameterCapability{
			CapCode: BGP_CAP_CARRYING_LABEL_INFO,
		},
	}
}

type CapExtendedNexthopTuple struct {
	NLRIAFI    uint16
	NLRISAFI   uint16
	NexthopAFI uint16
}

func (c *CapExtendedNexthopTuple) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		NLRIAddressFamily    RouteFamily `json:"nlri_address_family"`
		NexthopAddressFamily uint16      `json:"nexthop_address_family"`
	}{
		NLRIAddressFamily:    AfiSafiToRouteFamily(c.NLRIAFI, uint8(c.NLRISAFI)),
		NexthopAddressFamily: c.NexthopAFI,
	})
}

func NewCapExtendedNexthopTuple(af RouteFamily, nexthop uint16) *CapExtendedNexthopTuple {
	afi, safi := RouteFamilyToAfiSafi(af)
	return &CapExtendedNexthopTuple{
		NLRIAFI:    afi,
		NLRISAFI:   uint16(safi),
		NexthopAFI: nexthop,
	}
}

type CapExtendedNexthop struct {
	DefaultParameterCapability
	Tuples []*CapExtendedNexthopTuple
}

func (c *CapExtendedNexthop) DecodeFromBytes(data []byte) error {
	c.DefaultParameterCapability.DecodeFromBytes(data)
	data = data[2:]
	capLen := int(c.CapLen)
	if capLen%6 != 0 || capLen < 6 || len(data) < capLen {
		return NewMessageError(BGP_ERROR_OPEN_MESSAGE_ERROR, BGP_ERROR_SUB_UNSUPPORTED_CAPABILITY, nil, "Not all CapabilityExtendedNexthop bytes available")
	}

	c.Tuples = []*CapExtendedNexthopTuple{}
	for capLen >= 6 {
		t := &CapExtendedNexthopTuple{
			binary.BigEndian.Uint16(data[0:2]),
			binary.BigEndian.Uint16(data[2:4]),
			binary.BigEndian.Uint16(data[4:6]),
		}
		c.Tuples = append(c.Tuples, t)
		data = data[6:]
		capLen -= 6
	}
	return nil
}

func (c *CapExtendedNexthop) Serialize() ([]byte, error) {
	buf := make([]byte, len(c.Tuples)*6)
	for i, t := range c.Tuples {
		binary.BigEndian.PutUint16(buf[i*6:i*6+2], t.NLRIAFI)
		binary.BigEndian.PutUint16(buf[i*6+2:i*6+4], t.NLRISAFI)
		binary.BigEndian.PutUint16(buf[i*6+4:i*6+6], t.NexthopAFI)
	}
	c.DefaultParameterCapability.CapValue = buf
	return c.DefaultParameterCapability.Serialize()
}

func (c *CapExtendedNexthop) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Code   BGPCapabilityCode          `json:"code"`
		Tuples []*CapExtendedNexthopTuple `json:"tuples"`
	}{
		Code:   c.Code(),
		Tuples: c.Tuples,
	})
}

func NewCapExtendedNexthop(tuples []*CapExtendedNexthopTuple) *CapExtendedNexthop {
	return &CapExtendedNexthop{
		DefaultParameterCapability{
			CapCode: BGP_CAP_EXTENDED_NEXTHOP,
		},
		tuples,
	}
}

type CapGracefulRestartTuple struct {
	AFI   uint16
	SAFI  uint8
	Flags uint8
}

func (c *CapGracefulRestartTuple) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		RouteFamily RouteFamily `json:"route_family"`
		Flags       uint8       `json:"flags"`
	}{
		RouteFamily: AfiSafiToRouteFamily(c.AFI, c.SAFI),
		Flags:       c.Flags,
	})
}

func NewCapGracefulRestartTuple(rf RouteFamily, forward bool) *CapGracefulRestartTuple {
	afi, safi := RouteFamilyToAfiSafi(rf)
	flags := 0
	if forward {
		flags = 0x80
	}
	return &CapGracefulRestartTuple{
		AFI:   afi,
		SAFI:  safi,
		Flags: uint8(flags),
	}
}

type CapGracefulRestart struct {
	DefaultParameterCapability
	Flags  uint8
	Time   uint16
	Tuples []*CapGracefulRestartTuple
}

func (c *CapGracefulRestart) DecodeFromBytes(data []byte) error {
	c.DefaultParameterCapability.DecodeFromBytes(data)
	data = data[2:]
	if len(data) < 2 {
		return NewMessageError(BGP_ERROR_OPEN_MESSAGE_ERROR, BGP_ERROR_SUB_UNSUPPORTED_CAPABILITY, nil, "Not all CapabilityGracefulRestart bytes available")
	}
	restart := binary.BigEndian.Uint16(data[0:2])
	c.Flags = uint8(restart >> 12)
	c.Time = restart & 0xfff
	data = data[2:]

	valueLen := int(c.CapLen) - 2

	if valueLen >= 4 && len(data) >= valueLen {
		c.Tuples = make([]*CapGracefulRestartTuple, 0, valueLen/4)

		for i := valueLen; i >= 4; i -= 4 {
			t := &CapGracefulRestartTuple{binary.BigEndian.Uint16(data[0:2]),
				data[2], data[3]}
			c.Tuples = append(c.Tuples, t)
			data = data[4:]
		}
	}
	return nil
}

func (c *CapGracefulRestart) Serialize() ([]byte, error) {
	buf := make([]byte, 2, 2+4*len(c.Tuples))
	binary.BigEndian.PutUint16(buf[0:], uint16(c.Flags)<<12|c.Time)
	var tbuf [4]byte
	for _, t := range c.Tuples {
		binary.BigEndian.PutUint16(tbuf[0:2], t.AFI)
		tbuf[2] = t.SAFI
		tbuf[3] = t.Flags
		buf = append(buf, tbuf[:]...)
	}
	c.DefaultParameterCapability.CapValue = buf
	return c.DefaultParameterCapability.Serialize()
}

func (c *CapGracefulRestart) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Code   BGPCapabilityCode          `json:"code"`
		Flags  uint8                      `json:"flags"`
		Time   uint16                     `json:"time"`
		Tuples []*CapGracefulRestartTuple `json:"tuples"`
	}{
		Code:   c.Code(),
		Flags:  c.Flags,
		Time:   c.Time,
		Tuples: c.Tuples,
	})
}

func NewCapGracefulRestart(restarting, notification bool, time uint16, tuples []*CapGracefulRestartTuple) *CapGracefulRestart {
	flags := 0
	if restarting {
		flags = 0x08
	}
	if notification {
		flags |= 0x04
	}
	return &CapGracefulRestart{
		DefaultParameterCapability: DefaultParameterCapability{
			CapCode: BGP_CAP_GRACEFUL_RESTART,
		},
		Flags:  uint8(flags),
		Time:   time,
		Tuples: tuples,
	}
}

type CapFourOctetASNumber struct {
	DefaultParameterCapability
	CapValue uint32
}

func (c *CapFourOctetASNumber) DecodeFromBytes(data []byte) error {
	c.DefaultParameterCapability.DecodeFromBytes(data)
	data = data[2:]
	if len(data) < 4 {
		return NewMessageError(BGP_ERROR_OPEN_MESSAGE_ERROR, BGP_ERROR_SUB_UNSUPPORTED_CAPABILITY, nil, "Not all CapabilityFourOctetASNumber bytes available")
	}
	c.CapValue = binary.BigEndian.Uint32(data[0:4])
	return nil
}

func (c *CapFourOctetASNumber) Serialize() ([]byte, error) {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, c.CapValue)
	c.DefaultParameterCapability.CapValue = buf
	return c.DefaultParameterCapability.Serialize()
}

func (c *CapFourOctetASNumber) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Code  BGPCapabilityCode `json:"code"`
		Value uint32            `json:"value"`
	}{
		Code:  c.Code(),
		Value: c.CapValue,
	})
}

func NewCapFourOctetASNumber(asnum uint32) *CapFourOctetASNumber {
	return &CapFourOctetASNumber{
		DefaultParameterCapability{
			CapCode: BGP_CAP_FOUR_OCTET_AS_NUMBER,
		},
		asnum,
	}
}

type BGPAddPathMode uint8

const (
	BGP_ADD_PATH_NONE BGPAddPathMode = iota
	BGP_ADD_PATH_RECEIVE
	BGP_ADD_PATH_SEND
	BGP_ADD_PATH_BOTH
)

func (m BGPAddPathMode) String() string {
	switch m {
	case BGP_ADD_PATH_NONE:
		return "none"
	case BGP_ADD_PATH_RECEIVE:
		return "receive"
	case BGP_ADD_PATH_SEND:
		return "send"
	case BGP_ADD_PATH_BOTH:
		return "receive/send"
	default:
		return fmt.Sprintf("unknown(%d)", m)
	}
}

type CapAddPathTuple struct {
	RouteFamily RouteFamily
	Mode        BGPAddPathMode
}

func (t *CapAddPathTuple) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		RouteFamily RouteFamily `json:"family"`
		Mode        uint8       `json:"mode"`
	}{
		RouteFamily: t.RouteFamily,
		Mode:        uint8(t.Mode),
	})
}

func NewCapAddPathTuple(family RouteFamily, mode BGPAddPathMode) *CapAddPathTuple {
	return &CapAddPathTuple{
		RouteFamily: family,
		Mode:        mode,
	}
}

type CapAddPath struct {
	DefaultParameterCapability
	Tuples []*CapAddPathTuple
}

func (c *CapAddPath) DecodeFromBytes(data []byte) error {
	c.DefaultParameterCapability.DecodeFromBytes(data)
	data = data[2:]
	capLen := int(c.CapLen)
	if capLen%4 != 0 || capLen < 4 || len(data) < capLen {
		return NewMessageError(BGP_ERROR_OPEN_MESSAGE_ERROR, BGP_ERROR_SUB_UNSUPPORTED_CAPABILITY, nil, "Not all CapabilityAddPath bytes available")
	}

	c.Tuples = []*CapAddPathTuple{}
	for capLen >= 4 {
		t := &CapAddPathTuple{
			RouteFamily: AfiSafiToRouteFamily(binary.BigEndian.Uint16(data[:2]), data[2]),
			Mode:        BGPAddPathMode(data[3]),
		}
		c.Tuples = append(c.Tuples, t)
		data = data[4:]
		capLen -= 4
	}
	return nil
}

func (c *CapAddPath) Serialize() ([]byte, error) {
	buf := make([]byte, len(c.Tuples)*4)
	for i, t := range c.Tuples {
		afi, safi := RouteFamilyToAfiSafi(t.RouteFamily)
		binary.BigEndian.PutUint16(buf[i*4:i*4+2], afi)
		buf[i*4+2] = safi
		buf[i*4+3] = byte(t.Mode)
	}
	c.DefaultParameterCapability.CapValue = buf
	return c.DefaultParameterCapability.Serialize()
}

func (c *CapAddPath) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Code   BGPCapabilityCode  `json:"code"`
		Tuples []*CapAddPathTuple `json:"tuples"`
	}{
		Code:   c.Code(),
		Tuples: c.Tuples,
	})
}

func NewCapAddPath(tuples []*CapAddPathTuple) *CapAddPath {
	return &CapAddPath{
		DefaultParameterCapability: DefaultParameterCapability{
			CapCode: BGP_CAP_ADD_PATH,
		},
		Tuples: tuples,
	}
}

type CapEnhancedRouteRefresh struct {
	DefaultParameterCapability
}

func NewCapEnhancedRouteRefresh() *CapEnhancedRouteRefresh {
	return &CapEnhancedRouteRefresh{
		DefaultParameterCapability{
			CapCode: BGP_CAP_ENHANCED_ROUTE_REFRESH,
		},
	}
}

type CapRouteRefreshCisco struct {
	DefaultParameterCapability
}

func NewCapRouteRefreshCisco() *CapRouteRefreshCisco {
	return &CapRouteRefreshCisco{
		DefaultParameterCapability{
			CapCode: BGP_CAP_ROUTE_REFRESH_CISCO,
		},
	}
}

type CapLongLivedGracefulRestartTuple struct {
	AFI         uint16
	SAFI        uint8
	Flags       uint8
	RestartTime uint32
}

func (c *CapLongLivedGracefulRestartTuple) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		RouteFamily RouteFamily `json:"route_family"`
		Flags       uint8       `json:"flags"`
		RestartTime uint32      `json:"restart_time"`
	}{
		RouteFamily: AfiSafiToRouteFamily(c.AFI, c.SAFI),
		Flags:       c.Flags,
		RestartTime: c.RestartTime,
	})
}

func NewCapLongLivedGracefulRestartTuple(rf RouteFamily, forward bool, restartTime uint32) *CapLongLivedGracefulRestartTuple {
	afi, safi := RouteFamilyToAfiSafi(rf)
	flags := 0
	if forward {
		flags = 0x80
	}
	return &CapLongLivedGracefulRestartTuple{
		AFI:         afi,
		SAFI:        safi,
		Flags:       uint8(flags),
		RestartTime: restartTime,
	}
}

type CapLongLivedGracefulRestart struct {
	DefaultParameterCapability
	Tuples []*CapLongLivedGracefulRestartTuple
}

func (c *CapLongLivedGracefulRestart) DecodeFromBytes(data []byte) error {
	c.DefaultParameterCapability.DecodeFromBytes(data)
	data = data[2:]

	valueLen := int(c.CapLen)
	if valueLen%7 != 0 || len(data) < valueLen {
		return NewMessageError(BGP_ERROR_OPEN_MESSAGE_ERROR, BGP_ERROR_SUB_UNSUPPORTED_CAPABILITY, nil, "invalid length of long lived graceful restart capablity")
	}
	for i := valueLen; i >= 7; i -= 7 {
		t := &CapLongLivedGracefulRestartTuple{
			binary.BigEndian.Uint16(data),
			data[2],
			data[3],
			uint32(data[4])<<16 | uint32(data[5])<<8 | uint32(data[6]),
		}
		c.Tuples = append(c.Tuples, t)
		data = data[7:]
	}
	return nil
}

func (c *CapLongLivedGracefulRestart) Serialize() ([]byte, error) {
	buf := make([]byte, 7*len(c.Tuples))
	for idx, t := range c.Tuples {
		binary.BigEndian.PutUint16(buf[idx*7:], t.AFI)
		buf[idx*7+2] = t.SAFI
		buf[idx*7+3] = t.Flags
		buf[idx*7+4] = uint8((t.RestartTime >> 16) & 0xff)
		buf[idx*7+5] = uint8((t.RestartTime >> 8) & 0xff)
		buf[idx*7+6] = uint8(t.RestartTime & 0xff)
	}
	c.DefaultParameterCapability.CapValue = buf
	return c.DefaultParameterCapability.Serialize()
}

func (c *CapLongLivedGracefulRestart) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Code   BGPCapabilityCode                   `json:"code"`
		Tuples []*CapLongLivedGracefulRestartTuple `json:"tuples"`
	}{
		Code:   c.Code(),
		Tuples: c.Tuples,
	})
}

func NewCapLongLivedGracefulRestart(tuples []*CapLongLivedGracefulRestartTuple) *CapLongLivedGracefulRestart {
	return &CapLongLivedGracefulRestart{
		DefaultParameterCapability: DefaultParameterCapability{
			CapCode: BGP_CAP_LONG_LIVED_GRACEFUL_RESTART,
		},
		Tuples: tuples,
	}
}

type CapFQDN struct {
	DefaultParameterCapability
	HostNameLen   uint8
	HostName      string
	DomainNameLen uint8
	DomainName    string
}

func (c *CapFQDN) DecodeFromBytes(data []byte) error {
	c.DefaultParameterCapability.DecodeFromBytes(data)
	data = data[2:]
	if len(data) < 2 {
		return NewMessageError(BGP_ERROR_OPEN_MESSAGE_ERROR, BGP_ERROR_SUB_UNSUPPORTED_CAPABILITY, nil, "Not all CapabilityFQDN bytes allowed")
	}
	hostNameLen := uint8(data[0])
	c.HostNameLen = hostNameLen
	c.HostName = string(data[1 : c.HostNameLen+1])
	domainNameLen := uint8(data[c.HostNameLen+1])
	c.DomainNameLen = domainNameLen
	c.DomainName = string(data[c.HostNameLen+2:])
	return nil
}

func (c *CapFQDN) Serialize() ([]byte, error) {
	buf := make([]byte, c.HostNameLen+c.DomainNameLen+2)
	buf[0] = c.HostNameLen
	copy(buf[1:c.HostNameLen+1], c.HostName)
	buf[c.HostNameLen+1] = c.DomainNameLen
	copy(buf[c.HostNameLen+2:], c.DomainName)
	c.DefaultParameterCapability.CapValue = buf
	return c.DefaultParameterCapability.Serialize()
}

func (c *CapFQDN) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		HostNameLen   uint8  `json:"hostname_len"`
		HostName      string `json:"hostname"`
		DomainNameLen uint8  `json:"domainname_len"`
		DomainName    string `json:"domainname"`
	}{
		HostNameLen:   c.HostNameLen,
		HostName:      c.HostName,
		DomainNameLen: c.DomainNameLen,
		DomainName:    c.DomainName,
	})
}

func NewCapFQDN(hostname string, domainname string) *CapFQDN {
	if len(hostname) > 64 {
		hostname = hostname[:64]
	}
	if len(domainname) > 64 {
		domainname = domainname[:64]
	}
	return &CapFQDN{
		DefaultParameterCapability{
			CapCode: BGP_CAP_FQDN,
		},
		uint8(len(hostname)),
		hostname,
		uint8(len(domainname)),
		domainname,
	}
}

type CapUnknown struct {
	DefaultParameterCapability
}

func NewCapUnknown(code BGPCapabilityCode, value []byte) *CapUnknown {
	return &CapUnknown{
		DefaultParameterCapability{
			CapCode:  code,
			CapValue: value,
		},
	}
}

func DecodeCapability(data []byte) (ParameterCapabilityInterface, error) {
	if len(data) < 2 {
		return nil, NewMessageError(BGP_ERROR_OPEN_MESSAGE_ERROR, BGP_ERROR_SUB_UNSUPPORTED_CAPABILITY, nil, "Not all ParameterCapability bytes available")
	}
	var c ParameterCapabilityInterface
	switch BGPCapabilityCode(data[0]) {
	case BGP_CAP_MULTIPROTOCOL:
		c = &CapMultiProtocol{}
	case BGP_CAP_ROUTE_REFRESH:
		c = &CapRouteRefresh{}
	case BGP_CAP_CARRYING_LABEL_INFO:
		c = &CapCarryingLabelInfo{}
	case BGP_CAP_EXTENDED_NEXTHOP:
		c = &CapExtendedNexthop{}
	case BGP_CAP_GRACEFUL_RESTART:
		c = &CapGracefulRestart{}
	case BGP_CAP_FOUR_OCTET_AS_NUMBER:
		c = &CapFourOctetASNumber{}
	case BGP_CAP_ADD_PATH:
		c = &CapAddPath{}
	case BGP_CAP_ENHANCED_ROUTE_REFRESH:
		c = &CapEnhancedRouteRefresh{}
	case BGP_CAP_ROUTE_REFRESH_CISCO:
		c = &CapRouteRefreshCisco{}
	case BGP_CAP_LONG_LIVED_GRACEFUL_RESTART:
		c = &CapLongLivedGracefulRestart{}
	case BGP_CAP_FQDN:
		c = &CapFQDN{}
	default:
		c = &CapUnknown{}
	}
	err := c.DecodeFromBytes(data)
	return c, err
}

type OptionParameterInterface interface {
	Serialize() ([]byte, error)
}

type OptionParameterCapability struct {
	ParamType  uint8
	ParamLen   uint8
	Capability []ParameterCapabilityInterface
}

func (o *OptionParameterCapability) DecodeFromBytes(data []byte) error {
	if uint8(len(data)) < o.ParamLen {
		return NewMessageError(BGP_ERROR_OPEN_MESSAGE_ERROR, BGP_ERROR_SUB_UNSUPPORTED_OPTIONAL_PARAMETER, nil, "Not all OptionParameterCapability bytes available")
	}
	for len(data) >= 2 {
		c, err := DecodeCapability(data)
		if err != nil {
			return err
		}
		o.Capability = append(o.Capability, c)
		if c.Len() == 0 || len(data) < c.Len() {
			return NewMessageError(BGP_ERROR_MESSAGE_HEADER_ERROR, BGP_ERROR_SUB_BAD_MESSAGE_LENGTH, nil, "Bad capability length")
		}
		data = data[c.Len():]
	}
	return nil
}

func (o *OptionParameterCapability) Serialize() ([]byte, error) {
	buf := make([]byte, 2)
	buf[0] = o.ParamType
	for _, p := range o.Capability {
		pbuf, err := p.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, pbuf...)
	}
	o.ParamLen = uint8(len(buf) - 2)
	buf[1] = o.ParamLen
	return buf, nil
}

func NewOptionParameterCapability(capability []ParameterCapabilityInterface) *OptionParameterCapability {
	return &OptionParameterCapability{
		ParamType:  BGP_OPT_CAPABILITY,
		Capability: capability,
	}
}

type OptionParameterUnknown struct {
	ParamType uint8
	ParamLen  uint8
	Value     []byte
}

func (o *OptionParameterUnknown) Serialize() ([]byte, error) {
	buf := make([]byte, 2+len(o.Value))
	buf[0] = o.ParamType
	if o.ParamLen == 0 {
		o.ParamLen = uint8(len(o.Value))
	}
	buf[1] = o.ParamLen
	copy(buf[2:], o.Value)
	return buf, nil
}

type BGPOpen struct {
	Version     uint8
	MyAS        uint16
	HoldTime    uint16
	ID          net.IP
	OptParamLen uint8
	OptParams   []OptionParameterInterface
}

func (msg *BGPOpen) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	if len(data) < 10 {
		return NewMessageError(BGP_ERROR_MESSAGE_HEADER_ERROR, BGP_ERROR_SUB_BAD_MESSAGE_LENGTH, nil, "Not all BGP Open message bytes available")
	}
	msg.Version = data[0]
	msg.MyAS = binary.BigEndian.Uint16(data[1:3])
	msg.HoldTime = binary.BigEndian.Uint16(data[3:5])
	msg.ID = net.IP(data[5:9]).To4()
	msg.OptParamLen = data[9]
	data = data[10:]
	if len(data) < int(msg.OptParamLen) {
		return NewMessageError(BGP_ERROR_MESSAGE_HEADER_ERROR, BGP_ERROR_SUB_BAD_MESSAGE_LENGTH, nil, "Not all BGP Open message bytes available")
	}

	msg.OptParams = []OptionParameterInterface{}
	for rest := msg.OptParamLen; rest > 0; {
		if rest < 2 {
			return NewMessageError(BGP_ERROR_MESSAGE_HEADER_ERROR, BGP_ERROR_SUB_BAD_MESSAGE_LENGTH, nil, "Malformed BGP Open message")
		}
		paramtype := data[0]
		paramlen := data[1]
		if paramlen >= 254 || rest < paramlen+2 {
			return NewMessageError(BGP_ERROR_MESSAGE_HEADER_ERROR, BGP_ERROR_SUB_BAD_MESSAGE_LENGTH, nil, "Malformed BGP Open message")
		}
		rest -= paramlen + 2

		if paramtype == BGP_OPT_CAPABILITY {
			p := &OptionParameterCapability{}
			p.ParamType = paramtype
			p.ParamLen = paramlen
			p.DecodeFromBytes(data[2 : 2+paramlen])
			msg.OptParams = append(msg.OptParams, p)
		} else {
			p := &OptionParameterUnknown{}
			p.ParamType = paramtype
			p.ParamLen = paramlen
			p.Value = data[2 : 2+paramlen]
			msg.OptParams = append(msg.OptParams, p)
		}
		data = data[2+paramlen:]
	}
	return nil
}

func (msg *BGPOpen) Serialize(options ...*MarshallingOption) ([]byte, error) {
	buf := make([]byte, 10)
	buf[0] = msg.Version
	binary.BigEndian.PutUint16(buf[1:3], msg.MyAS)
	binary.BigEndian.PutUint16(buf[3:5], msg.HoldTime)
	copy(buf[5:9], msg.ID.To4())
	pbuf := make([]byte, 0)
	for _, p := range msg.OptParams {
		onepbuf, err := p.Serialize()
		if err != nil {
			return nil, err
		}
		pbuf = append(pbuf, onepbuf...)
	}
	msg.OptParamLen = uint8(len(pbuf))
	buf[9] = msg.OptParamLen
	return append(buf, pbuf...), nil
}

func NewBGPOpenMessage(myas uint16, holdtime uint16, id string, optparams []OptionParameterInterface) *BGPMessage {
	return &BGPMessage{
		Header: BGPHeader{Type: BGP_MSG_OPEN},
		Body:   &BGPOpen{4, myas, holdtime, net.ParseIP(id).To4(), 0, optparams},
	}
}

type AddrPrefixInterface interface {
	DecodeFromBytes([]byte, ...*MarshallingOption) error
	Serialize(...*MarshallingOption) ([]byte, error)
	AFI() uint16
	SAFI() uint8
	Len(...*MarshallingOption) int
	String() string
	MarshalJSON() ([]byte, error)
	// Create a flat map to describe attributes and their
	// values. This can be used to create structured outputs.
	Flat() map[string]string
	PathIdentifier() uint32
	SetPathIdentifier(uint32)
	PathLocalIdentifier() uint32
	SetPathLocalIdentifier(uint32)
}

func LabelString(nlri AddrPrefixInterface) string {
	label := ""
	switch n := nlri.(type) {
	case *LabeledIPAddrPrefix:
		label = n.Labels.String()
	case *LabeledIPv6AddrPrefix:
		label = n.Labels.String()
	case *LabeledVPNIPAddrPrefix:
		label = n.Labels.String()
	case *LabeledVPNIPv6AddrPrefix:
		label = n.Labels.String()
	case *EVPNNLRI:
		switch route := n.RouteTypeData.(type) {
		case *EVPNEthernetAutoDiscoveryRoute:
			label = fmt.Sprintf("[%d]", route.Label)
		case *EVPNMacIPAdvertisementRoute:
			ls := make([]string, len(route.Labels))
			for i, l := range route.Labels {
				ls[i] = strconv.Itoa(int(l))
			}
			label = fmt.Sprintf("[%s]", strings.Join(ls, ","))
		case *EVPNIPPrefixRoute:
			label = fmt.Sprintf("[%d]", route.Label)
		}
	}
	return label
}

type PrefixDefault struct {
	mu      sync.Mutex
	id      uint32
	localId uint32
}

func (p *PrefixDefault) PathIdentifier() uint32 {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.id
}

func (p *PrefixDefault) SetPathIdentifier(id uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.id = id
}

func (p *PrefixDefault) PathLocalIdentifier() uint32 {
	p.mu.Lock()
	defer p.mu.Unlock()

	return p.localId
}

func (p *PrefixDefault) SetPathLocalIdentifier(id uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.localId = id
}

func (p *PrefixDefault) decodePathIdentifier(data []byte) ([]byte, error) {
	if len(data) < 4 {
		code := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
		subcode := uint8(BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST)
		return nil, NewMessageError(code, subcode, nil, "prefix misses path identifier field")
	}
	p.SetPathIdentifier(binary.BigEndian.Uint32(data[:4]))
	return data[4:], nil
}

func (p *PrefixDefault) serializeIdentifier() ([]byte, error) {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, p.PathLocalIdentifier())
	return buf, nil
}

type IPAddrPrefixDefault struct {
	PrefixDefault
	Length uint8
	Prefix net.IP
}

func (r *IPAddrPrefixDefault) decodePrefix(data []byte, bitlen uint8, addrlen uint8) error {
	bytelen := (int(bitlen) + 7) / 8
	if len(data) < bytelen {
		eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
		eSubCode := uint8(BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST)
		return NewMessageError(eCode, eSubCode, nil, "network bytes is short")
	}
	if bitlen > addrlen*8 {
		eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
		eSubCode := uint8(BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST)
		return NewMessageError(eCode, eSubCode, nil, "network bit length is too long")
	}
	b := make([]byte, addrlen)
	copy(b, data[:bytelen])
	// clear trailing bits in the last byte. rfc doesn't require
	// this but some bgp implementations need this...
	rem := bitlen % 8
	if rem != 0 {
		mask := 0xff00 >> rem
		lastByte := b[bytelen-1] & byte(mask)
		b[bytelen-1] = lastByte
	}
	r.Prefix = b
	return nil
}

func (r *IPAddrPrefixDefault) serializePrefix(bitLen uint8) ([]byte, error) {
	byteLen := (int(bitLen) + 7) / 8
	buf := make([]byte, byteLen)
	copy(buf, r.Prefix)
	return buf, nil
}

func (r *IPAddrPrefixDefault) String() string {
	return fmt.Sprintf("%s/%d", r.Prefix.String(), r.Length)
}

func (r *IPAddrPrefixDefault) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Prefix string `json:"prefix"`
	}{
		Prefix: r.String(),
	})
}

type IPAddrPrefix struct {
	IPAddrPrefixDefault
	addrlen uint8
}

func (r *IPAddrPrefix) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	if r.addrlen == 0 {
		r.addrlen = 4
	}
	f := RF_IPv4_UC
	if r.addrlen == 16 {
		f = RF_IPv6_UC
	}
	if IsAddPathEnabled(true, f, options) {
		var err error
		data, err = r.decodePathIdentifier(data)
		if err != nil {
			return err
		}
	}
	if len(data) < 1 {
		eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
		eSubCode := uint8(BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST)
		return NewMessageError(eCode, eSubCode, nil, "prefix misses length field")
	}
	r.Length = data[0]
	return r.decodePrefix(data[1:], r.Length, r.addrlen)
}

func (r *IPAddrPrefix) Serialize(options ...*MarshallingOption) ([]byte, error) {
	f := RF_IPv4_UC
	if r.addrlen == 16 {
		f = RF_IPv6_UC
	}
	var buf []byte
	if IsAddPathEnabled(false, f, options) {
		var err error
		buf, err = r.serializeIdentifier()
		if err != nil {
			return nil, err
		}
	}
	buf = append(buf, r.Length)
	pbuf, err := r.serializePrefix(r.Length)
	if err != nil {
		return nil, err
	}
	return append(buf, pbuf...), nil
}

func (r *IPAddrPrefix) AFI() uint16 {
	return AFI_IP
}

func (r *IPAddrPrefix) SAFI() uint8 {
	return SAFI_UNICAST
}

func (r *IPAddrPrefix) Len(options ...*MarshallingOption) int {
	return 1 + ((int(r.Length) + 7) / 8)
}

func NewIPAddrPrefix(length uint8, prefix string) *IPAddrPrefix {
	p := &IPAddrPrefix{
		IPAddrPrefixDefault{
			Length: length,
		},
		4,
	}
	p.IPAddrPrefixDefault.decodePrefix(net.ParseIP(prefix).To4(), length, 4)
	return p
}

func isIPv4MappedIPv6(ip net.IP) bool {
	return len(ip) == net.IPv6len && ip.To4() != nil
}

type IPv6AddrPrefix struct {
	IPAddrPrefix
}

func (r *IPv6AddrPrefix) AFI() uint16 {
	return AFI_IP6
}

func (r *IPv6AddrPrefix) String() string {
	prefix := r.Prefix.String()
	if isIPv4MappedIPv6(r.Prefix) {
		prefix = "::ffff:" + prefix
	}
	return fmt.Sprintf("%s/%d", prefix, r.Length)
}

func NewIPv6AddrPrefix(length uint8, prefix string) *IPv6AddrPrefix {
	p := &IPv6AddrPrefix{
		IPAddrPrefix{
			IPAddrPrefixDefault{
				Length: length,
			},
			16,
		},
	}
	p.IPAddrPrefixDefault.decodePrefix(net.ParseIP(prefix), length, 16)
	return p
}

const (
	BGP_RD_TWO_OCTET_AS = iota
	BGP_RD_IPV4_ADDRESS
	BGP_RD_FOUR_OCTET_AS
)

type RouteDistinguisherInterface interface {
	DecodeFromBytes([]byte) error
	Serialize() ([]byte, error)
	Len() int
	String() string
	MarshalJSON() ([]byte, error)
}

type DefaultRouteDistinguisher struct {
	Type uint16
}

func (rd *DefaultRouteDistinguisher) serialize(value []byte) ([]byte, error) {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint16(buf, rd.Type)
	copy(buf[2:], value)
	return buf, nil
}

func (rd *DefaultRouteDistinguisher) Len() int {
	return 8
}

type RouteDistinguisherTwoOctetAS struct {
	DefaultRouteDistinguisher
	Admin    uint16
	Assigned uint32
}

func (rd *RouteDistinguisherTwoOctetAS) DecodeFromBytes(data []byte) error {
	rd.Admin = binary.BigEndian.Uint16(data[0:2])
	rd.Assigned = binary.BigEndian.Uint32(data[2:6])
	return nil
}

func (rd *RouteDistinguisherTwoOctetAS) Serialize() ([]byte, error) {
	buf := make([]byte, 6)
	binary.BigEndian.PutUint16(buf[0:2], rd.Admin)
	binary.BigEndian.PutUint32(buf[2:6], rd.Assigned)
	return rd.serialize(buf)
}

func (rd *RouteDistinguisherTwoOctetAS) String() string {
	return fmt.Sprintf("%d:%d", rd.Admin, rd.Assigned)
}

func (rd *RouteDistinguisherTwoOctetAS) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type     uint16 `json:"type"`
		Admin    uint16 `json:"admin"`
		Assigned uint32 `json:"assigned"`
	}{
		Type:     rd.Type,
		Admin:    rd.Admin,
		Assigned: rd.Assigned,
	})
}

func NewRouteDistinguisherTwoOctetAS(admin uint16, assigned uint32) *RouteDistinguisherTwoOctetAS {
	return &RouteDistinguisherTwoOctetAS{
		DefaultRouteDistinguisher: DefaultRouteDistinguisher{
			Type: BGP_RD_TWO_OCTET_AS,
		},
		Admin:    admin,
		Assigned: assigned,
	}
}

type RouteDistinguisherIPAddressAS struct {
	DefaultRouteDistinguisher
	Admin    net.IP
	Assigned uint16
}

func (rd *RouteDistinguisherIPAddressAS) DecodeFromBytes(data []byte) error {
	rd.Admin = data[0:4]
	rd.Assigned = binary.BigEndian.Uint16(data[4:6])
	return nil
}

func (rd *RouteDistinguisherIPAddressAS) Serialize() ([]byte, error) {
	buf := make([]byte, 6)
	copy(buf[0:4], rd.Admin.To4())
	binary.BigEndian.PutUint16(buf[4:6], rd.Assigned)
	return rd.serialize(buf)
}

func (rd *RouteDistinguisherIPAddressAS) String() string {
	return fmt.Sprintf("%s:%d", rd.Admin.String(), rd.Assigned)
}

func (rd *RouteDistinguisherIPAddressAS) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type     uint16 `json:"type"`
		Admin    string `json:"admin"`
		Assigned uint16 `json:"assigned"`
	}{
		Type:     rd.Type,
		Admin:    rd.Admin.String(),
		Assigned: rd.Assigned,
	})
}

func NewRouteDistinguisherIPAddressAS(admin string, assigned uint16) *RouteDistinguisherIPAddressAS {
	return &RouteDistinguisherIPAddressAS{
		DefaultRouteDistinguisher: DefaultRouteDistinguisher{
			Type: BGP_RD_IPV4_ADDRESS,
		},
		Admin:    net.ParseIP(admin).To4(),
		Assigned: assigned,
	}
}

type RouteDistinguisherFourOctetAS struct {
	DefaultRouteDistinguisher
	Admin    uint32
	Assigned uint16
}

func (rd *RouteDistinguisherFourOctetAS) DecodeFromBytes(data []byte) error {
	rd.Admin = binary.BigEndian.Uint32(data[0:4])
	rd.Assigned = binary.BigEndian.Uint16(data[4:6])
	return nil
}

func (rd *RouteDistinguisherFourOctetAS) Serialize() ([]byte, error) {
	buf := make([]byte, 6)
	binary.BigEndian.PutUint32(buf[0:4], rd.Admin)
	binary.BigEndian.PutUint16(buf[4:6], rd.Assigned)
	return rd.serialize(buf)
}

func (rd *RouteDistinguisherFourOctetAS) String() string {
	fst := rd.Admin >> 16 & 0xffff
	snd := rd.Admin & 0xffff
	return fmt.Sprintf("%d.%d:%d", fst, snd, rd.Assigned)
}

func (rd *RouteDistinguisherFourOctetAS) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type     uint16 `json:"type"`
		Admin    uint32 `json:"admin"`
		Assigned uint16 `json:"assigned"`
	}{
		Type:     rd.Type,
		Admin:    rd.Admin,
		Assigned: rd.Assigned,
	})
}

func NewRouteDistinguisherFourOctetAS(admin uint32, assigned uint16) *RouteDistinguisherFourOctetAS {
	return &RouteDistinguisherFourOctetAS{
		DefaultRouteDistinguisher: DefaultRouteDistinguisher{
			Type: BGP_RD_FOUR_OCTET_AS,
		},
		Admin:    admin,
		Assigned: assigned,
	}
}

type RouteDistinguisherUnknown struct {
	DefaultRouteDistinguisher
	Value []byte
}

func (rd *RouteDistinguisherUnknown) DecodeFromBytes(data []byte) error {
	rd.Value = data[0:6]
	return nil
}

func (rd *RouteDistinguisherUnknown) Serialize() ([]byte, error) {
	return rd.DefaultRouteDistinguisher.serialize(rd.Value)
}

func (rd *RouteDistinguisherUnknown) String() string {
	return fmt.Sprintf("%v", rd.Value)
}

func (rd *RouteDistinguisherUnknown) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  uint16 `json:"type"`
		Value []byte `json:"value"`
	}{
		Type:  rd.Type,
		Value: rd.Value,
	})
}

func GetRouteDistinguisher(data []byte) RouteDistinguisherInterface {
	typ := binary.BigEndian.Uint16(data[0:2])
	switch typ {
	case BGP_RD_TWO_OCTET_AS:
		return NewRouteDistinguisherTwoOctetAS(binary.BigEndian.Uint16(data[2:4]), binary.BigEndian.Uint32(data[4:8]))
	case BGP_RD_IPV4_ADDRESS:
		return NewRouteDistinguisherIPAddressAS(net.IP(data[2:6]).String(), binary.BigEndian.Uint16(data[6:8]))
	case BGP_RD_FOUR_OCTET_AS:
		return NewRouteDistinguisherFourOctetAS(binary.BigEndian.Uint32(data[2:6]), binary.BigEndian.Uint16(data[6:8]))
	}
	rd := &RouteDistinguisherUnknown{
		DefaultRouteDistinguisher: DefaultRouteDistinguisher{
			Type: typ,
		},
	}
	return rd
}

func parseRdAndRt(input string) ([]string, error) {
	elems := _regexpRouteDistinguisher.FindStringSubmatch(input)
	if len(elems) != 11 {
		return nil, errors.New("failed to parse")
	}
	return elems, nil
}

func ParseRouteDistinguisher(rd string) (RouteDistinguisherInterface, error) {
	elems, err := parseRdAndRt(rd)
	if err != nil {
		return nil, err
	}
	assigned, _ := strconv.ParseUint(elems[10], 10, 32)
	ip := net.ParseIP(elems[1])
	switch {
	case ip.To4() != nil:
		return NewRouteDistinguisherIPAddressAS(elems[1], uint16(assigned)), nil
	case elems[6] == "" && elems[7] == "":
		asn, _ := strconv.ParseUint(elems[8], 10, 16)
		return NewRouteDistinguisherTwoOctetAS(uint16(asn), uint32(assigned)), nil
	default:
		fst, _ := strconv.ParseUint(elems[7], 10, 16)
		snd, _ := strconv.ParseUint(elems[8], 10, 16)
		asn := fst<<16 | snd
		return NewRouteDistinguisherFourOctetAS(uint32(asn), uint16(assigned)), nil
	}
}

//
// RFC3107 Carrying Label Information in BGP-4
//
// 3. Carrying Label Mapping Information
//
// b) Label:
//
// The Label field carries one or more labels (that corresponds to
// the stack of labels [MPLS-ENCAPS(RFC3032)]). Each label is encoded as
// 4 octets, where the high-order 20 bits contain the label value, and
// the low order bit contains "Bottom of Stack"
//
// RFC3032 MPLS Label Stack Encoding
//
// 2.1. Encoding the Label Stack
//
//  0       1       2               3
//  0 ... 9 0 ... 9 0 1 2 3 4 ... 9 0 1
// +-----+-+-+---+-+-+-+-+-+-----+-+-+-+
// |     Label     | Exp |S|    TTL    |
// +-----+-+-+---+-+-+-+-+-+-----+-+-+-+
//

// RFC3107 Carrying Label Information in BGP-4
//
// 3. Carrying Label Mapping Information
//
// The label information carried (as part of NLRI) in the Withdrawn
// Routes field should be set to 0x800000.
const WITHDRAW_LABEL = uint32(0x800000)
const ZERO_LABEL = uint32(0) // some platform uses this as withdraw label

type MPLSLabelStack struct {
	Labels []uint32
}

func (l *MPLSLabelStack) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	labels := []uint32{}
	foundBottom := false
	bottomExpected := true
	if IsAttributePresent(BGP_ATTR_TYPE_PREFIX_SID, options) {
		// If Update carries Prefix SID attribute then one should not rely on BoS for the label stack processing,
		// the first and only label carries transposed variable part of the SRv6 SID.
		bottomExpected = false
	}
	for len(data) >= 3 {
		label := uint32(data[0])<<16 | uint32(data[1])<<8 | uint32(data[2])
		if label == WITHDRAW_LABEL || label == ZERO_LABEL {
			l.Labels = []uint32{label}
			return nil
		}
		data = data[3:]
		labels = append(labels, label>>4)
		if !bottomExpected {
			// Faking found bottom.
			foundBottom = true
			break
		}
		if label&1 == 1 {
			foundBottom = true
			break
		}
	}

	if !foundBottom {
		l.Labels = []uint32{}
		return nil
	}
	l.Labels = labels
	return nil
}

func (l *MPLSLabelStack) Serialize(options ...*MarshallingOption) ([]byte, error) {
	buf := make([]byte, len(l.Labels)*3)
	for i, label := range l.Labels {
		if label == WITHDRAW_LABEL {
			return []byte{128, 0, 0}, nil
		}
		label = label << 4
		buf[i*3] = byte((label >> 16) & 0xff)
		buf[i*3+1] = byte((label >> 8) & 0xff)
		buf[i*3+2] = byte(label & 0xff)
	}
	buf[len(buf)-1] |= 1
	return buf, nil
}

func (l *MPLSLabelStack) Len() int { return 3 * len(l.Labels) }

func (l *MPLSLabelStack) String() string {
	if len(l.Labels) == 0 {
		return ""
	}
	s := bytes.NewBuffer(make([]byte, 0, 64))
	s.WriteString("[")
	ss := make([]string, 0, len(l.Labels))
	for _, label := range l.Labels {
		ss = append(ss, fmt.Sprintf("%d", label))
	}
	s.WriteString(strings.Join(ss, ", "))
	s.WriteString("]")
	return s.String()
}

func NewMPLSLabelStack(labels ...uint32) *MPLSLabelStack {
	if len(labels) == 0 {
		labels = []uint32{0}
	}
	return &MPLSLabelStack{labels}
}

func ParseMPLSLabelStack(buf string) (*MPLSLabelStack, error) {
	elems := strings.Split(buf, "/")
	labels := make([]uint32, 0, len(elems))
	if len(elems) == 0 {
		goto ERR
	}
	for _, elem := range elems {
		i, err := strconv.ParseUint(elem, 10, 32)
		if err != nil {
			goto ERR
		}
		if i > ((1 << 20) - 1) {
			goto ERR
		}
		labels = append(labels, uint32(i))
	}
	return NewMPLSLabelStack(labels...), nil
ERR:
	return nil, NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "invalid mpls label stack format")
}

//
// RFC3107 Carrying Label Information in BGP-4
//
// 3. Carrying Label Mapping Information
//
// +----------------------+
// |   Length (1 octet)   |
// +----------------------+
// |   Label (3 octets)   |
// +----------------------+
// .......................
// +----------------------+
// |   Prefix (variable)  |
// +----------------------+
//
// RFC4364 BGP/MPLS IP VPNs
//
// 4.3.4. How VPN-IPv4 NLRI Is Carried in BGP
//
// The labeled VPN-IPv4 NLRI itself is encoded as specified in
// [MPLS-BGP(RFC3107)], where the prefix consists of an 8-byte RD
// followed by an IPv4 prefix.
//

type LabeledVPNIPAddrPrefix struct {
	IPAddrPrefixDefault
	Labels  MPLSLabelStack
	RD      RouteDistinguisherInterface
	addrlen uint8
}

func (l *LabeledVPNIPAddrPrefix) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	f := RF_IPv4_VPN
	if l.addrlen == 16 {
		f = RF_IPv6_VPN
	}
	if IsAddPathEnabled(true, f, options) {
		var err error
		data, err = l.decodePathIdentifier(data)
		if err != nil {
			return err
		}
	}
	if len(data) < 1 {
		return NewMessageError(uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR), uint8(BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST), nil, "prefix misses length field")
	}
	l.Length = uint8(data[0])
	data = data[1:]
	l.Labels.DecodeFromBytes(data, options...)
	if int(l.Length)-8*(l.Labels.Len()) < 0 {
		l.Labels.Labels = []uint32{}
	}
	data = data[l.Labels.Len():]
	l.RD = GetRouteDistinguisher(data)
	rdLen := l.RD.Len()
	if len(data) < rdLen {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "bad labeled VPN-IPv4 NLRI length")
	}
	data = data[l.RD.Len():]
	restbits := int(l.Length) - 8*(l.Labels.Len()+l.RD.Len())
	return l.decodePrefix(data, uint8(restbits), l.addrlen)
}

func (l *LabeledVPNIPAddrPrefix) Serialize(options ...*MarshallingOption) ([]byte, error) {
	f := RF_IPv4_VPN
	if l.addrlen == 16 {
		f = RF_IPv6_VPN
	}
	var buf []byte
	if IsAddPathEnabled(false, f, options) {
		var err error
		buf, err = l.serializeIdentifier()
		if err != nil {
			return nil, err
		}
	}
	buf = append(buf, l.Length)
	lbuf, err := l.Labels.Serialize(options...)
	if err != nil {
		return nil, err
	}
	buf = append(buf, lbuf...)
	rbuf, err := l.RD.Serialize()
	if err != nil {
		return nil, err
	}
	buf = append(buf, rbuf...)
	restbits := int(l.Length) - 8*(l.Labels.Len()+l.RD.Len())
	pbuf, err := l.serializePrefix(uint8(restbits))
	if err != nil {
		return nil, err
	}
	buf = append(buf, pbuf...)
	return buf, nil
}

func (l *LabeledVPNIPAddrPrefix) AFI() uint16 {
	return AFI_IP
}

func (l *LabeledVPNIPAddrPrefix) SAFI() uint8 {
	return SAFI_MPLS_VPN
}

func (l *LabeledVPNIPAddrPrefix) IPPrefixLen() uint8 {
	return l.Length - 8*uint8(l.Labels.Len()+l.RD.Len())
}

func (l *LabeledVPNIPAddrPrefix) Len(options ...*MarshallingOption) int {
	return 1 + l.Labels.Len() + l.RD.Len() + int((l.IPPrefixLen()+7)/8)
}

func (l *LabeledVPNIPAddrPrefix) String() string {
	return fmt.Sprintf("%s:%s", l.RD, l.IPPrefix())
}

func (l *LabeledVPNIPAddrPrefix) IPPrefix() string {
	masklen := l.IPAddrPrefixDefault.Length - uint8(8*(l.Labels.Len()+l.RD.Len()))
	return fmt.Sprintf("%s/%d", l.IPAddrPrefixDefault.Prefix, masklen)
}

func (l *LabeledVPNIPAddrPrefix) MarshalJSON() ([]byte, error) {
	masklen := l.IPAddrPrefixDefault.Length - uint8(8*(l.Labels.Len()+l.RD.Len()))
	return json.Marshal(struct {
		Prefix string                      `json:"prefix"`
		Labels []uint32                    `json:"labels"`
		RD     RouteDistinguisherInterface `json:"rd"`
	}{
		Prefix: fmt.Sprintf("%s/%d", l.IPAddrPrefixDefault.Prefix, masklen),
		Labels: l.Labels.Labels,
		RD:     l.RD,
	})
}

func NewLabeledVPNIPAddrPrefix(length uint8, prefix string, label MPLSLabelStack, rd RouteDistinguisherInterface) *LabeledVPNIPAddrPrefix {
	rdlen := 0
	if rd != nil {
		rdlen = rd.Len()
	}
	return &LabeledVPNIPAddrPrefix{
		IPAddrPrefixDefault{
			Length: length + uint8(8*(label.Len()+rdlen)),
			Prefix: net.ParseIP(prefix).To4(),
		},
		label,
		rd,
		4,
	}
}

type LabeledVPNIPv6AddrPrefix struct {
	LabeledVPNIPAddrPrefix
}

func (l *LabeledVPNIPv6AddrPrefix) AFI() uint16 {
	return AFI_IP6
}

func NewLabeledVPNIPv6AddrPrefix(length uint8, prefix string, label MPLSLabelStack, rd RouteDistinguisherInterface) *LabeledVPNIPv6AddrPrefix {
	rdlen := 0
	if rd != nil {
		rdlen = rd.Len()
	}
	return &LabeledVPNIPv6AddrPrefix{
		LabeledVPNIPAddrPrefix{
			IPAddrPrefixDefault{
				Length: length + uint8(8*(label.Len()+rdlen)),
				Prefix: net.ParseIP(prefix),
			},
			label,
			rd,
			16,
		},
	}
}

type LabeledIPAddrPrefix struct {
	IPAddrPrefixDefault
	Labels  MPLSLabelStack
	addrlen uint8
}

func (r *LabeledIPAddrPrefix) AFI() uint16 {
	return AFI_IP
}

func (r *LabeledIPAddrPrefix) SAFI() uint8 {
	return SAFI_MPLS_LABEL
}

func (l *LabeledIPAddrPrefix) IPPrefixLen() uint8 {
	return l.Length - 8*uint8(l.Labels.Len())
}

func (l *LabeledIPAddrPrefix) Len(options ...*MarshallingOption) int {
	return 1 + l.Labels.Len() + int((l.IPPrefixLen()+7)/8)
}

func (l *LabeledIPAddrPrefix) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	f := RF_IPv4_MPLS
	if l.addrlen == 16 {
		f = RF_IPv6_MPLS
	}
	if IsAddPathEnabled(true, f, options) {
		var err error
		data, err = l.decodePathIdentifier(data)
		if err != nil {
			return err
		}
	}
	l.Length = uint8(data[0])
	data = data[1:]
	l.Labels.DecodeFromBytes(data)

	if int(l.Length)-8*(l.Labels.Len()) < 0 {
		l.Labels.Labels = []uint32{}
	}
	restbits := int(l.Length) - 8*(l.Labels.Len())
	data = data[l.Labels.Len():]
	return l.decodePrefix(data, uint8(restbits), l.addrlen)
}

func (l *LabeledIPAddrPrefix) Serialize(options ...*MarshallingOption) ([]byte, error) {
	f := RF_IPv4_MPLS
	if l.addrlen == 16 {
		f = RF_IPv6_MPLS
	}
	var buf []byte
	if IsAddPathEnabled(false, f, options) {
		var err error
		buf, err = l.serializeIdentifier()
		if err != nil {
			return nil, err
		}
	}
	buf = append(buf, l.Length)
	restbits := int(l.Length) - 8*(l.Labels.Len())
	lbuf, err := l.Labels.Serialize()
	if err != nil {
		return nil, err
	}
	buf = append(buf, lbuf...)
	pbuf, err := l.serializePrefix(uint8(restbits))
	if err != nil {
		return nil, err
	}
	buf = append(buf, pbuf...)
	return buf, nil
}

func (l *LabeledIPAddrPrefix) String() string {
	prefix := l.Prefix.String()
	if isIPv4MappedIPv6(l.Prefix) {
		prefix = "::ffff:" + prefix
	}
	return fmt.Sprintf("%s/%d", prefix, int(l.Length)-l.Labels.Len()*8)
}

func (l *LabeledIPAddrPrefix) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Prefix string   `json:"prefix"`
		Labels []uint32 `json:"labels"`
	}{
		Prefix: l.String(),
		Labels: l.Labels.Labels,
	})
}

func NewLabeledIPAddrPrefix(length uint8, prefix string, label MPLSLabelStack) *LabeledIPAddrPrefix {
	return &LabeledIPAddrPrefix{
		IPAddrPrefixDefault{
			Length: length + uint8(label.Len()*8),
			Prefix: net.ParseIP(prefix).To4(),
		},
		label,
		4,
	}
}

type LabeledIPv6AddrPrefix struct {
	LabeledIPAddrPrefix
}

func (l *LabeledIPv6AddrPrefix) AFI() uint16 {
	return AFI_IP6
}

func NewLabeledIPv6AddrPrefix(length uint8, prefix string, label MPLSLabelStack) *LabeledIPv6AddrPrefix {
	return &LabeledIPv6AddrPrefix{
		LabeledIPAddrPrefix{
			IPAddrPrefixDefault{
				Length: length + uint8(label.Len()*8),
				Prefix: net.ParseIP(prefix),
			},
			label,
			16,
		},
	}
}

type RouteTargetMembershipNLRI struct {
	PrefixDefault
	Length      uint8
	AS          uint32
	RouteTarget ExtendedCommunityInterface
}

func (n *RouteTargetMembershipNLRI) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	if IsAddPathEnabled(true, RF_RTC_UC, options) {
		var err error
		data, err = n.decodePathIdentifier(data)
		if err != nil {
			return err
		}
	}
	if len(data) < 1 {
		return NewMessageError(uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR), uint8(BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST), nil, "prefix misses length field")
	}
	n.Length = data[0]
	data = data[1 : n.Length/8+1]
	if len(data) == 0 {
		return nil
	} else if len(data) != 12 {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "Not all RouteTargetMembershipNLRI bytes available")
	}
	n.AS = binary.BigEndian.Uint32(data[0:4])
	rt, err := ParseExtended(data[4:])
	n.RouteTarget = rt
	if err != nil {
		return err
	}
	return nil
}

func (n *RouteTargetMembershipNLRI) Serialize(options ...*MarshallingOption) ([]byte, error) {
	var buf []byte
	if IsAddPathEnabled(false, RF_RTC_UC, options) {
		var err error
		buf, err = n.serializeIdentifier()
		if err != nil {
			return nil, err
		}
	}
	if n.RouteTarget == nil {
		return append(buf, 0), nil
	}
	offset := len(buf)
	buf = append(buf, make([]byte, 5)...)
	buf[offset] = 96
	binary.BigEndian.PutUint32(buf[offset+1:], n.AS)
	ebuf, err := n.RouteTarget.Serialize()
	if err != nil {
		return nil, err
	}
	return append(buf, ebuf...), nil
}

func (n *RouteTargetMembershipNLRI) AFI() uint16 {
	return AFI_IP
}

func (n *RouteTargetMembershipNLRI) SAFI() uint8 {
	return SAFI_ROUTE_TARGET_CONSTRAINTS
}

func (n *RouteTargetMembershipNLRI) Len(options ...*MarshallingOption) int {
	if n.AS == 0 && n.RouteTarget == nil {
		return 1
	}
	return 13
}

func (n *RouteTargetMembershipNLRI) String() string {
	target := "default"
	if n.RouteTarget != nil {
		target = n.RouteTarget.String()
	}
	return fmt.Sprintf("%d:%s", n.AS, target)
}

func (n *RouteTargetMembershipNLRI) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Prefix string `json:"prefix"`
	}{
		Prefix: n.String(),
	})
}

func NewRouteTargetMembershipNLRI(as uint32, target ExtendedCommunityInterface) *RouteTargetMembershipNLRI {
	l := 12 * 8
	if as == 0 && target == nil {
		l = 1
	}
	return &RouteTargetMembershipNLRI{
		Length:      uint8(l),
		AS:          as,
		RouteTarget: target,
	}
}

//go:generate stringer -type=ESIType
type ESIType uint8

const (
	ESI_ARBITRARY ESIType = iota
	ESI_LACP
	ESI_MSTP
	ESI_MAC
	ESI_ROUTERID
	ESI_AS
)

type EthernetSegmentIdentifier struct {
	Type  ESIType
	Value []byte
}

func (esi *EthernetSegmentIdentifier) DecodeFromBytes(data []byte) error {
	if len(data) < 10 {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, fmt.Sprintf("invalid %s length", esi.Type.String()))
	}
	esi.Type = ESIType(data[0])
	esi.Value = data[1:10]
	switch esi.Type {
	case ESI_LACP, ESI_MSTP, ESI_ROUTERID, ESI_AS:
		if esi.Value[8] != 0x00 {
			return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, fmt.Sprintf("invalid %s. last octet must be 0x00 (0x%02x)", esi.Type.String(), esi.Value[8]))
		}
	}
	return nil
}

func (esi *EthernetSegmentIdentifier) Serialize() ([]byte, error) {
	buf := make([]byte, 10)
	buf[0] = uint8(esi.Type)
	copy(buf[1:], esi.Value)
	return buf, nil
}

func isZeroBuf(buf []byte) bool {
	for _, b := range buf {
		if b != 0 {
			return false
		}
	}
	return true
}

func (esi *EthernetSegmentIdentifier) String() string {
	toHexArray := func(data []byte) string {
		// Converts byte slice into the colon separated hex values and the
		// number of elements are 9 at most (excluding Type field).
		values := make([]string, 0, 9)
		for _, v := range data {
			values = append(values, fmt.Sprintf("%02x", v))
		}
		return strings.Join(values, ":")
	}

	s := bytes.NewBuffer(make([]byte, 0, 64))
	s.WriteString(fmt.Sprintf("%s | ", esi.Type.String()))
	switch esi.Type {
	case ESI_LACP:
		s.WriteString(fmt.Sprintf("system mac %s, ", net.HardwareAddr(esi.Value[:6]).String()))
		s.WriteString(fmt.Sprintf("port key %d", binary.BigEndian.Uint16(esi.Value[6:8])))
	case ESI_MSTP:
		s.WriteString(fmt.Sprintf("bridge mac %s, ", net.HardwareAddr(esi.Value[:6]).String()))
		s.WriteString(fmt.Sprintf("priority %d", binary.BigEndian.Uint16(esi.Value[6:8])))
	case ESI_MAC:
		s.WriteString(fmt.Sprintf("system mac %s, ", net.HardwareAddr(esi.Value[:6]).String()))
		s.WriteString(fmt.Sprintf("local discriminator %d", uint32(esi.Value[6])<<16|uint32(esi.Value[7])<<8|uint32(esi.Value[8])))
	case ESI_ROUTERID:
		s.WriteString(fmt.Sprintf("router id %s, ", net.IP(esi.Value[:4])))
		s.WriteString(fmt.Sprintf("local discriminator %d", binary.BigEndian.Uint32(esi.Value[4:8])))
	case ESI_AS:
		s.WriteString(fmt.Sprintf("as %d, ", binary.BigEndian.Uint32(esi.Value[:4])))
		s.WriteString(fmt.Sprintf("local discriminator %d", binary.BigEndian.Uint32(esi.Value[4:8])))
	case ESI_ARBITRARY:
		if isZeroBuf(esi.Value) {
			return "single-homed"
		}
		fallthrough
	default:
		s.WriteString(toHexArray(esi.Value))
	}
	return s.String()
}

// Decode Ethernet Segment Identifier (ESI) from string slice.
//
// The first element of args should be the Type field (e.g., "ARBITRARY",
// "arbitrary", "ESI_ARBITRARY" or "esi_arbitrary") and "single-homed" is
// the special keyword for all zeroed ESI.
// For the "ARBITRARY" Value field (Type 0), it should be the colon separated
// hex values and the number of elements should be 9 at most.
//
//	e.g.) args := []string{"ARBITRARY", "11:22:33:44:55:66:77:88:99"}
//
// For the other types, the Value field format is the similar to the string
// format of ESI.
//
//	e.g.) args := []string{"lacp", "aa:bb:cc:dd:ee:ff", "100"}
func ParseEthernetSegmentIdentifier(args []string) (EthernetSegmentIdentifier, error) {
	esi := EthernetSegmentIdentifier{}
	argLen := len(args)
	if argLen == 0 || args[0] == "single-homed" {
		return esi, nil
	}

	typeStr := strings.TrimPrefix(strings.ToUpper(args[0]), "ESI_")
	switch typeStr {
	case "ARBITRARY":
		esi.Type = ESI_ARBITRARY
	case "LACP":
		esi.Type = ESI_LACP
	case "MSTP":
		esi.Type = ESI_MSTP
	case "MAC":
		esi.Type = ESI_MAC
	case "ROUTERID":
		esi.Type = ESI_ROUTERID
	case "AS":
		esi.Type = ESI_AS
	default:
		typ, err := strconv.ParseUint(args[0], 10, 8)
		if err != nil {
			return esi, fmt.Errorf("invalid esi type: %s", args[0])
		}
		esi.Type = ESIType(typ)
	}

	invalidEsiValuesError := fmt.Errorf("invalid esi values for type %s: %s", esi.Type.String(), args[1:])
	esi.Value = make([]byte, 9)
	switch esi.Type {
	case ESI_LACP:
		fallthrough
	case ESI_MSTP:
		if argLen < 3 {
			return esi, invalidEsiValuesError
		}
		// MAC
		mac, err := net.ParseMAC(args[1])
		if err != nil {
			return esi, invalidEsiValuesError
		}
		copy(esi.Value[0:6], mac)
		// Port Key or Bridge Priority
		i, err := strconv.ParseUint(args[2], 10, 16)
		if err != nil {
			return esi, invalidEsiValuesError
		}
		binary.BigEndian.PutUint16(esi.Value[6:8], uint16(i))
	case ESI_MAC:
		if argLen < 3 {
			return esi, invalidEsiValuesError
		}
		// MAC
		mac, err := net.ParseMAC(args[1])
		if err != nil {
			return esi, invalidEsiValuesError
		}
		copy(esi.Value[0:6], mac)
		// Local Discriminator
		i, err := strconv.ParseUint(args[2], 10, 32)
		if err != nil {
			return esi, invalidEsiValuesError
		}
		iBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(iBuf, uint32(i))
		copy(esi.Value[6:9], iBuf[1:4])
	case ESI_ROUTERID:
		if argLen < 3 {
			return esi, invalidEsiValuesError
		}
		// Router ID
		ip := net.ParseIP(args[1])
		if ip == nil || ip.To4() == nil {
			return esi, invalidEsiValuesError
		}
		copy(esi.Value[0:4], ip.To4())
		// Local Discriminator
		i, err := strconv.ParseUint(args[2], 10, 32)
		if err != nil {
			return esi, invalidEsiValuesError
		}
		binary.BigEndian.PutUint32(esi.Value[4:8], uint32(i))
	case ESI_AS:
		if argLen < 3 {
			return esi, invalidEsiValuesError
		}
		// AS
		as, err := strconv.ParseUint(args[1], 10, 32)
		if err != nil {
			return esi, invalidEsiValuesError
		}
		binary.BigEndian.PutUint32(esi.Value[0:4], uint32(as))
		// Local Discriminator
		i, err := strconv.ParseUint(args[2], 10, 32)
		if err != nil {
			return esi, invalidEsiValuesError
		}
		binary.BigEndian.PutUint32(esi.Value[4:8], uint32(i))
	case ESI_ARBITRARY:
		fallthrough
	default:
		if argLen < 2 {
			// Assumes the Value field is omitted
			break
		}
		values := make([]byte, 0, 9)
		for _, e := range strings.SplitN(args[1], ":", 9) {
			v, err := strconv.ParseUint(e, 16, 16)
			if err != nil {
				return esi, invalidEsiValuesError
			}
			values = append(values, byte(v))
		}
		copy(esi.Value, values)
	}

	return esi, nil
}

//
// I-D bess-evpn-overlay-01
//
// 5.1.3 Constructing EVPN BGP Routes
//
// For the balance of this memo, the MPLS label field will be
// referred to as the VNI/VSID field. The VNI/VSID field is used for
// both local and global VNIs/VSIDs, and for either case the entire 24-
// bit field is used to encode the VNI/VSID value.
//
// We can't use type MPLSLabelStack for EVPN NLRI, because EVPN NLRI's MPLS
// field can be filled with VXLAN VNI. In that case, we must avoid modifying
// bottom of stack bit.
//

func labelDecode(data []byte) (uint32, error) {
	if len(data) < 3 {
		return 0, NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "Not all Label bytes available")
	}
	return uint32(data[0])<<16 | uint32(data[1])<<8 | uint32(data[2]), nil
}

func labelSerialize(label uint32) ([]byte, error) {
	if label > 0xffffff {
		return nil, NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, fmt.Sprintf("Out of range Label: %d", label))
	}
	buf := make([]byte, 3)
	buf[0] = byte((label >> 16) & 0xff)
	buf[1] = byte((label >> 8) & 0xff)
	buf[2] = byte(label & 0xff)
	return buf, nil
}

type EVPNEthernetAutoDiscoveryRoute struct {
	RD    RouteDistinguisherInterface
	ESI   EthernetSegmentIdentifier
	ETag  uint32
	Label uint32
}

func (er *EVPNEthernetAutoDiscoveryRoute) Len() int {
	// RD(8) + ESI(10) + ETag(4) + Label(3)
	return 25
}

func (er *EVPNEthernetAutoDiscoveryRoute) DecodeFromBytes(data []byte) error {
	er.RD = GetRouteDistinguisher(data)
	rdLen := er.RD.Len()
	if len(data) < rdLen+14 { // 14 is 10 for
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "bad Ethernet Auto-discovery Route length")
	}
	data = data[er.RD.Len():]
	err := er.ESI.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	data = data[10:]
	er.ETag = binary.BigEndian.Uint32(data[0:4])
	data = data[4:]
	if er.Label, err = labelDecode(data); err != nil {
		return err
	}
	return nil
}

func (er *EVPNEthernetAutoDiscoveryRoute) Serialize() ([]byte, error) {
	var buf []byte
	var err error
	if er.RD != nil {
		buf, err = er.RD.Serialize()
		if err != nil {
			return nil, err
		}
	} else {
		buf = make([]byte, 8)
	}
	tbuf, err := er.ESI.Serialize()
	if err != nil {
		return nil, err
	}
	buf = append(buf, tbuf...)

	var tagBuf [4]byte
	binary.BigEndian.PutUint32(tagBuf[:4], er.ETag)
	buf = append(buf, tagBuf[:4]...)

	tbuf, err = labelSerialize(er.Label)
	if err != nil {
		return nil, err
	}
	buf = append(buf, tbuf...)

	return buf, nil
}

func (er *EVPNEthernetAutoDiscoveryRoute) String() string {
	// RFC7432: BGP MPLS-Based Ethernet VPN
	// 7.1. Ethernet Auto-discovery Route
	// For the purpose of BGP route key processing, only the Ethernet
	// Segment Identifier and the Ethernet Tag ID are considered to be part
	// of the prefix in the NLRI.  The MPLS Label field is to be treated as
	// a route attribute as opposed to being part of the route.
	return fmt.Sprintf("[type:A-D][rd:%s][esi:%s][etag:%d]", er.RD, er.ESI.String(), er.ETag)
}

func (er *EVPNEthernetAutoDiscoveryRoute) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		RD    RouteDistinguisherInterface `json:"rd"`
		ESI   string                      `json:"esi"`
		Etag  uint32                      `json:"etag"`
		Label uint32                      `json:"label"`
	}{
		RD:    er.RD,
		ESI:   er.ESI.String(),
		Etag:  er.ETag,
		Label: er.Label,
	})
}

func (er *EVPNEthernetAutoDiscoveryRoute) rd() RouteDistinguisherInterface {
	return er.RD
}

func NewEVPNEthernetAutoDiscoveryRoute(rd RouteDistinguisherInterface, esi EthernetSegmentIdentifier, etag uint32, label uint32) *EVPNNLRI {
	return NewEVPNNLRI(EVPN_ROUTE_TYPE_ETHERNET_AUTO_DISCOVERY, &EVPNEthernetAutoDiscoveryRoute{
		RD:    rd,
		ESI:   esi,
		ETag:  etag,
		Label: label,
	})
}

type EVPNMacIPAdvertisementRoute struct {
	RD               RouteDistinguisherInterface
	ESI              EthernetSegmentIdentifier
	ETag             uint32
	MacAddressLength uint8
	MacAddress       net.HardwareAddr
	IPAddressLength  uint8
	IPAddress        net.IP
	Labels           []uint32
}

func (er *EVPNMacIPAdvertisementRoute) Len() int {
	// RD(8) + ESI(10) + ETag(4) + MacAddressLength(1) + MacAddress(6)
	// + IPAddressLength(1) + IPAddress(0, 4 or 16) + Labels(3 or 6)
	return 30 + int(er.IPAddressLength)/8 + len(er.Labels)*3
}

func (er *EVPNMacIPAdvertisementRoute) DecodeFromBytes(data []byte) error {
	er.RD = GetRouteDistinguisher(data)
	rdLen := er.RD.Len()
	if len(data) < rdLen {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "bad length of MAC/IP Advertisement Route")
	}
	data = data[er.RD.Len():]
	err := er.ESI.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	data = data[10:]
	er.ETag = binary.BigEndian.Uint32(data[0:4])
	data = data[4:]
	er.MacAddressLength = data[0]
	er.MacAddress = net.HardwareAddr(data[1:7])
	er.IPAddressLength = data[7]
	data = data[8:]
	if er.IPAddressLength == 32 || er.IPAddressLength == 128 {
		er.IPAddress = net.IP(data[0:((er.IPAddressLength) / 8)])
	} else if er.IPAddressLength != 0 {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, fmt.Sprintf("Invalid IP address length: %d", er.IPAddressLength))
	}
	data = data[(er.IPAddressLength / 8):]
	var label uint32
	if label, err = labelDecode(data); err != nil {
		return err
	}
	er.Labels = append(er.Labels, label)
	data = data[3:]
	if len(data) == 3 {
		if label, err = labelDecode(data); err != nil {
			return err
		}
		er.Labels = append(er.Labels, label)
	}
	return nil
}

func (er *EVPNMacIPAdvertisementRoute) Serialize() ([]byte, error) {
	var buf []byte
	var err error
	if er.RD != nil {
		buf, err = er.RD.Serialize()
		if err != nil {
			return nil, err
		}
	} else {
		buf = make([]byte, 8)
	}

	esi, err := er.ESI.Serialize()
	if err != nil {
		return nil, err
	}

	buf = append(buf, esi...)
	var tbuf [7]byte
	binary.BigEndian.PutUint32(tbuf[:4], er.ETag)
	buf = append(buf, tbuf[:4]...)
	tbuf[0] = er.MacAddressLength
	copy(tbuf[1:], er.MacAddress)
	buf = append(buf, tbuf[:7]...)

	buf = append(buf, er.IPAddressLength)
	switch er.IPAddressLength {
	case 0:
		// IP address omitted
	case 32:
		buf = append(buf, []byte(er.IPAddress.To4())...)
	case 128:
		buf = append(buf, []byte(er.IPAddress.To16())...)
	default:
		return nil, fmt.Errorf("invalid IP address length: %d", er.IPAddressLength)
	}

	for _, l := range er.Labels {
		label, err := labelSerialize(l)
		if err != nil {
			return nil, err
		}
		buf = append(buf, label...)
	}
	return buf, nil
}

func (er *EVPNMacIPAdvertisementRoute) String() string {
	// RFC7432: BGP MPLS-Based Ethernet VPN
	// 7.2. MAC/IP Advertisement Route
	// For the purpose of BGP route key processing, only the Ethernet Tag
	// ID, MAC Address Length, MAC Address, IP Address Length, and IP
	// Address fields are considered to be part of the prefix in the NLRI.
	// The Ethernet Segment Identifier, MPLS Label1, and MPLS Label2 fields
	// are to be treated as route attributes as opposed to being part of the
	// "route".
	return fmt.Sprintf("[type:macadv][rd:%s][etag:%d][mac:%s][ip:%s]", er.RD, er.ETag, er.MacAddress, er.IPAddress)
}

func (er *EVPNMacIPAdvertisementRoute) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		RD         RouteDistinguisherInterface `json:"rd"`
		ESI        string                      `json:"esi"`
		Etag       uint32                      `json:"etag"`
		MacAddress string                      `json:"mac"`
		IPAddress  string                      `json:"ip"`
		Labels     []uint32                    `json:"labels"`
	}{
		RD:         er.RD,
		ESI:        er.ESI.String(),
		Etag:       er.ETag,
		MacAddress: er.MacAddress.String(),
		IPAddress:  er.IPAddress.String(),
		Labels:     er.Labels,
	})
}

func (er *EVPNMacIPAdvertisementRoute) rd() RouteDistinguisherInterface {
	return er.RD
}

func NewEVPNMacIPAdvertisementRoute(rd RouteDistinguisherInterface, esi EthernetSegmentIdentifier, etag uint32, macAddress string, ipAddress string, labels []uint32) *EVPNNLRI {
	mac, _ := net.ParseMAC(macAddress)
	var ipLen uint8
	ip := net.ParseIP(ipAddress)
	if ip != nil {
		if ipv4 := ip.To4(); ipv4 != nil {
			ipLen = 32
			ip = ipv4
		} else {
			ipLen = 128
		}
	}
	return NewEVPNNLRI(EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT, &EVPNMacIPAdvertisementRoute{
		RD:               rd,
		ESI:              esi,
		ETag:             etag,
		MacAddressLength: 48,
		MacAddress:       mac,
		IPAddressLength:  ipLen,
		IPAddress:        ip,
		Labels:           labels,
	})
}

type EVPNMulticastEthernetTagRoute struct {
	RD              RouteDistinguisherInterface
	ETag            uint32
	IPAddressLength uint8
	IPAddress       net.IP
}

func (er *EVPNMulticastEthernetTagRoute) Len() int {
	// RD(8) + ETag(4) + IPAddressLength(1) + IPAddress(4 or 16)
	return 13 + int(er.IPAddressLength)/8
}

func (er *EVPNMulticastEthernetTagRoute) DecodeFromBytes(data []byte) error {
	er.RD = GetRouteDistinguisher(data)
	rdLen := er.RD.Len()
	if len(data) < rdLen+4 {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "invalid length of multicast ethernet tag route")
	}
	data = data[er.RD.Len():]
	er.ETag = binary.BigEndian.Uint32(data[0:4])
	er.IPAddressLength = data[4]
	data = data[5:]
	if er.IPAddressLength == 32 || er.IPAddressLength == 128 {
		er.IPAddress = net.IP(data[:er.IPAddressLength/8])
	} else {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, fmt.Sprintf("Invalid IP address length: %d", er.IPAddressLength))
	}
	return nil
}

func (er *EVPNMulticastEthernetTagRoute) Serialize() ([]byte, error) {
	var buf []byte
	var err error
	if er.RD != nil {
		buf, err = er.RD.Serialize()
		if err != nil {
			return nil, err
		}
	} else {
		buf = make([]byte, 8)
	}
	var tbuf [4]byte
	binary.BigEndian.PutUint32(tbuf[:4], er.ETag)
	buf = append(buf, tbuf[:4]...)
	buf = append(buf, er.IPAddressLength)
	switch er.IPAddressLength {
	case 32:
		buf = append(buf, []byte(er.IPAddress.To4())...)
	case 128:
		buf = append(buf, []byte(er.IPAddress.To16())...)
	default:
		return nil, fmt.Errorf("invalid IP address length: %d", er.IPAddressLength)
	}
	return buf, nil
}

func (er *EVPNMulticastEthernetTagRoute) String() string {
	// RFC7432: BGP MPLS-Based Ethernet VPN
	// 7.3. Inclusive Multicast Ethernet Tag Route
	// ...(snip)... For the purpose of BGP route key
	// processing, only the Ethernet Tag ID, IP Address Length, and
	// Originating Router's IP Address fields are considered to be part of
	// the prefix in the NLRI.
	return fmt.Sprintf("[type:multicast][rd:%s][etag:%d][ip:%s]", er.RD, er.ETag, er.IPAddress)
}

func (er *EVPNMulticastEthernetTagRoute) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		RD        RouteDistinguisherInterface `json:"rd"`
		Etag      uint32                      `json:"etag"`
		IPAddress string                      `json:"ip"`
	}{
		RD:        er.RD,
		Etag:      er.ETag,
		IPAddress: er.IPAddress.String(),
	})
}

func (er *EVPNMulticastEthernetTagRoute) rd() RouteDistinguisherInterface {
	return er.RD
}

func NewEVPNMulticastEthernetTagRoute(rd RouteDistinguisherInterface, etag uint32, ipAddress string) *EVPNNLRI {
	ipLen := uint8(32)
	ip := net.ParseIP(ipAddress)
	if ipv4 := ip.To4(); ipv4 != nil {
		ip = ipv4
	} else {
		ipLen = 128
	}
	return NewEVPNNLRI(EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG, &EVPNMulticastEthernetTagRoute{
		RD:              rd,
		ETag:            etag,
		IPAddressLength: ipLen,
		IPAddress:       ip,
	})
}

type EVPNEthernetSegmentRoute struct {
	RD              RouteDistinguisherInterface
	ESI             EthernetSegmentIdentifier
	IPAddressLength uint8
	IPAddress       net.IP
}

func (er *EVPNEthernetSegmentRoute) Len() int {
	// RD(8) + ESI(10) + IPAddressLength(1) + IPAddress(4 or 16)
	return 19 + int(er.IPAddressLength)/8
}

func (er *EVPNEthernetSegmentRoute) DecodeFromBytes(data []byte) error {
	er.RD = GetRouteDistinguisher(data)
	rdLen := er.RD.Len()
	if len(data) < rdLen {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "invalid Ethernet Segment Route length")
	}
	data = data[er.RD.Len():]
	er.ESI.DecodeFromBytes(data)
	data = data[10:]
	er.IPAddressLength = data[0]
	data = data[1:]
	if er.IPAddressLength == 32 || er.IPAddressLength == 128 {
		er.IPAddress = net.IP(data[:er.IPAddressLength/8])
	} else {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, fmt.Sprintf("Invalid IP address length: %d", er.IPAddressLength))
	}
	return nil
}

func (er *EVPNEthernetSegmentRoute) Serialize() ([]byte, error) {
	var buf []byte
	var err error
	if er.RD != nil {
		buf, err = er.RD.Serialize()
		if err != nil {
			return nil, err
		}
	} else {
		buf = make([]byte, 8)
	}
	tbuf, err := er.ESI.Serialize()
	if err != nil {
		return nil, err
	}
	buf = append(buf, tbuf...)
	buf = append(buf, er.IPAddressLength)
	switch er.IPAddressLength {
	case 32:
		buf = append(buf, []byte(er.IPAddress.To4())...)
	case 128:
		buf = append(buf, []byte(er.IPAddress.To16())...)
	default:
		return nil, fmt.Errorf("invalid IP address length: %d", er.IPAddressLength)
	}
	return buf, nil
}

func (er *EVPNEthernetSegmentRoute) String() string {
	// RFC7432: BGP MPLS-Based Ethernet VPN
	// 7.4. Ethernet Segment Route
	// For the purpose of BGP route key processing, only the Ethernet
	// Segment ID, IP Address Length, and Originating Router's IP Address
	// fields are considered to be part of the prefix in the NLRI.
	return fmt.Sprintf("[type:esi][rd:%s][esi:%s][ip:%s]", er.RD, er.ESI.String(), er.IPAddress)
}

func (er *EVPNEthernetSegmentRoute) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		RD        RouteDistinguisherInterface `json:"rd"`
		ESI       string                      `json:"esi"`
		IPAddress string                      `json:"ip"`
	}{
		RD:        er.RD,
		ESI:       er.ESI.String(),
		IPAddress: er.IPAddress.String(),
	})
}

func (er *EVPNEthernetSegmentRoute) rd() RouteDistinguisherInterface {
	return er.RD
}

func NewEVPNEthernetSegmentRoute(rd RouteDistinguisherInterface, esi EthernetSegmentIdentifier, ipAddress string) *EVPNNLRI {
	ipLen := uint8(32)
	ip := net.ParseIP(ipAddress)
	if ipv4 := ip.To4(); ipv4 != nil {
		ip = ipv4
	} else {
		ipLen = 128
	}
	return NewEVPNNLRI(EVPN_ETHERNET_SEGMENT_ROUTE, &EVPNEthernetSegmentRoute{
		RD:              rd,
		ESI:             esi,
		IPAddressLength: ipLen,
		IPAddress:       ip,
	})
}

type EVPNIPPrefixRoute struct {
	RD             RouteDistinguisherInterface
	ESI            EthernetSegmentIdentifier
	ETag           uint32
	IPPrefixLength uint8
	IPPrefix       net.IP
	GWIPAddress    net.IP
	Label          uint32
}

func (er *EVPNIPPrefixRoute) Len() int {
	if er.IPPrefix.To4() != nil {
		return 34
	}
	return 58
}

func (er *EVPNIPPrefixRoute) DecodeFromBytes(data []byte) error {
	addrLen := net.IPv4len
	switch len(data) {
	case 34:
		// RD(8) + ESI(10) + ETag(4) + IPPrefixLength(1) + IPv4 Prefix(4) + GW IPv4(4) + Label(3)
	case 58:
		// RD(8) + ESI(10) + ETag(4) + IPPrefixLength(1) + IPv6 Prefix(16) + GW IPv6(16) + Label(3)
		addrLen = net.IPv6len
	default:
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "Not all EVPN IP Prefix Route bytes available")
	}

	er.RD = GetRouteDistinguisher(data[0:8])

	err := er.ESI.DecodeFromBytes(data[8:18])
	if err != nil {
		return err
	}

	er.ETag = binary.BigEndian.Uint32(data[18:22])

	er.IPPrefixLength = data[22]

	offset := 23 // RD(8) + ESI(10) + ETag(4) + IPPrefixLength(1)
	er.IPPrefix = data[offset : offset+addrLen]
	offset += addrLen

	er.GWIPAddress = data[offset : offset+addrLen]
	offset += addrLen

	if er.Label, err = labelDecode(data[offset : offset+3]); err != nil {
		return err
	}
	//offset += 3

	return nil
}

func (er *EVPNIPPrefixRoute) Serialize() ([]byte, error) {
	buf := make([]byte, 23) // RD(8) + ESI(10) + ETag(4) + IPPrefixLength(1)

	if er.RD != nil {
		tbuf, err := er.RD.Serialize()
		if err != nil {
			return nil, err
		}
		copy(buf[0:8], tbuf)
	}

	tbuf, err := er.ESI.Serialize()
	if err != nil {
		return nil, err
	}
	copy(buf[8:18], tbuf)

	binary.BigEndian.PutUint32(buf[18:22], er.ETag)

	buf[22] = er.IPPrefixLength

	if er.IPPrefix == nil {
		return nil, NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "IP Prefix is nil")
	} else if er.IPPrefix.To4() != nil {
		buf = append(buf, er.IPPrefix.To4()...)
		if er.GWIPAddress == nil {
			// draft-ietf-bess-evpn-prefix-advertisement: IP Prefix Advertisement in EVPN
			// The GW IP field SHOULD be zero if it is not used as an Overlay Index.
			er.GWIPAddress = net.IPv4zero
		}
		buf = append(buf, er.GWIPAddress.To4()...)
	} else {
		buf = append(buf, er.IPPrefix.To16()...)
		if er.GWIPAddress == nil {
			er.GWIPAddress = net.IPv6zero
		}
		buf = append(buf, er.GWIPAddress.To16()...)
	}

	tbuf, err = labelSerialize(er.Label)
	if err != nil {
		return nil, err
	}
	buf = append(buf, tbuf...)

	return buf, nil
}

func (er *EVPNIPPrefixRoute) String() string {
	// draft-ietf-bess-evpn-prefix-advertisement: IP Prefix Advertisement in EVPN
	// 3.1 IP Prefix Route Encoding
	// The RD, Eth-Tag ID, IP Prefix Length and IP Prefix will be part of
	// the route key used by BGP to compare routes. The rest of the fields
	// will not be part of the route key.
	return fmt.Sprintf("[type:Prefix][rd:%s][etag:%d][prefix:%s/%d]", er.RD, er.ETag, er.IPPrefix, er.IPPrefixLength)
}

func (er *EVPNIPPrefixRoute) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		RD      RouteDistinguisherInterface `json:"rd"`
		ESI     string                      `json:"esi"`
		Etag    uint32                      `json:"etag"`
		Prefix  string                      `json:"prefix"`
		Gateway string                      `json:"gateway"`
		Label   uint32                      `json:"label"`
	}{
		RD:      er.RD,
		ESI:     er.ESI.String(),
		Etag:    er.ETag,
		Prefix:  fmt.Sprintf("%s/%d", er.IPPrefix, er.IPPrefixLength),
		Gateway: er.GWIPAddress.String(),
		Label:   er.Label,
	})
}

func (er *EVPNIPPrefixRoute) rd() RouteDistinguisherInterface {
	return er.RD
}

func NewEVPNIPPrefixRoute(rd RouteDistinguisherInterface, esi EthernetSegmentIdentifier, etag uint32, ipPrefixLength uint8, ipPrefix string, gateway string, label uint32) *EVPNNLRI {
	ip := net.ParseIP(ipPrefix)
	gw := net.ParseIP(gateway)
	if ipv4 := ip.To4(); ipv4 != nil {
		ip = ipv4
		gw = gw.To4()
	}
	return NewEVPNNLRI(EVPN_IP_PREFIX, &EVPNIPPrefixRoute{
		RD:             rd,
		ESI:            esi,
		ETag:           etag,
		IPPrefixLength: ipPrefixLength,
		IPPrefix:       ip,
		GWIPAddress:    gw,
		Label:          label,
	})
}

type EVPNIPMSIRoute struct {
	RD   RouteDistinguisherInterface
	ETag uint32
	EC   ExtendedCommunityInterface
}

func (er *EVPNIPMSIRoute) Len() int {
	// RD(8) + ETag(4) + EC(8)
	return 20
}

func (er *EVPNIPMSIRoute) DecodeFromBytes(data []byte) error {

	er.RD = GetRouteDistinguisher(data[0:8])

	data = data[er.RD.Len():]
	er.ETag = binary.BigEndian.Uint32(data[0:4])

	data = data[4:]
	ec, err := ParseExtended(data[0:8])
	if err != nil {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "Parse extended community interface failed")
	}
	er.EC = ec
	return nil
}

func (er *EVPNIPMSIRoute) Serialize() ([]byte, error) {
	buf := make([]byte, 20)

	if er.RD != nil {
		tbuf, err := er.RD.Serialize()
		if err != nil {
			return nil, err
		}
		copy(buf[0:8], tbuf)
	}

	binary.BigEndian.PutUint32(buf[8:12], er.ETag)

	ec, err := er.EC.Serialize()
	if err != nil {
		return nil, err
	}

	return append(buf, ec...), nil
}

func (er *EVPNIPMSIRoute) String() string {
	ec := "default"
	if er.EC != nil {
		ec = er.EC.String()
	}
	return fmt.Sprintf("[type:I-PMSI][rd:%s][etag:%d][EC:%s]", er.RD, er.ETag, ec)
}

func (er *EVPNIPMSIRoute) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		RD   RouteDistinguisherInterface `json:"rd"`
		ETag uint32                      `json:"etag"`
		EC   string                      `json:"ec"`
	}{
		RD:   er.RD,
		ETag: er.ETag,
		EC:   er.EC.String(),
	})
}

func (er *EVPNIPMSIRoute) rd() RouteDistinguisherInterface {
	return er.RD
}

func NewEVPNIPMSIRoute(rd RouteDistinguisherInterface, etag uint32, ec ExtendedCommunityInterface) *EVPNNLRI {

	return NewEVPNNLRI(EVPN_I_PMSI, &EVPNIPMSIRoute{
		RD:   rd,
		ETag: etag,
		EC:   ec,
	})
}

type EVPNRouteTypeInterface interface {
	Len() int
	DecodeFromBytes([]byte) error
	Serialize() ([]byte, error)
	String() string
	rd() RouteDistinguisherInterface
	MarshalJSON() ([]byte, error)
}

func getEVPNRouteType(t uint8) (EVPNRouteTypeInterface, error) {
	switch t {
	case EVPN_ROUTE_TYPE_ETHERNET_AUTO_DISCOVERY:
		return &EVPNEthernetAutoDiscoveryRoute{}, nil
	case EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT:
		return &EVPNMacIPAdvertisementRoute{}, nil
	case EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG:
		return &EVPNMulticastEthernetTagRoute{}, nil
	case EVPN_ETHERNET_SEGMENT_ROUTE:
		return &EVPNEthernetSegmentRoute{}, nil
	case EVPN_IP_PREFIX:
		return &EVPNIPPrefixRoute{}, nil
	}
	return nil, NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, fmt.Sprintf("Unknown EVPN Route type: %d", t))
}

const (
	EVPN_ROUTE_TYPE_ETHERNET_AUTO_DISCOVERY = 1
	EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT    = 2
	EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG   = 3
	EVPN_ETHERNET_SEGMENT_ROUTE             = 4
	EVPN_IP_PREFIX                          = 5
	EVPN_I_PMSI                             = 9
)

type EVPNNLRI struct {
	PrefixDefault
	RouteType     uint8
	Length        uint8
	RouteTypeData EVPNRouteTypeInterface
}

func (n *EVPNNLRI) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	if IsAddPathEnabled(true, RF_EVPN, options) {
		var err error
		data, err = n.decodePathIdentifier(data)
		if err != nil {
			return err
		}
	}
	if len(data) < 2 {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "Not all EVPNNLRI bytes available")
	}
	n.RouteType = data[0]
	n.Length = data[1]
	data = data[2:]
	if len(data) < int(n.Length) {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "Not all EVPNNLRI Route type bytes available")
	}
	r, err := getEVPNRouteType(n.RouteType)
	if err != nil {
		return err
	}
	n.RouteTypeData = r
	return n.RouteTypeData.DecodeFromBytes(data[:n.Length])
}

func (n *EVPNNLRI) Serialize(options ...*MarshallingOption) ([]byte, error) {
	var buf []byte
	if IsAddPathEnabled(false, RF_EVPN, options) {
		var err error
		buf, err = n.serializeIdentifier()
		if err != nil {
			return nil, err
		}
	}
	offset := len(buf)
	buf = append(buf, make([]byte, 2)...)
	buf[offset] = n.RouteType
	tbuf, err := n.RouteTypeData.Serialize()
	buf[offset+1] = n.Length
	if err != nil {
		return nil, err
	}
	return append(buf, tbuf...), nil
}

func (n *EVPNNLRI) AFI() uint16 {
	return AFI_L2VPN
}

func (n *EVPNNLRI) SAFI() uint8 {
	return SAFI_EVPN
}

func (n *EVPNNLRI) Len(options ...*MarshallingOption) int {
	return int(n.Length) + 2
}

func (n *EVPNNLRI) String() string {
	if n.RouteTypeData != nil {
		return n.RouteTypeData.String()
	}
	return fmt.Sprintf("%d:%d", n.RouteType, n.Length)
}

func (n *EVPNNLRI) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  uint8                  `json:"type"`
		Value EVPNRouteTypeInterface `json:"value"`
	}{
		Type:  n.RouteType,
		Value: n.RouteTypeData,
	})
}

func (n *EVPNNLRI) RD() RouteDistinguisherInterface {
	return n.RouteTypeData.rd()
}

func NewEVPNNLRI(routeType uint8, routeTypeData EVPNRouteTypeInterface) *EVPNNLRI {
	var l uint8
	if routeTypeData != nil {
		l = uint8(routeTypeData.Len())
	}
	return &EVPNNLRI{
		RouteType:     routeType,
		Length:        l,
		RouteTypeData: routeTypeData,
	}
}

type EncapNLRI struct {
	IPAddrPrefixDefault
	addrlen uint8
}

func (n *EncapNLRI) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	if n.addrlen == 0 {
		n.addrlen = 4
	}
	f := RF_IPv4_ENCAP
	if n.addrlen == 16 {
		f = RF_IPv6_ENCAP
	}
	if IsAddPathEnabled(true, f, options) {
		var err error
		data, err = n.decodePathIdentifier(data)
		if err != nil {
			return err
		}
	}
	if len(data) < 4 {
		eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
		eSubCode := uint8(BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST)
		return NewMessageError(eCode, eSubCode, nil, "prefix misses length field")
	}
	n.Length = data[0]
	if n.addrlen == 0 {
		n.addrlen = 4
	}
	return n.decodePrefix(data[1:], n.Length, n.addrlen)
}

func (n *EncapNLRI) Serialize(options ...*MarshallingOption) ([]byte, error) {
	var buf []byte
	f := RF_IPv4_ENCAP
	if n.addrlen == 16 {
		f = RF_IPv6_ENCAP
	}
	if IsAddPathEnabled(false, f, options) {
		var err error
		buf, err = n.serializeIdentifier()
		if err != nil {
			return nil, err
		}
	}
	if n.Prefix.To4() != nil {
		buf = append(buf, net.IPv4len*8)
		n.Prefix = n.Prefix.To4()
	} else {
		buf = append(buf, net.IPv6len*8)
	}
	n.Length = buf[len(buf)-1]
	pbuf, err := n.serializePrefix(n.Length)
	if err != nil {
		return nil, err
	}
	return append(buf, pbuf...), nil
}

func (n *EncapNLRI) String() string {
	return n.Prefix.String()
}

func (n *EncapNLRI) AFI() uint16 {
	return AFI_IP
}

func (n *EncapNLRI) SAFI() uint8 {
	return SAFI_ENCAPSULATION
}

func (n *EncapNLRI) Len(options ...*MarshallingOption) int {
	return 1 + len(n.Prefix)
}

func NewEncapNLRI(endpoint string) *EncapNLRI {
	return &EncapNLRI{
		IPAddrPrefixDefault{Length: 32, Prefix: net.ParseIP(endpoint).To4()},
		4,
	}
}

type Encapv6NLRI struct {
	EncapNLRI
}

func (n *Encapv6NLRI) AFI() uint16 {
	return AFI_IP6
}

func NewEncapv6NLRI(endpoint string) *Encapv6NLRI {
	return &Encapv6NLRI{
		EncapNLRI{
			IPAddrPrefixDefault{Length: 128, Prefix: net.ParseIP(endpoint)},
			16,
		},
	}
}

type BGPFlowSpecType uint8

const (
	FLOW_SPEC_TYPE_UNKNOWN BGPFlowSpecType = iota
	FLOW_SPEC_TYPE_DST_PREFIX
	FLOW_SPEC_TYPE_SRC_PREFIX
	FLOW_SPEC_TYPE_IP_PROTO
	FLOW_SPEC_TYPE_PORT
	FLOW_SPEC_TYPE_DST_PORT
	FLOW_SPEC_TYPE_SRC_PORT
	FLOW_SPEC_TYPE_ICMP_TYPE
	FLOW_SPEC_TYPE_ICMP_CODE
	FLOW_SPEC_TYPE_TCP_FLAG
	FLOW_SPEC_TYPE_PKT_LEN
	FLOW_SPEC_TYPE_DSCP
	FLOW_SPEC_TYPE_FRAGMENT
	FLOW_SPEC_TYPE_LABEL
	FLOW_SPEC_TYPE_ETHERNET_TYPE // 14
	FLOW_SPEC_TYPE_SRC_MAC
	FLOW_SPEC_TYPE_DST_MAC
	FLOW_SPEC_TYPE_LLC_DSAP
	FLOW_SPEC_TYPE_LLC_SSAP
	FLOW_SPEC_TYPE_LLC_CONTROL
	FLOW_SPEC_TYPE_SNAP
	FLOW_SPEC_TYPE_VID
	FLOW_SPEC_TYPE_COS
	FLOW_SPEC_TYPE_INNER_VID
	FLOW_SPEC_TYPE_INNER_COS
)

var FlowSpecNameMap = map[BGPFlowSpecType]string{
	FLOW_SPEC_TYPE_UNKNOWN:       "unknown",
	FLOW_SPEC_TYPE_DST_PREFIX:    "destination",
	FLOW_SPEC_TYPE_SRC_PREFIX:    "source",
	FLOW_SPEC_TYPE_IP_PROTO:      "protocol",
	FLOW_SPEC_TYPE_PORT:          "port",
	FLOW_SPEC_TYPE_DST_PORT:      "destination-port",
	FLOW_SPEC_TYPE_SRC_PORT:      "source-port",
	FLOW_SPEC_TYPE_ICMP_TYPE:     "icmp-type",
	FLOW_SPEC_TYPE_ICMP_CODE:     "icmp-code",
	FLOW_SPEC_TYPE_TCP_FLAG:      "tcp-flags",
	FLOW_SPEC_TYPE_PKT_LEN:       "packet-length",
	FLOW_SPEC_TYPE_DSCP:          "dscp",
	FLOW_SPEC_TYPE_FRAGMENT:      "fragment",
	FLOW_SPEC_TYPE_LABEL:         "label",
	FLOW_SPEC_TYPE_ETHERNET_TYPE: "ether-type",
	FLOW_SPEC_TYPE_SRC_MAC:       "source-mac",
	FLOW_SPEC_TYPE_DST_MAC:       "destination-mac",
	FLOW_SPEC_TYPE_LLC_DSAP:      "llc-dsap",
	FLOW_SPEC_TYPE_LLC_SSAP:      "llc-ssap",
	FLOW_SPEC_TYPE_LLC_CONTROL:   "llc-control",
	FLOW_SPEC_TYPE_SNAP:          "snap",
	FLOW_SPEC_TYPE_VID:           "vid",
	FLOW_SPEC_TYPE_COS:           "cos",
	FLOW_SPEC_TYPE_INNER_VID:     "inner-vid",
	FLOW_SPEC_TYPE_INNER_COS:     "inner-cos",
}

var FlowSpecValueMap = map[string]BGPFlowSpecType{
	FlowSpecNameMap[FLOW_SPEC_TYPE_DST_PREFIX]:    FLOW_SPEC_TYPE_DST_PREFIX,
	FlowSpecNameMap[FLOW_SPEC_TYPE_SRC_PREFIX]:    FLOW_SPEC_TYPE_SRC_PREFIX,
	FlowSpecNameMap[FLOW_SPEC_TYPE_IP_PROTO]:      FLOW_SPEC_TYPE_IP_PROTO,
	FlowSpecNameMap[FLOW_SPEC_TYPE_PORT]:          FLOW_SPEC_TYPE_PORT,
	FlowSpecNameMap[FLOW_SPEC_TYPE_DST_PORT]:      FLOW_SPEC_TYPE_DST_PORT,
	FlowSpecNameMap[FLOW_SPEC_TYPE_SRC_PORT]:      FLOW_SPEC_TYPE_SRC_PORT,
	FlowSpecNameMap[FLOW_SPEC_TYPE_ICMP_TYPE]:     FLOW_SPEC_TYPE_ICMP_TYPE,
	FlowSpecNameMap[FLOW_SPEC_TYPE_ICMP_CODE]:     FLOW_SPEC_TYPE_ICMP_CODE,
	FlowSpecNameMap[FLOW_SPEC_TYPE_TCP_FLAG]:      FLOW_SPEC_TYPE_TCP_FLAG,
	FlowSpecNameMap[FLOW_SPEC_TYPE_PKT_LEN]:       FLOW_SPEC_TYPE_PKT_LEN,
	FlowSpecNameMap[FLOW_SPEC_TYPE_DSCP]:          FLOW_SPEC_TYPE_DSCP,
	FlowSpecNameMap[FLOW_SPEC_TYPE_FRAGMENT]:      FLOW_SPEC_TYPE_FRAGMENT,
	FlowSpecNameMap[FLOW_SPEC_TYPE_LABEL]:         FLOW_SPEC_TYPE_LABEL,
	FlowSpecNameMap[FLOW_SPEC_TYPE_ETHERNET_TYPE]: FLOW_SPEC_TYPE_ETHERNET_TYPE,
	FlowSpecNameMap[FLOW_SPEC_TYPE_SRC_MAC]:       FLOW_SPEC_TYPE_SRC_MAC,
	FlowSpecNameMap[FLOW_SPEC_TYPE_DST_MAC]:       FLOW_SPEC_TYPE_DST_MAC,
	FlowSpecNameMap[FLOW_SPEC_TYPE_LLC_DSAP]:      FLOW_SPEC_TYPE_LLC_DSAP,
	FlowSpecNameMap[FLOW_SPEC_TYPE_LLC_SSAP]:      FLOW_SPEC_TYPE_LLC_SSAP,
	FlowSpecNameMap[FLOW_SPEC_TYPE_LLC_CONTROL]:   FLOW_SPEC_TYPE_LLC_CONTROL,
	FlowSpecNameMap[FLOW_SPEC_TYPE_SNAP]:          FLOW_SPEC_TYPE_SNAP,
	FlowSpecNameMap[FLOW_SPEC_TYPE_VID]:           FLOW_SPEC_TYPE_VID,
	FlowSpecNameMap[FLOW_SPEC_TYPE_COS]:           FLOW_SPEC_TYPE_COS,
	FlowSpecNameMap[FLOW_SPEC_TYPE_INNER_VID]:     FLOW_SPEC_TYPE_INNER_VID,
	FlowSpecNameMap[FLOW_SPEC_TYPE_INNER_COS]:     FLOW_SPEC_TYPE_INNER_COS,
}

// Joins the given and args into a single string and normalize it.
// Example:
// args := []string{"  &  <=80", " tcp  != udp ", " =!   SA   & =U!  F", " =  is-fragment+last-fragment"}
// fmt.Printf("%q", normalizeFlowSpecOpValues(args))
// >>> ["<=80" "tcp" "!=udp" "=!SA" "&=U" "!F" "=is-fragment+last-fragment"]
func normalizeFlowSpecOpValues(args []string) []string {
	// Extracts keywords from the given args.
	sub := ""
	subs := make([]string, 0)
	for _, s := range _regexpFlowSpecOperator.FindAllString(strings.Join(args, " "), -1) {
		sub += s
		if _regexpFlowSpecOperatorValue.MatchString(s) {
			subs = append(subs, sub)
			sub = ""
		}
	}

	// RFC5575 says "It should be unset in the first operator byte of a
	// sequence".
	if len(subs) > 0 {
		subs[0] = strings.TrimPrefix(subs[0], "&")
	}

	return subs
}

// Parses the FlowSpec numeric operator using the given submatch which should be
// the return value of func (*Regexp) FindStringSubmatch.
func parseFlowSpecNumericOperator(submatch []string) (operator uint8, err error) {
	if submatch[1] == "&" {
		operator = DEC_NUM_OP_AND
	}
	value, ok := DECNumOpValueMap[submatch[2]]
	if !ok {
		return 0, fmt.Errorf("invalid numeric operator: %s%s", submatch[1], submatch[2])
	}
	operator |= uint8(value)
	return operator, nil
}

// Parses the pairs of operator and value for the FlowSpec numeric type. The
// given validationFunc is applied to evaluate whether the parsed value is
// valid or not (e.g., if exceeds range or not).
// Note: Each of the args should be formatted in single pair of operator and
// value before calling this function.
// e.g.) "&==100", ">=200" or "&<300"
func parseFlowSpecNumericOpValues(typ BGPFlowSpecType, args []string, validationFunc func(uint64) error) (FlowSpecComponentInterface, error) {
	argsLen := len(args)
	items := make([]*FlowSpecComponentItem, 0, argsLen)
	for idx, arg := range args {
		m := _regexpFlowSpecNumericType.FindStringSubmatch(arg)
		if len(m) < 4 {
			return nil, fmt.Errorf("invalid argument for %s: %s in %q", typ.String(), arg, args)
		}
		operator, err := parseFlowSpecNumericOperator(m)
		if err != nil {
			return nil, err
		}
		// "true" and "false" is operator, but here handles them as value.
		var value uint64
		switch m[3] {
		case "true", "false":
			if idx != argsLen-1 {
				return nil, fmt.Errorf("%s should be the last of each rule", m[3])
			}
			operator = uint8(DECNumOpValueMap[m[3]])
		default:
			if value, err = strconv.ParseUint(m[3], 10, 64); err != nil {
				return nil, fmt.Errorf("invalid numeric value: %s", m[3])
			}
			if err = validationFunc(value); err != nil {
				return nil, err
			}
		}
		items = append(items, NewFlowSpecComponentItem(operator, value))
	}

	// Marks end-of-list bit
	items[argsLen-1].Op |= uint8(DEC_NUM_OP_END)

	return NewFlowSpecComponent(typ, items), nil
}

func flowSpecNumeric1ByteParser(_ RouteFamily, typ BGPFlowSpecType, args []string) (FlowSpecComponentInterface, error) {
	args = normalizeFlowSpecOpValues(args)

	f := func(i uint64) error {
		if i <= 0xff { // 1 byte
			return nil
		}
		return fmt.Errorf("%s range exceeded", typ.String())
	}

	return parseFlowSpecNumericOpValues(typ, args, f)
}

func flowSpecNumeric2BytesParser(_ RouteFamily, typ BGPFlowSpecType, args []string) (FlowSpecComponentInterface, error) {
	args = normalizeFlowSpecOpValues(args)

	f := func(i uint64) error {
		if i <= 0xffff { // 2 bytes
			return nil
		}
		return fmt.Errorf("%s range exceeded", typ.String())
	}

	return parseFlowSpecNumericOpValues(typ, args, f)
}

// Parses the FlowSpec bitmask operand using the given submatch which should be
// the return value of func (*Regexp) FindStringSubmatch.
func parseFlowSpecBitmaskOperand(submatch []string) (operand uint8, err error) {
	if submatch[1] == "&" {
		operand = BITMASK_FLAG_OP_AND
	}
	value, ok := BitmaskFlagOpValueMap[submatch[2]]
	if !ok {
		return 0, fmt.Errorf("invalid bitmask operand: %s%s", submatch[1], submatch[2])
	}
	operand |= uint8(value)
	return operand, nil
}

func flowSpecPrefixParser(rf RouteFamily, typ BGPFlowSpecType, args []string) (FlowSpecComponentInterface, error) {
	// args[0]: IP Prefix or IP Address (suppose prefix length is 32)
	// args[1]: Offset in bit (IPv6 only)
	//
	// Example:
	// - IPv4 Prefix
	//   args := []string{"192.168.0.0/24"}
	// - IPv4 Address
	//   args := []string{"192.168.0.1"}
	// - IPv6 Prefix
	//   args := []string{"2001:db8:1::/64"}
	// - IPv6 Prefix with offset
	//   args := []string{"0:db8:1::/64/16"}
	//   args := []string{"0:db8:1::/64", "16"}
	// - IPv6 Address
	//   args := []string{"2001:db8:1::1"}
	// - IPv6 Address with offset
	//   args := []string{"0:db8:1::1", "16"}
	afi, _ := RouteFamilyToAfiSafi(rf)
	switch afi {
	case AFI_IP:
		if len(args) > 1 {
			return nil, errors.New("cannot specify offset for ipv4 prefix")
		}
		invalidIPv4PrefixError := fmt.Errorf("invalid ipv4 prefix: %s", args[0])
		m := _regexpFindIPv4Prefix.FindStringSubmatch(args[0])
		if len(m) < 4 {
			return nil, invalidIPv4PrefixError
		}
		prefix := net.ParseIP(m[1])
		if prefix.To4() == nil {
			return nil, invalidIPv4PrefixError
		}
		var prefixLen uint64 = 32
		if m[3] != "" {
			var err error
			prefixLen, err = strconv.ParseUint(m[3], 10, 8)
			if err != nil || prefixLen > 32 {
				return nil, invalidIPv4PrefixError
			}
		}
		switch typ {
		case FLOW_SPEC_TYPE_DST_PREFIX:
			return NewFlowSpecDestinationPrefix(NewIPAddrPrefix(uint8(prefixLen), prefix.String())), nil
		case FLOW_SPEC_TYPE_SRC_PREFIX:
			return NewFlowSpecSourcePrefix(NewIPAddrPrefix(uint8(prefixLen), prefix.String())), nil
		}
		return nil, fmt.Errorf("invalid traffic filtering rule type: %s", typ.String())
	case AFI_IP6:
		if len(args) > 2 {
			return nil, fmt.Errorf("invalid arguments for ipv6 prefix: %q", args)
		}
		invalidIPv6PrefixError := fmt.Errorf("invalid ipv6 prefix: %s", args[0])
		m := _regexpFindIPv6Prefix.FindStringSubmatch(args[0])
		if len(m) < 4 {
			return nil, invalidIPv6PrefixError
		}
		prefix := net.ParseIP(m[1])
		if prefix.To16() == nil {
			return nil, invalidIPv6PrefixError
		}
		var prefixLen uint64 = 128
		if m[3] != "" {
			var err error
			prefixLen, err = strconv.ParseUint(m[3], 10, 8)
			if err != nil || prefixLen > 128 {
				return nil, invalidIPv6PrefixError
			}
		}
		var offset uint64
		if len(args) == 1 && m[5] != "" {
			var err error
			offset, err = strconv.ParseUint(m[5], 10, 8)
			if err != nil || offset > 128 {
				return nil, fmt.Errorf("invalid ipv6 prefix offset: %s", m[5])
			}
		} else if len(args) == 2 {
			if m[5] != "" {
				return nil, fmt.Errorf("multiple ipv6 prefix offset arguments detected: %q", args)
			}
			var err error
			offset, err = strconv.ParseUint(args[1], 10, 8)
			if err != nil || offset > 128 {
				return nil, fmt.Errorf("invalid ipv6 prefix offset: %s", args[1])
			}
		}
		switch typ {
		case FLOW_SPEC_TYPE_DST_PREFIX:
			return NewFlowSpecDestinationPrefix6(NewIPv6AddrPrefix(uint8(prefixLen), prefix.String()), uint8(offset)), nil
		case FLOW_SPEC_TYPE_SRC_PREFIX:
			return NewFlowSpecSourcePrefix6(NewIPv6AddrPrefix(uint8(prefixLen), prefix.String()), uint8(offset)), nil
		}
		return nil, fmt.Errorf("invalid traffic filtering rule type: %s", typ.String())
	}
	return nil, fmt.Errorf("invalid address family: %s", rf.String())
}

func flowSpecIpProtoParser(_ RouteFamily, typ BGPFlowSpecType, args []string) (FlowSpecComponentInterface, error) {
	// args: List of pairs of Operator and IP protocol type
	//
	// Example:
	// - TCP or UDP
	//   args := []string{"tcp", "==udp"}
	// - Not TCP and not UDP
	//   args := []string{"!=tcp", "&!=udp"}
	args = normalizeFlowSpecOpValues(args)
	s := strings.Join(args, " ")
	for i, name := range ProtocolNameMap {
		s = strings.Replace(s, name, fmt.Sprintf("%d", i), -1)
	}
	args = strings.Split(s, " ")

	f := func(i uint64) error {
		if i <= 0xff { // 1 byte
			return nil
		}
		return fmt.Errorf("%s range exceeded", typ.String())
	}

	return parseFlowSpecNumericOpValues(typ, args, f)
}

func flowSpecTcpFlagParser(_ RouteFamily, typ BGPFlowSpecType, args []string) (FlowSpecComponentInterface, error) {
	// args: List of pairs of Operand and TCP Flags
	//
	// Example:
	// - SYN or SYN/ACK
	//   args := []string{"==S", "==SA"}
	// - Not FIN and not URG
	//   args := []string{"!=F", "&!=U"}
	args = normalizeFlowSpecOpValues(args)

	argsLen := len(args)
	items := make([]*FlowSpecComponentItem, 0, argsLen)

	for _, arg := range args {
		m := _regexpFlowSpecTCPFlag.FindStringSubmatch(arg)
		if len(m) < 6 {
			return nil, fmt.Errorf("invalid argument for %s: %s in %q", typ.String(), arg, args)
		} else if mLast := m[len(m)-1]; mLast != "" || m[3] != "" {
			return nil, fmt.Errorf("invalid argument for %s: %s in %q", typ.String(), arg, args)
		}
		operand, err := parseFlowSpecBitmaskOperand(m)
		if err != nil {
			return nil, err
		}
		var value uint64
		for flag, name := range TCPFlagNameMap {
			if strings.Contains(m[4], name) {
				value |= uint64(flag)
			}
		}
		items = append(items, NewFlowSpecComponentItem(operand, value))
	}

	// Marks end-of-list bit
	items[argsLen-1].Op |= BITMASK_FLAG_OP_END

	return NewFlowSpecComponent(typ, items), nil
}

func flowSpecDscpParser(_ RouteFamily, typ BGPFlowSpecType, args []string) (FlowSpecComponentInterface, error) {
	args = normalizeFlowSpecOpValues(args)

	f := func(i uint64) error {
		if i < 64 { // 6 bits
			return nil
		}
		return fmt.Errorf("%s range exceeded", typ.String())
	}

	return parseFlowSpecNumericOpValues(typ, args, f)
}

func flowSpecFragmentParser(_ RouteFamily, typ BGPFlowSpecType, args []string) (FlowSpecComponentInterface, error) {
	// args: List of pairs of Operator and Fragment flags
	//
	// Example:
	// - is-fragment or last-fragment
	//   args := []string{"==is-fragment", "==last-fragment"}
	// - is-fragment and last-fragment (exact match)
	//   args := []string{"==is-fragment+last-fragment"}
	args = normalizeFlowSpecOpValues(args)

	argsLen := len(args)
	items := make([]*FlowSpecComponentItem, 0, argsLen)

	for _, arg := range args {
		m := _regexpFlowSpecFragment.FindStringSubmatch(arg)
		if len(m) < 4 {
			return nil, fmt.Errorf("invalid argument for %s: %s in %q", typ.String(), arg, args)
		} else if mLast := m[len(m)-1]; mLast != "" {
			return nil, fmt.Errorf("invalid argument for %s: %s in %q", typ.String(), arg, args)
		}
		operand, err := parseFlowSpecBitmaskOperand(m)
		if err != nil {
			return nil, err
		}
		var value uint64
		// Example:
		// m[3] = "first-fragment+last-fragment"
		for flag, name := range FragmentFlagNameMap {
			if strings.Contains(m[3], name) {
				value |= uint64(flag)
			}
		}
		items = append(items, NewFlowSpecComponentItem(operand, value))
	}

	// Marks end-of-list bit
	items[argsLen-1].Op |= BITMASK_FLAG_OP_END

	return NewFlowSpecComponent(typ, items), nil
}

func flowSpecLabelParser(rf RouteFamily, typ BGPFlowSpecType, args []string) (FlowSpecComponentInterface, error) {
	afi, _ := RouteFamilyToAfiSafi(rf)
	if afi == AFI_IP {
		return nil, fmt.Errorf("%s is not supported for ipv4", typ.String())
	}

	args = normalizeFlowSpecOpValues(args)

	f := func(i uint64) error {
		if i <= 0xfffff { // 20 bits
			return nil
		}
		return errors.New("flow label range exceeded")
	}

	return parseFlowSpecNumericOpValues(typ, args, f)
}

func flowSpecEtherTypeParser(rf RouteFamily, typ BGPFlowSpecType, args []string) (FlowSpecComponentInterface, error) {
	// args: List of pairs of Operator and Ether Types
	//
	// Example:
	// - ARP or IPv4
	//   args := []string{"==arp", "==ipv4"}
	// - Not IPv4 and not IPv6
	//   args := []string{"!=ipv4", "&!=ipv6"}
	if rf != RF_FS_L2_VPN {
		return nil, fmt.Errorf("%s is supported for only l2vpn", typ.String())
	}

	args = normalizeFlowSpecOpValues(args)
	s := strings.Join(args, " ")
	for i, name := range EthernetTypeNameMap {
		s = strings.Replace(s, name, fmt.Sprintf("%d", i), -1)
	}
	args = strings.Split(s, " ")

	f := func(i uint64) error {
		if i <= 0xffff { // 2 bytes
			return nil
		}
		return fmt.Errorf("%s range exceeded", typ.String())
	}

	return parseFlowSpecNumericOpValues(typ, args, f)
}

func flowSpecMacParser(rf RouteFamily, typ BGPFlowSpecType, args []string) (FlowSpecComponentInterface, error) {
	// args[0]: MAC address
	if rf != RF_FS_L2_VPN {
		return nil, fmt.Errorf("%s is supported for only l2vpn", typ.String())
	}

	mac, err := net.ParseMAC(args[0])
	if err != nil {
		return nil, fmt.Errorf("invalid mac address: %s", args[0])
	}

	switch typ {
	case FLOW_SPEC_TYPE_DST_MAC:
		return NewFlowSpecDestinationMac(mac), nil
	case FLOW_SPEC_TYPE_SRC_MAC:
		return NewFlowSpecSourceMac(mac), nil
	}
	return nil, fmt.Errorf("invalid traffic filtering rule type: %s", typ.String())
}

func flowSpecLlcParser(rf RouteFamily, typ BGPFlowSpecType, args []string) (FlowSpecComponentInterface, error) {
	if rf != RF_FS_L2_VPN {
		return nil, fmt.Errorf("%s is supported for only l2vpn", typ.String())
	}

	return flowSpecNumeric1ByteParser(rf, typ, args)
}

func flowSpecSnapParser(rf RouteFamily, typ BGPFlowSpecType, args []string) (FlowSpecComponentInterface, error) {
	if rf != RF_FS_L2_VPN {
		return nil, fmt.Errorf("%s is supported for only l2vpn", typ.String())
	}

	args = normalizeFlowSpecOpValues(args)

	f := func(i uint64) error {
		if i <= 0xffffffffff { // 5 bytes
			return nil
		}
		return fmt.Errorf("%s range exceeded", typ.String())
	}

	return parseFlowSpecNumericOpValues(typ, args, f)
}

func flowSpecVlanIDParser(rf RouteFamily, typ BGPFlowSpecType, args []string) (FlowSpecComponentInterface, error) {
	if rf != RF_FS_L2_VPN {
		return nil, fmt.Errorf("%s is supported for only l2vpn", typ.String())
	}

	args = normalizeFlowSpecOpValues(args)
	s := strings.Join(args, " ")
	for i, name := range EthernetTypeNameMap {
		s = strings.Replace(s, name, fmt.Sprintf("%d", i), -1)
	}
	args = strings.Split(s, " ")

	f := func(i uint64) error {
		if i <= 4095 { // 12 bits
			return nil
		}
		return fmt.Errorf("%s range exceeded", typ.String())
	}

	return parseFlowSpecNumericOpValues(typ, args, f)
}

func flowSpecVlanCosParser(rf RouteFamily, typ BGPFlowSpecType, args []string) (FlowSpecComponentInterface, error) {
	if rf != RF_FS_L2_VPN {
		return nil, fmt.Errorf("%s is supported for only l2vpn", typ.String())
	}

	args = normalizeFlowSpecOpValues(args)
	s := strings.Join(args, " ")
	for i, name := range EthernetTypeNameMap {
		s = strings.Replace(s, name, fmt.Sprintf("%d", i), -1)
	}
	args = strings.Split(s, " ")

	f := func(i uint64) error {
		if i <= 7 { // 3 bits
			return nil
		}
		return fmt.Errorf("%s range exceeded", typ.String())
	}

	return parseFlowSpecNumericOpValues(typ, args, f)
}

var flowSpecParserMap = map[BGPFlowSpecType]func(RouteFamily, BGPFlowSpecType, []string) (FlowSpecComponentInterface, error){
	FLOW_SPEC_TYPE_DST_PREFIX:    flowSpecPrefixParser,
	FLOW_SPEC_TYPE_SRC_PREFIX:    flowSpecPrefixParser,
	FLOW_SPEC_TYPE_IP_PROTO:      flowSpecIpProtoParser,
	FLOW_SPEC_TYPE_PORT:          flowSpecNumeric2BytesParser,
	FLOW_SPEC_TYPE_DST_PORT:      flowSpecNumeric2BytesParser,
	FLOW_SPEC_TYPE_SRC_PORT:      flowSpecNumeric2BytesParser,
	FLOW_SPEC_TYPE_ICMP_TYPE:     flowSpecNumeric1ByteParser,
	FLOW_SPEC_TYPE_ICMP_CODE:     flowSpecNumeric1ByteParser,
	FLOW_SPEC_TYPE_TCP_FLAG:      flowSpecTcpFlagParser,
	FLOW_SPEC_TYPE_PKT_LEN:       flowSpecNumeric2BytesParser,
	FLOW_SPEC_TYPE_DSCP:          flowSpecDscpParser,
	FLOW_SPEC_TYPE_FRAGMENT:      flowSpecFragmentParser,
	FLOW_SPEC_TYPE_LABEL:         flowSpecLabelParser,
	FLOW_SPEC_TYPE_ETHERNET_TYPE: flowSpecEtherTypeParser,
	FLOW_SPEC_TYPE_DST_MAC:       flowSpecMacParser,
	FLOW_SPEC_TYPE_SRC_MAC:       flowSpecMacParser,
	FLOW_SPEC_TYPE_LLC_DSAP:      flowSpecLlcParser,
	FLOW_SPEC_TYPE_LLC_SSAP:      flowSpecLlcParser,
	FLOW_SPEC_TYPE_LLC_CONTROL:   flowSpecLlcParser,
	FLOW_SPEC_TYPE_SNAP:          flowSpecSnapParser,
	FLOW_SPEC_TYPE_VID:           flowSpecVlanIDParser,
	FLOW_SPEC_TYPE_COS:           flowSpecVlanCosParser,
	FLOW_SPEC_TYPE_INNER_VID:     flowSpecVlanIDParser,
	FLOW_SPEC_TYPE_INNER_COS:     flowSpecVlanCosParser,
}

func extractFlowSpecArgs(args []string) map[BGPFlowSpecType][]string {
	m := make(map[BGPFlowSpecType][]string, len(FlowSpecValueMap))
	var typ BGPFlowSpecType
	for _, arg := range args {
		if t, ok := FlowSpecValueMap[arg]; ok {
			typ = t
			m[typ] = make([]string, 0)
		} else {
			m[typ] = append(m[typ], arg)
		}
	}
	return m
}

func ParseFlowSpecComponents(rf RouteFamily, arg string) ([]FlowSpecComponentInterface, error) {
	_, safi := RouteFamilyToAfiSafi(rf)
	switch safi {
	case SAFI_FLOW_SPEC_UNICAST, SAFI_FLOW_SPEC_VPN:
		// Valid
	default:
		return nil, fmt.Errorf("invalid address family: %s", rf.String())
	}

	typeArgs := extractFlowSpecArgs(strings.Split(arg, " "))
	rules := make([]FlowSpecComponentInterface, 0, len(typeArgs))
	for typ, args := range typeArgs {
		parser, ok := flowSpecParserMap[typ]
		if !ok {
			return nil, fmt.Errorf("unsupported traffic filtering rule type: %s", typ.String())
		}
		if len(args) == 0 {
			return nil, fmt.Errorf("specify traffic filtering rules for %s", typ.String())
		}
		rule, err := parser(rf, typ, args)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func (t BGPFlowSpecType) String() string {
	name, ok := FlowSpecNameMap[t]
	if !ok {
		return fmt.Sprintf("%s(%d)", FlowSpecNameMap[FLOW_SPEC_TYPE_UNKNOWN], t)
	}
	return name
}

type FlowSpecComponentInterface interface {
	DecodeFromBytes([]byte, ...*MarshallingOption) error
	Serialize(...*MarshallingOption) ([]byte, error)
	Len(...*MarshallingOption) int
	Type() BGPFlowSpecType
	String() string
}

type flowSpecPrefix struct {
	Prefix AddrPrefixInterface
	typ    BGPFlowSpecType
}

func (p *flowSpecPrefix) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	p.typ = BGPFlowSpecType(data[0])
	return p.Prefix.DecodeFromBytes(data[1:], options...)
}

func (p *flowSpecPrefix) Serialize(options ...*MarshallingOption) ([]byte, error) {
	bbuf, err := p.Prefix.Serialize(options...)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 1+len(bbuf))
	buf[0] = byte(p.Type())
	copy(buf[1:], bbuf)
	return buf, nil
}

func (p *flowSpecPrefix) Len(options ...*MarshallingOption) int {
	buf, _ := p.Serialize(options...)
	return len(buf)
}

func (p *flowSpecPrefix) Type() BGPFlowSpecType {
	return p.typ
}

func (p *flowSpecPrefix) String() string {
	return fmt.Sprintf("[%s: %s]", p.Type(), p.Prefix.String())
}

func (p *flowSpecPrefix) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  BGPFlowSpecType     `json:"type"`
		Value AddrPrefixInterface `json:"value"`
	}{
		Type:  p.Type(),
		Value: p.Prefix,
	})
}

type flowSpecPrefix6 struct {
	Prefix AddrPrefixInterface
	Offset uint8
	typ    BGPFlowSpecType
}

// draft-ietf-idr-flow-spec-v6-06
// <type (1 octet), prefix length (1 octet), prefix offset(1 octet), prefix>
func (p *flowSpecPrefix6) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	p.typ = BGPFlowSpecType(data[0])
	p.Offset = data[2]
	prefix := append([]byte{data[1]}, data[3:]...)
	return p.Prefix.DecodeFromBytes(prefix, options...)
}

func (p *flowSpecPrefix6) Serialize(options ...*MarshallingOption) ([]byte, error) {
	buf := []byte{byte(p.Type())}
	bbuf, err := p.Prefix.Serialize(options...)
	if err != nil {
		return nil, err
	}
	buf = append(buf, bbuf[0])
	buf = append(buf, p.Offset)
	return append(buf, bbuf[1:]...), nil
}

func (p *flowSpecPrefix6) Len(options ...*MarshallingOption) int {
	buf, _ := p.Serialize(options...)
	return len(buf)
}

func (p *flowSpecPrefix6) Type() BGPFlowSpecType {
	return p.typ
}

func (p *flowSpecPrefix6) String() string {
	return fmt.Sprintf("[%s: %s/%d]", p.Type(), p.Prefix.String(), p.Offset)
}

func (p *flowSpecPrefix6) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type   BGPFlowSpecType     `json:"type"`
		Value  AddrPrefixInterface `json:"value"`
		Offset uint8               `json:"offset"`
	}{
		Type:   p.Type(),
		Value:  p.Prefix,
		Offset: p.Offset,
	})
}

type FlowSpecDestinationPrefix struct {
	flowSpecPrefix
}

func NewFlowSpecDestinationPrefix(prefix AddrPrefixInterface) *FlowSpecDestinationPrefix {
	return &FlowSpecDestinationPrefix{flowSpecPrefix{prefix, FLOW_SPEC_TYPE_DST_PREFIX}}
}

type FlowSpecSourcePrefix struct {
	flowSpecPrefix
}

func NewFlowSpecSourcePrefix(prefix AddrPrefixInterface) *FlowSpecSourcePrefix {
	return &FlowSpecSourcePrefix{flowSpecPrefix{prefix, FLOW_SPEC_TYPE_SRC_PREFIX}}
}

type FlowSpecDestinationPrefix6 struct {
	flowSpecPrefix6
}

func NewFlowSpecDestinationPrefix6(prefix AddrPrefixInterface, offset uint8) *FlowSpecDestinationPrefix6 {
	return &FlowSpecDestinationPrefix6{flowSpecPrefix6{prefix, offset, FLOW_SPEC_TYPE_DST_PREFIX}}
}

type FlowSpecSourcePrefix6 struct {
	flowSpecPrefix6
}

func NewFlowSpecSourcePrefix6(prefix AddrPrefixInterface, offset uint8) *FlowSpecSourcePrefix6 {
	return &FlowSpecSourcePrefix6{flowSpecPrefix6{prefix, offset, FLOW_SPEC_TYPE_SRC_PREFIX}}
}

type flowSpecMac struct {
	Mac net.HardwareAddr
	typ BGPFlowSpecType
}

func (p *flowSpecMac) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	if len(data) < 2 || len(data) < 2+int(data[1]) {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "not all mac bits available")
	}
	p.typ = BGPFlowSpecType(data[0])
	p.Mac = net.HardwareAddr(data[2 : 2+int(data[1])])
	return nil
}

func (p *flowSpecMac) Serialize(options ...*MarshallingOption) ([]byte, error) {
	if len(p.Mac) == 0 {
		return nil, errors.New("mac unset")
	}
	buf := make([]byte, 2+len(p.Mac))
	buf[0] = byte(p.Type())
	buf[1] = byte(len(p.Mac))
	copy(buf[2:], p.Mac)
	return buf, nil
}

func (p *flowSpecMac) Len(options ...*MarshallingOption) int {
	return 2 + len(p.Mac)
}

func (p *flowSpecMac) Type() BGPFlowSpecType {
	return p.typ
}

func (p *flowSpecMac) String() string {
	return fmt.Sprintf("[%s: %s]", p.Type(), p.Mac.String())
}

func (p *flowSpecMac) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  BGPFlowSpecType `json:"type"`
		Value string          `json:"value"`
	}{
		Type:  p.Type(),
		Value: p.Mac.String(),
	})
}

type FlowSpecSourceMac struct {
	flowSpecMac
}

func NewFlowSpecSourceMac(mac net.HardwareAddr) *FlowSpecSourceMac {
	return &FlowSpecSourceMac{flowSpecMac{Mac: mac, typ: FLOW_SPEC_TYPE_SRC_MAC}}
}

type FlowSpecDestinationMac struct {
	flowSpecMac
}

func NewFlowSpecDestinationMac(mac net.HardwareAddr) *FlowSpecDestinationMac {
	return &FlowSpecDestinationMac{flowSpecMac{Mac: mac, typ: FLOW_SPEC_TYPE_DST_MAC}}
}

type FlowSpecComponentItem struct {
	Op    uint8  `json:"op"`
	Value uint64 `json:"value"`
}

func (v *FlowSpecComponentItem) Len() int {
	return 1 << ((uint32(v.Op) >> 4) & 0x3)
}

func (v *FlowSpecComponentItem) Serialize() ([]byte, error) {
	order := uint32(math.Log2(float64(v.Len())))
	buf := make([]byte, 1+(1<<order))
	buf[0] = byte(uint32(v.Op) | order<<4)
	switch order {
	case 0:
		buf[1] = byte(v.Value)
	case 1:
		binary.BigEndian.PutUint16(buf[1:], uint16(v.Value))
	case 2:
		binary.BigEndian.PutUint32(buf[1:], uint32(v.Value))
	case 3:
		binary.BigEndian.PutUint64(buf[1:], uint64(v.Value))
	default:
		return nil, fmt.Errorf("invalid value size(too big): %d", v.Value)
	}
	return buf, nil
}

func NewFlowSpecComponentItem(op uint8, value uint64) *FlowSpecComponentItem {
	v := &FlowSpecComponentItem{op, value}
	order := uint32(math.Log2(float64(v.Len())))
	// we don't know if not initialized properly or initialized to
	// zero...
	if order == 0 {
		order = func() uint32 {
			for i := 0; i < 3; i++ {
				if v.Value < (1 << ((1 << uint(i)) * 8)) {
					return uint32(i)
				}
			}
			// return invalid order
			return 4
		}()
	}
	if order > 3 {
		return nil
	}
	v.Op = uint8(uint32(v.Op) | order<<4)
	return v
}

type FlowSpecComponent struct {
	Items []*FlowSpecComponentItem
	typ   BGPFlowSpecType
}

func (p *FlowSpecComponent) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	p.typ = BGPFlowSpecType(data[0])
	data = data[1:]
	p.Items = make([]*FlowSpecComponentItem, 0)
	for {
		if len(data) < 2 {
			return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "not all flowspec component bytes available")
		}
		op := data[0]
		end := op & 0x80
		l := 1 << ((op >> 4) & 0x3) // (min, max) = (1, 8)
		v := make([]byte, 8)
		copy(v[8-l:], data[1:1+l])
		i := binary.BigEndian.Uint64(v)
		item := &FlowSpecComponentItem{op, i}
		p.Items = append(p.Items, item)
		if end > 0 {
			break
		}
		data = data[1+l:]
	}
	return nil
}

func (p *FlowSpecComponent) Serialize(options ...*MarshallingOption) ([]byte, error) {
	buf := []byte{byte(p.Type())}
	for _, v := range p.Items {
		bbuf, err := v.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, bbuf...)
	}
	return buf, nil
}

func (p *FlowSpecComponent) Len(options ...*MarshallingOption) int {
	l := 1
	for _, item := range p.Items {
		l += item.Len() + 1
	}
	return l
}

func (p *FlowSpecComponent) Type() BGPFlowSpecType {
	return p.typ
}

func formatRaw(op uint8, value uint64) string {
	return fmt.Sprintf("op:%b,value:%d", op, value)
}

func formatNumeric(op uint8, value uint64) string {
	cmpFlag := DECNumOp(op & 0x7) // lower 3 bits
	if cmpFlag == DEC_NUM_OP_TRUE || cmpFlag == DEC_NUM_OP_FALSE {
		// Omit value field
		return DECNumOp(op).String()
	}
	return DECNumOp(op).String() + strconv.FormatUint(value, 10)
}

func formatProto(op uint8, value uint64) string {
	cmpFlag := DECNumOp(op & 0x7) // lower 3 bits
	if cmpFlag == DEC_NUM_OP_TRUE || cmpFlag == DEC_NUM_OP_FALSE {
		// Omit value field
		return DECNumOp(op).String()
	}
	return DECNumOp(op).String() + Protocol(value).String()
}

func formatTCPFlag(op uint8, value uint64) string {
	return BitmaskFlagOp(op).String() + TCPFlag(value).String()
}

func formatFragment(op uint8, value uint64) string {
	return BitmaskFlagOp(op).String() + FragmentFlag(value).String()
}

func formatEtherType(op uint8, value uint64) string {
	cmpFlag := DECNumOp(op & 0x7) // lower 3 bits
	if cmpFlag == DEC_NUM_OP_TRUE || cmpFlag == DEC_NUM_OP_FALSE {
		// Omit value field
		return DECNumOp(op).String()
	}
	return DECNumOp(op).String() + EthernetType(value).String()
}

var flowSpecFormatMap = map[BGPFlowSpecType]func(op uint8, value uint64) string{
	FLOW_SPEC_TYPE_UNKNOWN:       formatRaw,
	FLOW_SPEC_TYPE_IP_PROTO:      formatProto,
	FLOW_SPEC_TYPE_PORT:          formatNumeric,
	FLOW_SPEC_TYPE_DST_PORT:      formatNumeric,
	FLOW_SPEC_TYPE_SRC_PORT:      formatNumeric,
	FLOW_SPEC_TYPE_ICMP_TYPE:     formatNumeric,
	FLOW_SPEC_TYPE_ICMP_CODE:     formatNumeric,
	FLOW_SPEC_TYPE_TCP_FLAG:      formatTCPFlag,
	FLOW_SPEC_TYPE_PKT_LEN:       formatNumeric,
	FLOW_SPEC_TYPE_DSCP:          formatNumeric,
	FLOW_SPEC_TYPE_FRAGMENT:      formatFragment,
	FLOW_SPEC_TYPE_LABEL:         formatNumeric,
	FLOW_SPEC_TYPE_ETHERNET_TYPE: formatEtherType,
	FLOW_SPEC_TYPE_LLC_DSAP:      formatNumeric,
	FLOW_SPEC_TYPE_LLC_SSAP:      formatNumeric,
	FLOW_SPEC_TYPE_LLC_CONTROL:   formatNumeric,
	FLOW_SPEC_TYPE_SNAP:          formatNumeric,
	FLOW_SPEC_TYPE_VID:           formatNumeric,
	FLOW_SPEC_TYPE_COS:           formatNumeric,
	FLOW_SPEC_TYPE_INNER_VID:     formatNumeric,
	FLOW_SPEC_TYPE_INNER_COS:     formatNumeric,
}

func (p *FlowSpecComponent) String() string {
	f := flowSpecFormatMap[FLOW_SPEC_TYPE_UNKNOWN]
	if _, ok := flowSpecFormatMap[p.typ]; ok {
		f = flowSpecFormatMap[p.typ]
	}

	items := make([]string, 0, len(p.Items))
	for _, i := range p.Items {
		items = append(items, f(i.Op, i.Value))
	}
	// Removes leading and tailing spaces
	value := strings.TrimSpace(strings.Join(items, ""))

	return fmt.Sprintf("[%s: %s]", p.typ, value)
}

func (p *FlowSpecComponent) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  BGPFlowSpecType          `json:"type"`
		Value []*FlowSpecComponentItem `json:"value"`
	}{
		Type:  p.Type(),
		Value: p.Items,
	})
}

func NewFlowSpecComponent(typ BGPFlowSpecType, items []*FlowSpecComponentItem) *FlowSpecComponent {
	// Set end-of-list bit on the last item and unset them on the others.
	for i, v := range items {
		if i == len(items)-1 {
			v.Op |= 0x80
		} else {
			v.Op &^= 0x80
		}

	}
	return &FlowSpecComponent{
		Items: items,
		typ:   typ,
	}
}

type FlowSpecUnknown struct {
	Value []byte
}

func (p *FlowSpecUnknown) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	p.Value = data
	return nil
}

func (p *FlowSpecUnknown) Serialize(options ...*MarshallingOption) ([]byte, error) {
	return p.Value, nil
}

func (p *FlowSpecUnknown) Len(options ...*MarshallingOption) int {
	return len(p.Value)
}

func (p *FlowSpecUnknown) Type() BGPFlowSpecType {
	if len(p.Value) > 0 {
		return BGPFlowSpecType(p.Value[0])
	}
	return FLOW_SPEC_TYPE_UNKNOWN
}

func (p *FlowSpecUnknown) String() string {
	return fmt.Sprintf("[unknown:%v]", p.Value)
}

func (p *FlowSpecUnknown) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  BGPFlowSpecType `json:"type"`
		Value string          `json:"value"`
	}{
		Type:  p.Type(),
		Value: string(p.Value),
	})
}

type FlowSpecNLRI struct {
	PrefixDefault
	Value []FlowSpecComponentInterface
	rf    RouteFamily
	rd    RouteDistinguisherInterface
}

func (n *FlowSpecNLRI) AFI() uint16 {
	afi, _ := RouteFamilyToAfiSafi(n.rf)
	return afi
}

func (n *FlowSpecNLRI) SAFI() uint8 {
	_, safi := RouteFamilyToAfiSafi(n.rf)
	return safi
}

func (n *FlowSpecNLRI) RD() RouteDistinguisherInterface {
	return n.rd
}

func (n *FlowSpecNLRI) decodeFromBytes(rf RouteFamily, data []byte, options ...*MarshallingOption) error {
	if IsAddPathEnabled(true, rf, options) {
		var err error
		data, err = n.decodePathIdentifier(data)
		if err != nil {
			return err
		}
	}
	var length int
	if (data[0]>>4) == 0xf && len(data) > 2 {
		length = int(binary.BigEndian.Uint16(data[0:2]))
		data = data[2:]
	} else if len(data) > 1 {
		length = int(data[0])
		data = data[1:]
	} else {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "not all flowspec component bytes available")
	}
	if len(data) < length {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "not all flowspec component bytes available")
	}

	n.rf = rf

	if n.SAFI() == SAFI_FLOW_SPEC_VPN {
		if length < 8 {
			return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "not all flowspec component bytes available")
		}
		n.rd = GetRouteDistinguisher(data[:8])
		data = data[8:]
		length -= 8
	}

	for l := length; l > 0; {
		if len(data) == 0 {
			return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "not all flowspec component bytes available")
		}
		t := BGPFlowSpecType(data[0])
		var i FlowSpecComponentInterface
		switch t {
		case FLOW_SPEC_TYPE_DST_PREFIX:
			switch {
			case rf>>16 == AFI_IP:
				i = NewFlowSpecDestinationPrefix(NewIPAddrPrefix(0, ""))
			case rf>>16 == AFI_IP6:
				i = NewFlowSpecDestinationPrefix6(NewIPv6AddrPrefix(0, ""), 0)
			default:
				return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, fmt.Sprintf("Invalid address family: %v", rf))
			}
		case FLOW_SPEC_TYPE_SRC_PREFIX:
			switch {
			case rf>>16 == AFI_IP:
				i = NewFlowSpecSourcePrefix(NewIPAddrPrefix(0, ""))
			case rf>>16 == AFI_IP6:
				i = NewFlowSpecSourcePrefix6(NewIPv6AddrPrefix(0, ""), 0)
			default:
				return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, fmt.Sprintf("Invalid address family: %v", rf))
			}
		case FLOW_SPEC_TYPE_SRC_MAC:
			switch rf {
			case RF_FS_L2_VPN:
				i = NewFlowSpecSourceMac(nil)
			default:
				return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, fmt.Sprintf("Invalid address family: %v", rf))
			}
		case FLOW_SPEC_TYPE_DST_MAC:
			switch rf {
			case RF_FS_L2_VPN:
				i = NewFlowSpecDestinationMac(nil)
			default:
				return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, fmt.Sprintf("Invalid address family: %v", rf))
			}
		case FLOW_SPEC_TYPE_IP_PROTO, FLOW_SPEC_TYPE_PORT, FLOW_SPEC_TYPE_DST_PORT, FLOW_SPEC_TYPE_SRC_PORT,
			FLOW_SPEC_TYPE_ICMP_TYPE, FLOW_SPEC_TYPE_ICMP_CODE, FLOW_SPEC_TYPE_TCP_FLAG, FLOW_SPEC_TYPE_PKT_LEN,
			FLOW_SPEC_TYPE_DSCP, FLOW_SPEC_TYPE_FRAGMENT, FLOW_SPEC_TYPE_LABEL, FLOW_SPEC_TYPE_ETHERNET_TYPE,
			FLOW_SPEC_TYPE_LLC_DSAP, FLOW_SPEC_TYPE_LLC_SSAP, FLOW_SPEC_TYPE_LLC_CONTROL, FLOW_SPEC_TYPE_SNAP,
			FLOW_SPEC_TYPE_VID, FLOW_SPEC_TYPE_COS, FLOW_SPEC_TYPE_INNER_VID, FLOW_SPEC_TYPE_INNER_COS:
			i = NewFlowSpecComponent(t, nil)
		default:
			i = &FlowSpecUnknown{}
		}

		err := i.DecodeFromBytes(data, options...)
		if err != nil {
			i = &FlowSpecUnknown{data}
		}
		l -= i.Len(options...)
		data = data[i.Len(options...):]
		n.Value = append(n.Value, i)
	}

	// Sort Traffic Filtering Rules in types order to avoid the unordered rules
	// are determined different.
	sort.SliceStable(n.Value, func(i, j int) bool { return n.Value[i].Type() < n.Value[j].Type() })

	return nil
}

func (n *FlowSpecNLRI) Serialize(options ...*MarshallingOption) ([]byte, error) {
	buf := make([]byte, 0, 32)
	if n.SAFI() == SAFI_FLOW_SPEC_VPN {
		if n.rd == nil {
			return nil, errors.New("RD is nil")
		}
		b, err := n.rd.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, b...)
	}
	for _, v := range n.Value {
		b, err := v.Serialize(options...)
		if err != nil {
			return nil, err
		}
		buf = append(buf, b...)
	}
	length := n.Len(options...)
	if length > 0xfff {
		return nil, fmt.Errorf("too large: %d", length)
	} else if length < 0xf0 {
		length -= 1
		buf = append([]byte{byte(length)}, buf...)
	} else {
		length -= 2
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, uint16(length))
		buf = append(b, buf...)
	}

	if IsAddPathEnabled(false, n.rf, options) {
		id, err := n.serializeIdentifier()
		if err != nil {
			return nil, err
		}
		return append(id, buf...), nil
	}
	return buf, nil
}

func (n *FlowSpecNLRI) Len(options ...*MarshallingOption) int {
	l := 0
	if n.SAFI() == SAFI_FLOW_SPEC_VPN {
		l += n.RD().Len()
	}
	for _, v := range n.Value {
		l += v.Len(options...)
	}
	if l < 0xf0 {
		return l + 1
	} else {
		return l + 2
	}
}

func (n *FlowSpecNLRI) String() string {
	buf := bytes.NewBuffer(make([]byte, 0, 32))
	if n.SAFI() == SAFI_FLOW_SPEC_VPN {
		buf.WriteString(fmt.Sprintf("[rd: %s]", n.rd))
	}
	for _, v := range n.Value {
		buf.WriteString(v.String())
	}
	return buf.String()
}

func (n *FlowSpecNLRI) MarshalJSON() ([]byte, error) {
	if n.rd != nil {
		return json.Marshal(struct {
			RD    RouteDistinguisherInterface  `json:"rd"`
			Value []FlowSpecComponentInterface `json:"value"`
		}{
			RD:    n.rd,
			Value: n.Value,
		})
	}
	return json.Marshal(struct {
		Value []FlowSpecComponentInterface `json:"value"`
	}{
		Value: n.Value,
	})

}

// CompareFlowSpecNLRI(n, m) returns
// -1 when m has precedence
//
//	0 when n and m have same precedence
//	1 when n has precedence
func CompareFlowSpecNLRI(n, m *FlowSpecNLRI) (int, error) {
	family := AfiSafiToRouteFamily(n.AFI(), n.SAFI())
	if family != AfiSafiToRouteFamily(m.AFI(), m.SAFI()) {
		return 0, errors.New("address family mismatch")
	}
	longer := n.Value
	shorter := m.Value
	invert := 1
	if n.SAFI() == SAFI_FLOW_SPEC_VPN {
		k, _ := n.Serialize()
		l, _ := m.Serialize()
		if result := bytes.Compare(k, l); result != 0 {
			return result, nil
		}
	}
	if len(n.Value) < len(m.Value) {
		longer = m.Value
		shorter = n.Value
		invert = -1
	}
	for idx, v := range longer {
		if len(shorter) < idx+1 {
			return invert, nil
		}
		w := shorter[idx]
		if v.Type() < w.Type() {
			return invert, nil
		} else if v.Type() > w.Type() {
			return invert * -1, nil
		} else if v.Type() == FLOW_SPEC_TYPE_DST_PREFIX || v.Type() == FLOW_SPEC_TYPE_SRC_PREFIX {
			// RFC5575 5.1
			//
			// For IP prefix values (IP destination and source prefix) precedence is
			// given to the lowest IP value of the common prefix length; if the
			// common prefix is equal, then the most specific prefix has precedence.
			var p, q *IPAddrPrefixDefault
			var pCommon, qCommon uint64
			if n.AFI() == AFI_IP {
				if v.Type() == FLOW_SPEC_TYPE_DST_PREFIX {
					p = &v.(*FlowSpecDestinationPrefix).Prefix.(*IPAddrPrefix).IPAddrPrefixDefault
					q = &w.(*FlowSpecDestinationPrefix).Prefix.(*IPAddrPrefix).IPAddrPrefixDefault
				} else {
					p = &v.(*FlowSpecSourcePrefix).Prefix.(*IPAddrPrefix).IPAddrPrefixDefault
					q = &w.(*FlowSpecSourcePrefix).Prefix.(*IPAddrPrefix).IPAddrPrefixDefault
				}
				min := p.Length
				if q.Length < p.Length {
					min = q.Length
				}
				pCommon = uint64(binary.BigEndian.Uint32([]byte(p.Prefix.To4())) >> (32 - min))
				qCommon = uint64(binary.BigEndian.Uint32([]byte(q.Prefix.To4())) >> (32 - min))
			} else if n.AFI() == AFI_IP6 {
				if v.Type() == FLOW_SPEC_TYPE_DST_PREFIX {
					p = &v.(*FlowSpecDestinationPrefix6).Prefix.(*IPv6AddrPrefix).IPAddrPrefixDefault
					q = &w.(*FlowSpecDestinationPrefix6).Prefix.(*IPv6AddrPrefix).IPAddrPrefixDefault
				} else {
					p = &v.(*FlowSpecSourcePrefix6).Prefix.(*IPv6AddrPrefix).IPAddrPrefixDefault
					q = &w.(*FlowSpecSourcePrefix6).Prefix.(*IPv6AddrPrefix).IPAddrPrefixDefault
				}
				min := uint(p.Length)
				if q.Length < p.Length {
					min = uint(q.Length)
				}
				var mask uint
				if min-64 > 0 {
					mask = min - 64
				}
				pCommon = binary.BigEndian.Uint64([]byte(p.Prefix.To16()[:8])) >> mask
				qCommon = binary.BigEndian.Uint64([]byte(q.Prefix.To16()[:8])) >> mask
				if pCommon == qCommon && mask == 0 {
					mask = 64 - min
					pCommon = binary.BigEndian.Uint64([]byte(p.Prefix.To16()[8:])) >> mask
					qCommon = binary.BigEndian.Uint64([]byte(q.Prefix.To16()[8:])) >> mask
				}
			}

			if pCommon < qCommon {
				return invert, nil
			} else if pCommon > qCommon {
				return invert * -1, nil
			} else if p.Length > q.Length {
				return invert, nil
			} else if p.Length < q.Length {
				return invert * -1, nil
			}

		} else {
			// RFC5575 5.1
			//
			// For all other component types, unless otherwise specified, the
			// comparison is performed by comparing the component data as a binary
			// string using the memcmp() function as defined by the ISO C standard.
			// For strings of different lengths, the common prefix is compared.  If
			// equal, the longest string is considered to have higher precedence
			// than the shorter one.
			p, _ := v.Serialize()
			q, _ := w.Serialize()
			min := len(p)
			if len(q) < len(p) {
				min = len(q)
			}
			if result := bytes.Compare(p[:min], q[:min]); result < 0 {
				return invert, nil
			} else if result > 0 {
				return invert * -1, nil
			} else if len(p) > len(q) {
				return invert, nil
			} else if len(q) > len(p) {
				return invert * -1, nil
			}
		}
	}
	return 0, nil
}

type FlowSpecIPv4Unicast struct {
	FlowSpecNLRI
}

func (n *FlowSpecIPv4Unicast) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	return n.decodeFromBytes(AfiSafiToRouteFamily(n.AFI(), n.SAFI()), data, options...)
}

func NewFlowSpecIPv4Unicast(value []FlowSpecComponentInterface) *FlowSpecIPv4Unicast {
	sort.SliceStable(value, func(i, j int) bool { return value[i].Type() < value[j].Type() })
	return &FlowSpecIPv4Unicast{
		FlowSpecNLRI: FlowSpecNLRI{
			Value: value,
			rf:    RF_FS_IPv4_UC,
		},
	}
}

type FlowSpecIPv4VPN struct {
	FlowSpecNLRI
}

func (n *FlowSpecIPv4VPN) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	return n.decodeFromBytes(AfiSafiToRouteFamily(n.AFI(), n.SAFI()), data, options...)
}

func NewFlowSpecIPv4VPN(rd RouteDistinguisherInterface, value []FlowSpecComponentInterface) *FlowSpecIPv4VPN {
	sort.SliceStable(value, func(i, j int) bool { return value[i].Type() < value[j].Type() })
	return &FlowSpecIPv4VPN{
		FlowSpecNLRI: FlowSpecNLRI{
			Value: value,
			rf:    RF_FS_IPv4_VPN,
			rd:    rd,
		},
	}
}

type FlowSpecIPv6Unicast struct {
	FlowSpecNLRI
}

func (n *FlowSpecIPv6Unicast) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	return n.decodeFromBytes(AfiSafiToRouteFamily(n.AFI(), n.SAFI()), data, options...)
}

func NewFlowSpecIPv6Unicast(value []FlowSpecComponentInterface) *FlowSpecIPv6Unicast {
	sort.SliceStable(value, func(i, j int) bool { return value[i].Type() < value[j].Type() })
	return &FlowSpecIPv6Unicast{
		FlowSpecNLRI: FlowSpecNLRI{
			Value: value,
			rf:    RF_FS_IPv6_UC,
		},
	}
}

type FlowSpecIPv6VPN struct {
	FlowSpecNLRI
}

func (n *FlowSpecIPv6VPN) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	return n.decodeFromBytes(AfiSafiToRouteFamily(n.AFI(), n.SAFI()), data, options...)
}

func NewFlowSpecIPv6VPN(rd RouteDistinguisherInterface, value []FlowSpecComponentInterface) *FlowSpecIPv6VPN {
	sort.SliceStable(value, func(i, j int) bool { return value[i].Type() < value[j].Type() })
	return &FlowSpecIPv6VPN{
		FlowSpecNLRI: FlowSpecNLRI{
			Value: value,
			rf:    RF_FS_IPv6_VPN,
			rd:    rd,
		},
	}
}

type FlowSpecL2VPN struct {
	FlowSpecNLRI
}

func (n *FlowSpecL2VPN) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	return n.decodeFromBytes(AfiSafiToRouteFamily(n.AFI(), n.SAFI()), data)
}

func NewFlowSpecL2VPN(rd RouteDistinguisherInterface, value []FlowSpecComponentInterface) *FlowSpecL2VPN {
	sort.SliceStable(value, func(i, j int) bool { return value[i].Type() < value[j].Type() })
	return &FlowSpecL2VPN{
		FlowSpecNLRI: FlowSpecNLRI{
			Value: value,
			rf:    RF_FS_L2_VPN,
			rd:    rd,
		},
	}
}

type OpaqueNLRI struct {
	PrefixDefault
	Length uint16
	Key    []byte
	Value  []byte
}

func (n *OpaqueNLRI) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	if len(data) < 2 {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "Not all OpaqueNLRI bytes available")
	}
	if IsAddPathEnabled(true, RF_OPAQUE, options) {
		var err error
		data, err = n.decodePathIdentifier(data)
		if err != nil {
			return err
		}
	}
	n.Length = binary.BigEndian.Uint16(data[0:2])
	if len(data)-2 < int(n.Length) {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "Not all OpaqueNLRI bytes available")
	}
	n.Key = data[2 : 2+n.Length]
	n.Value = data[2+n.Length:]
	return nil
}

func (n *OpaqueNLRI) Serialize(options ...*MarshallingOption) ([]byte, error) {
	keyLen := len(n.Key)
	if keyLen > math.MaxUint16 {
		return nil, errors.New("key length too big")
	}
	buf := make([]byte, 2, 2+keyLen+len(n.Value))
	binary.BigEndian.PutUint16(buf[:2], uint16(keyLen))
	buf = append(buf, n.Key...)
	buf = append(buf, n.Value...)
	if IsAddPathEnabled(false, RF_OPAQUE, options) {
		id, err := n.serializeIdentifier()
		if err != nil {
			return nil, err
		}
		return append(id, buf...), nil
	}
	return buf, nil
}

func (n *OpaqueNLRI) AFI() uint16 {
	return AFI_OPAQUE
}

func (n *OpaqueNLRI) SAFI() uint8 {
	return SAFI_KEY_VALUE
}

func (n *OpaqueNLRI) Len(options ...*MarshallingOption) int {
	return 2 + len(n.Key) + len(n.Value)
}

func (n *OpaqueNLRI) String() string {
	return string(n.Key)
}

func (n *OpaqueNLRI) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}{
		Key:   string(n.Key),
		Value: string(n.Value),
	})
}

func NewOpaqueNLRI(key, value []byte) *OpaqueNLRI {
	return &OpaqueNLRI{
		Key:   key,
		Value: value,
	}
}

type LsNLRIType uint16

const (
	LS_NLRI_TYPE_UNKNOWN LsNLRIType = iota
	LS_NLRI_TYPE_NODE
	LS_NLRI_TYPE_LINK
	LS_NLRI_TYPE_PREFIX_IPV4
	LS_NLRI_TYPE_PREFIX_IPV6
)

type LsNLRIInterface interface {
	DecodeFromBytes([]byte) error
	Serialize() ([]byte, error)
	Len() int
	Type() LsNLRIType
	String() string
}

type LsProtocolID uint8

const (
	LS_PROTOCOL_UNKNOWN = iota
	LS_PROTOCOL_ISIS_L1
	LS_PROTOCOL_ISIS_L2
	LS_PROTOCOL_OSPF_V2
	LS_PROTOCOL_DIRECT
	LS_PROTOCOL_STATIC
	LS_PROTOCOL_OSPF_V3
)

func (l LsProtocolID) String() string {
	switch l {
	case LS_PROTOCOL_ISIS_L1:
		return "ISIS-L1"
	case LS_PROTOCOL_ISIS_L2:
		return "ISIS-L2"
	case LS_PROTOCOL_OSPF_V2:
		return "OSPFv2"
	case LS_PROTOCOL_DIRECT:
		return "DIRECT"
	case LS_PROTOCOL_STATIC:
		return "STATIC"
	case LS_PROTOCOL_OSPF_V3:
		return "OSPFv3"
	default:
		return fmt.Sprintf("LsProtocolID(%d)", uint8(l))
	}
}

type LsNLRI struct {
	NLRIType   LsNLRIType
	Length     uint16
	ProtocolID LsProtocolID
	Identifier uint64
}

const lsNLRIHdrLen = 9

func (l *LsNLRI) DecodeFromBytes(data []byte) error {
	if len(data) < lsNLRIHdrLen {
		return malformedAttrListErr("Malformed NLRI")
	}

	l.ProtocolID = LsProtocolID(data[0])
	l.Identifier = binary.BigEndian.Uint64(data[1:lsNLRIHdrLen])

	return nil
}

func (l *LsNLRI) Serialize(value []byte) ([]byte, error) {
	buf := make([]byte, lsNLRIHdrLen)
	buf[0] = uint8(l.ProtocolID)
	binary.BigEndian.PutUint64(buf[1:], l.Identifier)
	buf = append(buf, value...)

	return buf, nil
}

func (l *LsNLRI) Len() int {
	return int(l.Length)
}

func (l *LsNLRI) Type() LsNLRIType {
	return l.NLRIType
}

type LsNodeNLRI struct {
	LsNLRI
	LocalNodeDesc LsTLVInterface
}

func (l *LsNodeNLRI) DecodeFromBytes(data []byte) error {
	if err := l.LsNLRI.DecodeFromBytes(data); err != nil {
		return nil
	}

	tlv := data[lsNLRIHdrLen:]
	if len(tlv) < tlvHdrLen {
		return malformedAttrListErr("Malformed Node NLRI")
	}

	tlvType := LsTLVType(binary.BigEndian.Uint16(tlv[:2]))
	if tlvType != LS_TLV_LOCAL_NODE_DESC {
		return malformedAttrListErr("Mandatory TLV missing")
	}

	l.LocalNodeDesc = &LsTLVNodeDescriptor{}
	if err := l.LocalNodeDesc.DecodeFromBytes(tlv); err != nil {
		return malformedAttrListErr(fmt.Sprintf("Malformed Node NLRI: %v", err))
	}

	return nil
}

func (l *LsNodeNLRI) String() string {
	if l.LocalNodeDesc == nil {
		return "NODE { EMPTY }"
	}

	local := l.LocalNodeDesc.(*LsTLVNodeDescriptor).Extract()
	return fmt.Sprintf("NODE { AS:%v BGP-LS ID:%v %v %v:%v }", local.Asn, local.BGPLsID, local.IGPRouterID, l.ProtocolID.String(), l.Identifier)
}

func (l *LsNodeNLRI) Serialize() ([]byte, error) {
	if l.LocalNodeDesc == nil {
		return nil, errors.New("local node descriptor missing")
	}
	ser, err := l.LocalNodeDesc.Serialize()
	if err != nil {
		return nil, err
	}

	return l.LsNLRI.Serialize(ser)
}

func (l *LsNodeNLRI) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type      LsNLRIType       `json:"type"`
		LocalNode LsNodeDescriptor `json:"local_node_desc"`
	}{
		Type:      l.Type(),
		LocalNode: *l.LocalNodeDesc.(*LsTLVNodeDescriptor).Extract(),
	})
}

type LsLinkDescriptor struct {
	LinkLocalID       *uint32
	LinkRemoteID      *uint32
	InterfaceAddrIPv4 *net.IP
	NeighborAddrIPv4  *net.IP
	InterfaceAddrIPv6 *net.IP
	NeighborAddrIPv6  *net.IP
}

func (l *LsLinkDescriptor) ParseTLVs(tlvs []LsTLVInterface) {
	for _, tlv := range tlvs {
		switch v := tlv.(type) {
		case *LsTLVLinkID:
			l.LinkLocalID = &v.Local
			l.LinkRemoteID = &v.Remote

		case *LsTLVIPv4InterfaceAddr:
			l.InterfaceAddrIPv4 = &v.IP

		case *LsTLVIPv4NeighborAddr:
			l.NeighborAddrIPv4 = &v.IP

		case *LsTLVIPv6InterfaceAddr:
			l.InterfaceAddrIPv6 = &v.IP

		case *LsTLVIPv6NeighborAddr:
			l.NeighborAddrIPv6 = &v.IP
		}
	}
}

func (l *LsLinkDescriptor) String() string {
	switch {
	case l.InterfaceAddrIPv4 != nil && l.NeighborAddrIPv4 != nil:
		return fmt.Sprintf("%v->%v", l.InterfaceAddrIPv4, l.NeighborAddrIPv4)

	case l.InterfaceAddrIPv6 != nil && l.NeighborAddrIPv6 != nil:
		return fmt.Sprintf("%v->%v", l.InterfaceAddrIPv6, l.NeighborAddrIPv6)

	case l.LinkLocalID != nil && l.LinkRemoteID != nil:
		return fmt.Sprintf("%v->%v", *l.LinkLocalID, *l.LinkRemoteID)

	case l.InterfaceAddrIPv4 != nil:
		return fmt.Sprintf("%v->UNKNOWN", l.InterfaceAddrIPv4)
	case l.NeighborAddrIPv4 != nil:
		return fmt.Sprintf("UNKNOWN->%v", l.NeighborAddrIPv4)

	case l.InterfaceAddrIPv6 != nil:
		return fmt.Sprintf("%v->UNKNOWN", l.InterfaceAddrIPv6)
	case l.NeighborAddrIPv6 != nil:
		return fmt.Sprintf("UNKNOWN->%v", l.NeighborAddrIPv6)

	case l.LinkLocalID != nil:
		return fmt.Sprintf("%v->UNKNOWN", *l.LinkLocalID)
	case l.LinkRemoteID != nil:
		return fmt.Sprintf("UNKNOWN->%v", *l.LinkRemoteID)

	default:
		return "UNKNOWN"
	}
}

type LsLinkNLRI struct {
	LsNLRI
	LocalNodeDesc  LsTLVInterface
	RemoteNodeDesc LsTLVInterface
	LinkDesc       []LsTLVInterface
}

func (l *LsLinkNLRI) String() string {
	if l.LocalNodeDesc == nil || l.RemoteNodeDesc == nil {
		return "LINK { EMPTY }"
	}

	local := l.LocalNodeDesc.(*LsTLVNodeDescriptor).Extract()
	remote := l.RemoteNodeDesc.(*LsTLVNodeDescriptor).Extract()
	link := &LsLinkDescriptor{}
	link.ParseTLVs(l.LinkDesc)

	return fmt.Sprintf("LINK { LOCAL_NODE: %v REMOTE_NODE: %v LINK: %v}", local.IGPRouterID, remote.IGPRouterID, link)
}

func (l *LsLinkNLRI) DecodeFromBytes(data []byte) error {
	if err := l.LsNLRI.DecodeFromBytes(data); err != nil {
		return nil
	}

	tlv := data[lsNLRIHdrLen:]
	m := make(map[LsTLVType]bool)

	for len(tlv) >= tlvHdrLen {
		sub := &LsTLV{}
		_, err := sub.DecodeFromBytes(tlv)
		if err != nil {
			return err
		}
		m[sub.Type] = true

		var subTLV LsTLVInterface
		switch sub.Type {
		case LS_TLV_LOCAL_NODE_DESC, LS_TLV_REMOTE_NODE_DESC:
			subTLV = &LsTLVNodeDescriptor{}
		case LS_TLV_LINK_ID:
			subTLV = &LsTLVLinkID{}
		case LS_TLV_IPV4_INTERFACE_ADDR:
			subTLV = &LsTLVIPv4InterfaceAddr{}
		case LS_TLV_IPV4_NEIGHBOR_ADDR:
			subTLV = &LsTLVIPv4NeighborAddr{}
		case LS_TLV_IPV6_INTERFACE_ADDR:
			subTLV = &LsTLVIPv6InterfaceAddr{}
		case LS_TLV_IPV6_NEIGHBOR_ADDR:
			subTLV = &LsTLVIPv6NeighborAddr{}

		default:
			tlv = tlv[sub.Len():]
			l.Length -= uint16(sub.Len())
			continue
		}

		if err := subTLV.DecodeFromBytes(tlv); err != nil {
			return err
		}
		tlv = tlv[subTLV.Len():]

		switch sub.Type {
		case LS_TLV_LOCAL_NODE_DESC:
			l.LocalNodeDesc = subTLV
		case LS_TLV_REMOTE_NODE_DESC:
			l.RemoteNodeDesc = subTLV
		default:
			l.LinkDesc = append(l.LinkDesc, subTLV)
		}
	}

	required := []LsTLVType{LS_TLV_LOCAL_NODE_DESC, LS_TLV_REMOTE_NODE_DESC}
	for _, tlv := range required {
		if _, ok := m[tlv]; !ok {
			return malformedAttrListErr("Required TLV missing")
		}
	}

	return nil
}

func (l *LsLinkNLRI) Serialize() ([]byte, error) {
	if l.LocalNodeDesc == nil || l.RemoteNodeDesc == nil {
		return nil, errors.New("required TLV missing")
	}

	buf := make([]byte, 0)
	s, err := l.LocalNodeDesc.Serialize()
	if err != nil {
		return nil, err
	}
	buf = append(buf, s...)

	s, err = l.RemoteNodeDesc.Serialize()
	if err != nil {
		return nil, err
	}
	buf = append(buf, s...)

	for _, tlv := range l.LinkDesc {
		s, err := tlv.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, s...)
	}

	return l.LsNLRI.Serialize(buf)
}

func (l *LsLinkNLRI) MarshalJSON() ([]byte, error) {
	linkDesc := &LsLinkDescriptor{}
	linkDesc.ParseTLVs(l.LinkDesc)

	return json.Marshal(struct {
		Type       LsNLRIType       `json:"type"`
		LocalNode  LsNodeDescriptor `json:"local_node_desc"`
		RemoteNode LsNodeDescriptor `json:"remote_node_desc"`
		LinkDesc   LsLinkDescriptor `json:"link_desc"`
	}{
		Type:       l.Type(),
		LocalNode:  *l.LocalNodeDesc.(*LsTLVNodeDescriptor).Extract(),
		RemoteNode: *l.RemoteNodeDesc.(*LsTLVNodeDescriptor).Extract(),
		LinkDesc:   *linkDesc,
	})
}

type LsPrefixDescriptor struct {
	IPReachability []net.IPNet
	OSPFRouteType  LsOspfRouteType
}

func (l *LsPrefixDescriptor) ParseTLVs(tlvs []LsTLVInterface, ipv6 bool) {
	for _, tlv := range tlvs {
		switch v := tlv.(type) {
		case *LsTLVIPReachability:
			l.IPReachability = append(l.IPReachability, v.ToIPNet(ipv6))

		case *LsTLVOspfRouteType:
			l.OSPFRouteType = v.RouteType
		}
	}
}

type LsPrefixV4NLRI struct {
	LsNLRI
	LocalNodeDesc LsTLVInterface
	PrefixDesc    []LsTLVInterface
}

func (l *LsPrefixV4NLRI) String() string {
	if l.LocalNodeDesc == nil {
		return "PREFIXv4 { EMPTY }"
	}

	local := l.LocalNodeDesc.(*LsTLVNodeDescriptor).Extract()
	prefix := &LsPrefixDescriptor{}
	prefix.ParseTLVs(l.PrefixDesc, false)
	ips := make([]string, len(prefix.IPReachability))
	for i, ip := range prefix.IPReachability {
		ips[i] = ip.String()
	}

	ospf := ""
	if prefix.OSPFRouteType != LS_OSPF_ROUTE_TYPE_UNKNOWN {
		ospf = fmt.Sprintf("OSPF_ROUTE_TYPE:%v ", prefix.OSPFRouteType)
	}

	return fmt.Sprintf("PREFIXv4 { LOCAL_NODE: %s PREFIX: %v %s}", local.IGPRouterID, ips, ospf)
}

func (l *LsPrefixV4NLRI) DecodeFromBytes(data []byte) error {
	if err := l.LsNLRI.DecodeFromBytes(data); err != nil {
		return nil
	}

	tlv := data[lsNLRIHdrLen:]
	m := make(map[LsTLVType]bool)

	for len(tlv) >= tlvHdrLen {
		sub := &LsTLV{}
		_, err := sub.DecodeFromBytes(tlv)
		if err != nil {
			return err
		}
		m[sub.Type] = true

		var subTLV LsTLVInterface
		switch sub.Type {
		case LS_TLV_LOCAL_NODE_DESC:
			subTLV = &LsTLVNodeDescriptor{}
		case LS_TLV_OSPF_ROUTE_TYPE:
			subTLV = &LsTLVOspfRouteType{}
		case LS_TLV_IP_REACH_INFO:
			subTLV = &LsTLVIPReachability{}

		default:
			tlv = tlv[sub.Len():]
			l.Length -= uint16(sub.Len())
			continue
		}

		if err := subTLV.DecodeFromBytes(tlv); err != nil {
			return err
		}
		tlv = tlv[subTLV.Len():]

		switch sub.Type {
		case LS_TLV_LOCAL_NODE_DESC:
			l.LocalNodeDesc = subTLV
		default:
			l.PrefixDesc = append(l.PrefixDesc, subTLV)
		}
	}

	required := []LsTLVType{LS_TLV_IP_REACH_INFO, LS_TLV_LOCAL_NODE_DESC}
	for _, tlv := range required {
		if _, ok := m[tlv]; !ok {
			return malformedAttrListErr("Required TLV missing")
		}
	}

	for _, tlv := range l.PrefixDesc {
		switch v := tlv.(type) {
		case *LsTLVIPReachability:
			if v.PrefixLength > 8*net.IPv4len {
				return malformedAttrListErr("Unexpected IP Reachability info")
			}
		}
	}

	return nil
}

func (l *LsPrefixV4NLRI) Serialize() ([]byte, error) {
	if l.LocalNodeDesc == nil {
		return nil, errors.New("required TLV missing")
	}

	buf := make([]byte, 0)
	s, err := l.LocalNodeDesc.Serialize()
	if err != nil {
		return nil, err
	}
	buf = append(buf, s...)

	for _, tlv := range l.PrefixDesc {
		s, err := tlv.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, s...)
	}

	return l.LsNLRI.Serialize(buf)
}

func (l *LsPrefixV4NLRI) MarshalJSON() ([]byte, error) {
	prefixDesc := &LsPrefixDescriptor{}
	prefixDesc.ParseTLVs(l.PrefixDesc, false)

	return json.Marshal(struct {
		Type       LsNLRIType         `json:"type"`
		LocalNode  LsNodeDescriptor   `json:"local_node_desc"`
		PrefixDesc LsPrefixDescriptor `json:"prefix_desc"`
	}{
		Type:       l.Type(),
		LocalNode:  *l.LocalNodeDesc.(*LsTLVNodeDescriptor).Extract(),
		PrefixDesc: *prefixDesc,
	})
}

type LsPrefixV6NLRI struct {
	LsNLRI
	LocalNodeDesc LsTLVInterface
	PrefixDesc    []LsTLVInterface
}

func (l *LsPrefixV6NLRI) String() string {
	if l.LocalNodeDesc == nil {
		return "PREFIXv6 { EMPTY }"
	}

	local := l.LocalNodeDesc.(*LsTLVNodeDescriptor).Extract()
	prefix := &LsPrefixDescriptor{}
	prefix.ParseTLVs(l.PrefixDesc, true)
	ips := []string{}
	for _, ip := range prefix.IPReachability {
		ips = append(ips, ip.String())
	}

	ospf := ""
	if prefix.OSPFRouteType != LS_OSPF_ROUTE_TYPE_UNKNOWN {
		ospf = fmt.Sprintf("OSPF_ROUTE_TYPE:%v ", prefix.OSPFRouteType)
	}

	return fmt.Sprintf("PREFIXv6 { LOCAL_NODE: %v PREFIX: %v %v}", local.IGPRouterID, ips, ospf)
}

func (l *LsPrefixV6NLRI) DecodeFromBytes(data []byte) error {
	if err := l.LsNLRI.DecodeFromBytes(data); err != nil {
		return nil
	}

	tlv := data[lsNLRIHdrLen:]
	m := make(map[LsTLVType]bool)

	for len(tlv) >= tlvHdrLen {
		sub := &LsTLV{}
		_, err := sub.DecodeFromBytes(tlv)
		if err != nil {
			return err
		}
		m[sub.Type] = true

		var subTLV LsTLVInterface
		switch sub.Type {
		case LS_TLV_LOCAL_NODE_DESC:
			subTLV = &LsTLVNodeDescriptor{}
		case LS_TLV_OSPF_ROUTE_TYPE:
			subTLV = &LsTLVOspfRouteType{}
		case LS_TLV_IP_REACH_INFO:
			subTLV = &LsTLVIPReachability{}

		default:
			tlv = tlv[sub.Len():]
			l.Length -= uint16(sub.Len())
			continue
		}

		if err := subTLV.DecodeFromBytes(tlv); err != nil {
			return err
		}
		tlv = tlv[subTLV.Len():]

		switch sub.Type {
		case LS_TLV_LOCAL_NODE_DESC:
			l.LocalNodeDesc = subTLV
		default:
			l.PrefixDesc = append(l.PrefixDesc, subTLV)
		}
	}

	required := []LsTLVType{LS_TLV_IP_REACH_INFO, LS_TLV_LOCAL_NODE_DESC}
	for _, tlv := range required {
		if _, ok := m[tlv]; !ok {
			return malformedAttrListErr("Required TLV missing")
		}
	}

	return nil
}

func (l *LsPrefixV6NLRI) Serialize() ([]byte, error) {
	if l.LocalNodeDesc == nil {
		return nil, errors.New("required TLV missing")
	}

	buf := make([]byte, 0)
	s, err := l.LocalNodeDesc.Serialize()
	if err != nil {
		return nil, err
	}
	buf = append(buf, s...)

	for _, tlv := range l.PrefixDesc {
		s, err := tlv.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, s...)
	}

	return l.LsNLRI.Serialize(buf)
}

func (l *LsPrefixV6NLRI) MarshalJSON() ([]byte, error) {
	prefixDesc := &LsPrefixDescriptor{}
	prefixDesc.ParseTLVs(l.PrefixDesc, true)

	return json.Marshal(struct {
		Type       LsNLRIType         `json:"type"`
		LocalNode  LsNodeDescriptor   `json:"local_node_desc"`
		PrefixDesc LsPrefixDescriptor `json:"prefix_desc"`
	}{
		Type:       l.Type(),
		LocalNode:  *l.LocalNodeDesc.(*LsTLVNodeDescriptor).Extract(),
		PrefixDesc: *prefixDesc,
	})
}

type LsTLVType uint16

// Based on https://www.iana.org/assignments/bgp-ls-parameters/bgp-ls-parameters.xhtml
const (
	LS_TLV_UNKNOWN LsTLVType = iota

	LS_TLV_LOCAL_NODE_DESC     = 256
	LS_TLV_REMOTE_NODE_DESC    = 257
	LS_TLV_LINK_ID             = 258
	LS_TLV_IPV4_INTERFACE_ADDR = 259
	LS_TLV_IPV4_NEIGHBOR_ADDR  = 260
	LS_TLV_IPV6_INTERFACE_ADDR = 261
	LS_TLV_IPV6_NEIGHBOR_ADDR  = 262
	LS_TLV_MULTI_TOPO_ID       = 263
	LS_TLV_OSPF_ROUTE_TYPE     = 264
	LS_TLV_IP_REACH_INFO       = 265

	LS_TLV_AS                       = 512
	LS_TLV_BGP_LS_ID                = 513
	LS_TLV_OSPF_AREA                = 514
	LS_TLV_IGP_ROUTER_ID            = 515
	LS_TLV_BGP_ROUTER_ID            = 516 // draft-ietf-idr-bgpls-segment-routing-epe, TODO
	LS_TLV_BGP_CONFEDERATION_MEMBER = 517 // draft-ietf-idr-bgpls-segment-routing-epe, TODO

	LS_TLV_NODE_FLAG_BITS        = 1024
	LS_TLV_OPAQUE_NODE_ATTR      = 1025
	LS_TLV_NODE_NAME             = 1026
	LS_TLV_ISIS_AREA             = 1027
	LS_TLV_IPV4_LOCAL_ROUTER_ID  = 1028
	LS_TLV_IPV6_LOCAL_ROUTER_ID  = 1029
	LS_TLV_IPV4_REMOTE_ROUTER_ID = 1030
	LS_TLV_IPV6_REMOTE_ROUTER_ID = 1031

	LS_TLV_SR_CAPABILITIES = 1034 // draft-ietf-idr-bgp-ls-segment-routing-ext
	LS_TLV_SR_ALGORITHM    = 1035 // draft-ietf-idr-bgp-ls-segment-routing-ext
	LS_TLV_SR_LOCAL_BLOCK  = 1036 // draft-ietf-idr-bgp-ls-segment-routing-ext
	LS_TLV_SRMS_PREFERENCE = 1037 // draft-ietf-idr-bgp-ls-segment-routing-ext, TODO

	LS_TLV_ADMIN_GROUP              = 1088
	LS_TLV_MAX_LINK_BANDWIDTH       = 1089
	LS_TLV_MAX_RESERVABLE_BANDWIDTH = 1090
	LS_TLV_UNRESERVED_BANDWIDTH     = 1091
	LS_TLV_TE_DEFAULT_METRIC        = 1092
	LS_TLV_LINK_PROTECTION_TYPE     = 1093 // TODO
	LS_TLV_MPLS_PROTOCOL_MASK       = 1094 // TODO
	LS_TLV_IGP_METRIC               = 1095
	LS_TLV_SRLG                     = 1096
	LS_TLV_OPAQUE_LINK_ATTR         = 1097
	LS_TLV_LINK_NAME                = 1098
	LS_TLV_ADJACENCY_SID            = 1099 // draft-ietf-idr-bgp-ls-segment-routing-ext
	LS_TLV_LAN_ADJACENCY_SID        = 1100 // draft-ietf-idr-bgp-ls-segment-routing-ext, TODO
	LS_TLV_PEER_NODE_SID            = 1101 // draft-ietf-idr-bgpls-segment-routing-epe, TODO
	LS_TLV_PEER_ADJACENCY_SID       = 1102 // draft-ietf-idr-bgpls-segment-routing-epe, TODO
	LS_TLV_PEER_SET_SID             = 1103 // draft-ietf-idr-bgpls-segment-routing-epe, TODO

	LS_TLV_RTM_CAPABILITY = 1105 // RFC8169, TODO

	LS_TLV_IGP_FLAGS              = 1152
	LS_TLV_IGP_ROUTE_TAG          = 1153 // TODO
	LS_TLV_EXTENDED_ROUTE_TAG     = 1154 // TODO
	LS_TLV_PREFIX_METRIC          = 1155 // TODO
	LS_TLV_OSPF_FORWARDING_ADDR   = 1156 // TODO
	LS_TLV_OPAQUE_PREFIX_ATTR     = 1157
	LS_TLV_PREFIX_SID             = 1158 // draft-ietf-idr-bgp-ls-segment-routing-ext
	LS_TLV_RANGE                  = 1159 // draft-ietf-idr-bgp-ls-segment-routing-ext, TODO
	LS_TLV_SID_LABEL_TLV          = 1161 // draft-ietf-idr-bgp-ls-segment-routing-ext
	LS_TLV_PREFIX_ATTRIBUTE_FLAGS = 1170 // draft-ietf-idr-bgp-ls-segment-routing-ext, TODO
	LS_TLV_SOURCE_ROUTER_ID       = 1171 // draft-ietf-idr-bgp-ls-segment-routing-ext, TODO
	LS_TLV_L2_BUNDLE_MEMBER_TLV   = 1172 // draft-ietf-idr-bgp-ls-segment-routing-ext, TODO
)

type LsTLVInterface interface {
	Len() int
	DecodeFromBytes([]byte) error
	Serialize() ([]byte, error)
	String() string
	MarshalJSON() ([]byte, error)
}

type LsTLV struct {
	Type   LsTLVType
	Length uint16
}

func malformedAttrListErr(s string) error {
	return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, s)
}

const tlvHdrLen = 4

func (l *LsTLV) Len() int {
	return int(l.Length) + tlvHdrLen
}

func (l *LsTLV) Serialize(value []byte) ([]byte, error) {
	if len(value) != int(l.Length) {
		return nil, malformedAttrListErr("serialization failed: LS TLV malformed")
	}

	buf := make([]byte, tlvHdrLen+len(value))
	binary.BigEndian.PutUint16(buf[:2], uint16(l.Type))
	binary.BigEndian.PutUint16(buf[2:4], uint16(l.Length))
	copy(buf[4:], value)

	return buf, nil
}

func (l *LsTLV) DecodeFromBytes(data []byte) ([]byte, error) {
	if len(data) < tlvHdrLen {
		return nil, malformedAttrListErr("decoding failed: LS TLV malformed")
	}
	l.Type = LsTLVType(binary.BigEndian.Uint16(data[:2]))
	l.Length = binary.BigEndian.Uint16(data[2:4])

	if len(data) < l.Len() {
		return nil, malformedAttrListErr("decoding failed: LS TLV malformed")
	}

	return data[tlvHdrLen:l.Len()], nil
}

type LsTLVLinkID struct {
	LsTLV
	Local  uint32
	Remote uint32
}

func (l *LsTLVLinkID) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_LINK_ID {
		return malformedAttrListErr("Unexpected TLV type")
	}

	// https://tools.ietf.org/html/rfc5307#section-1.1
	if len(value) != 8 {
		return malformedAttrListErr("Incorrect Link ID length")
	}

	l.Local = binary.BigEndian.Uint32(value[:4])
	l.Remote = binary.BigEndian.Uint32(value[4:])

	return nil
}

func (l *LsTLVLinkID) Serialize() ([]byte, error) {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint32(buf[:4], l.Local)
	binary.BigEndian.PutUint32(buf[4:], l.Remote)

	return l.LsTLV.Serialize(buf)
}

func (l *LsTLVLinkID) String() string {
	return fmt.Sprintf("{Link ID Remote: %v Local: %v}", l.Local, l.Remote)
}

func (l *LsTLVLinkID) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type   LsTLVType `json:"type"`
		Local  uint32    `json:"local_link_id"`
		Remote uint32    `json:"remote_link_id"`
	}{
		Type:   l.Type,
		Local:  l.Local,
		Remote: l.Remote,
	})
}

type LsTLVIPv4InterfaceAddr struct {
	LsTLV
	IP net.IP
}

func (l *LsTLVIPv4InterfaceAddr) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_IPV4_INTERFACE_ADDR {
		return malformedAttrListErr("Unexpected TLV type")
	}

	// https://tools.ietf.org/html/rfc5305#section-3.2
	if len(value) != 4 {
		return malformedAttrListErr("Unexpected address size")
	}

	l.IP = net.IP(value)

	return nil
}

func (l *LsTLVIPv4InterfaceAddr) Serialize() ([]byte, error) {
	return l.LsTLV.Serialize(l.IP)
}

func (l *LsTLVIPv4InterfaceAddr) String() string {
	return fmt.Sprintf("{IPv4 Interface Address: %v}", l.IP)
}

func (l *LsTLVIPv4InterfaceAddr) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  LsTLVType `json:"type"`
		Value string    `json:"ipv4_interface_address"`
	}{
		Type:  l.Type,
		Value: fmt.Sprintf("%v", l.IP),
	})
}

type LsTLVIPv4NeighborAddr struct {
	LsTLV
	IP net.IP
}

func (l *LsTLVIPv4NeighborAddr) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_IPV4_NEIGHBOR_ADDR {
		return malformedAttrListErr("Unexpected TLV type")
	}

	// https://tools.ietf.org/html/rfc5305#section-3.3
	if len(value) != 4 {
		return malformedAttrListErr("Unexpected address size")
	}

	l.IP = net.IP(value)

	return nil
}

func (l *LsTLVIPv4NeighborAddr) Serialize() ([]byte, error) {
	return l.LsTLV.Serialize(l.IP)
}

func (l *LsTLVIPv4NeighborAddr) String() string {
	return fmt.Sprintf("{IPv4 Neighbor Address: %v}", l.IP)
}

func (l *LsTLVIPv4NeighborAddr) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  LsTLVType `json:"type"`
		Value string    `json:"ipv4_neighbor_address"`
	}{
		Type:  l.Type,
		Value: fmt.Sprintf("%v", l.IP),
	})
}

type LsTLVIPv6InterfaceAddr struct {
	LsTLV
	IP net.IP
}

func (l *LsTLVIPv6InterfaceAddr) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_IPV6_INTERFACE_ADDR {
		return malformedAttrListErr("Unexpected TLV type")
	}

	// https://tools.ietf.org/html/rfc6119#section-4.2
	if len(value) != 16 {
		return malformedAttrListErr("Unexpected address size")
	}

	l.IP = net.IP(value)

	if l.IP.IsLinkLocalUnicast() {
		return malformedAttrListErr("Unexpected link local address")
	}

	return nil
}

func (l *LsTLVIPv6InterfaceAddr) Serialize() ([]byte, error) {
	return l.LsTLV.Serialize(l.IP)
}

func (l *LsTLVIPv6InterfaceAddr) String() string {
	return fmt.Sprintf("{IPv6 Interface Address: %v}", l.IP)
}

func (l *LsTLVIPv6InterfaceAddr) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  LsTLVType `json:"type"`
		Value string    `json:"ipv6_interface_address"`
	}{
		Type:  l.Type,
		Value: fmt.Sprintf("%v", l.IP),
	})
}

type LsTLVIPv6NeighborAddr struct {
	LsTLV
	IP net.IP
}

func (l *LsTLVIPv6NeighborAddr) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_IPV6_NEIGHBOR_ADDR {
		return malformedAttrListErr("Unexpected TLV type")
	}

	// https://tools.ietf.org/html/rfc6119#section-4.3
	if len(value) != 16 {
		return malformedAttrListErr("Unexpected address size")
	}

	l.IP = net.IP(value)

	if l.IP.IsLinkLocalUnicast() {
		return malformedAttrListErr("Unexpected link local address")
	}

	return nil
}

func (l *LsTLVIPv6NeighborAddr) Serialize() ([]byte, error) {
	return l.LsTLV.Serialize(l.IP)
}

func (l *LsTLVIPv6NeighborAddr) String() string {
	return fmt.Sprintf("{IPv6 Neighbor Address: %v}", l.IP)
}

func (l *LsTLVIPv6NeighborAddr) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  LsTLVType `json:"type"`
		Value string    `json:"ipv6_neighbor_address"`
	}{
		Type:  l.Type,
		Value: fmt.Sprintf("%v", l.IP),
	})
}

// https://tools.ietf.org/html/rfc7752#section-3.3.1.1
type LsNodeFlags struct {
	Overload bool `json:"overload"`
	Attached bool `json:"attached"`
	External bool `json:"external"`
	ABR      bool `json:"abr"`
	Router   bool `json:"router"`
	V6       bool `json:"v6"`
}

type LsTLVNodeFlagBits struct {
	LsTLV
	Flags uint8
}

func (l *LsTLVNodeFlagBits) Extract() *LsNodeFlags {
	return &LsNodeFlags{
		Overload: (l.Flags & (1 << 7)) > 0,
		Attached: (l.Flags & (1 << 6)) > 0,
		External: (l.Flags & (1 << 5)) > 0,
		ABR:      (l.Flags & (1 << 4)) > 0,
		Router:   (l.Flags & (1 << 3)) > 0,
		V6:       (l.Flags & (1 << 2)) > 0,
	}
}

func (l *LsTLVNodeFlagBits) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_NODE_FLAG_BITS {
		return malformedAttrListErr("Unexpected TLV type")
	}

	if l.Length != 1 {
		return malformedAttrListErr("Node Flag Bits TLV malformed")
	}

	l.Flags = value[0]

	return nil
}

func (l *LsTLVNodeFlagBits) Serialize() ([]byte, error) {
	return l.LsTLV.Serialize([]byte{l.Flags})
}

func (l *LsTLVNodeFlagBits) String() string {
	flags := "XXVRBETO"

	var buf bytes.Buffer

	for i := 0; i < len(flags); i++ {
		if l.Flags&(1<<uint(i)) > 0 {
			buf.WriteString(flags[i : i+1])
		} else {
			buf.WriteString("*")
		}
	}

	return fmt.Sprintf("{Node Flags: %s}", buf.String())
}

func (l *LsTLVNodeFlagBits) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  LsTLVType `json:"type"`
		Flags string    `json:"node_flags"`
	}{
		Type:  l.Type,
		Flags: l.String(),
	})
}

type LsTLVNodeName struct {
	LsTLV
	Name string
}

func (l *LsTLVNodeName) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_NODE_NAME {
		return malformedAttrListErr("Unexpected TLV type")
	}

	// RFC5301, section 3.
	if l.Length < 1 || l.Length > 255 {
		return malformedAttrListErr("Incorrect Node Name")
	}

	l.Name = string(value)

	return nil
}

func (l *LsTLVNodeName) Serialize() ([]byte, error) {
	return l.LsTLV.Serialize([]byte(l.Name))
}

func (l *LsTLVNodeName) String() string {
	return fmt.Sprintf("{Node Name: %s}", l.Name)
}

func (l *LsTLVNodeName) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type LsTLVType `json:"type"`
		Name string    `json:"node_name"`
	}{
		Type: l.Type,
		Name: l.Name,
	})
}

type LsTLVIsisArea struct {
	LsTLV
	Area []byte
}

func (l *LsTLVIsisArea) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_ISIS_AREA {
		return malformedAttrListErr("Unexpected TLV type")
	}

	if len(value) < 1 || len(value) > 13 {
		return malformedAttrListErr("Incorrect ISIS Area size")
	}

	l.Area = value

	return nil
}

func (l *LsTLVIsisArea) Serialize() ([]byte, error) {
	return l.LsTLV.Serialize(l.Area)
}

func (l *LsTLVIsisArea) String() string {
	return fmt.Sprintf("{ISIS Area ID: %v}", l.Area)
}

func (l *LsTLVIsisArea) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type LsTLVType `json:"type"`
		Area string    `json:"isis_area_id"`
	}{
		Type: l.Type,
		Area: fmt.Sprintf("%v", l.Area),
	})
}

type LsTLVLocalIPv4RouterID struct {
	LsTLV
	IP net.IP
}

func (l *LsTLVLocalIPv4RouterID) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_IPV4_LOCAL_ROUTER_ID {
		return malformedAttrListErr("Unexpected TLV type")
	}

	// https://tools.ietf.org/html/rfc5305#section-4.3
	if len(value) != 4 {
		return malformedAttrListErr("Unexpected address size")
	}

	l.IP = net.IP(value)

	return nil
}

func (l *LsTLVLocalIPv4RouterID) Serialize() ([]byte, error) {
	return l.LsTLV.Serialize(l.IP)
}

func (l *LsTLVLocalIPv4RouterID) String() string {
	return fmt.Sprintf("{Local RouterID IPv4: %v}", l.IP)
}

func (l *LsTLVLocalIPv4RouterID) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  LsTLVType `json:"type"`
		Value string    `json:"node_local_router_id_ipv4"`
	}{
		Type:  l.Type,
		Value: fmt.Sprintf("%v", l.IP),
	})
}

type LsTLVRemoteIPv4RouterID struct {
	LsTLV
	IP net.IP
}

func (l *LsTLVRemoteIPv4RouterID) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_IPV4_REMOTE_ROUTER_ID {
		return malformedAttrListErr("Unexpected TLV type")
	}

	// https://tools.ietf.org/html/rfc5305#section-4.3
	if len(value) != 4 {
		return malformedAttrListErr("Unexpected address size")
	}

	l.IP = net.IP(value)

	return nil
}

func (l *LsTLVRemoteIPv4RouterID) Serialize() ([]byte, error) {
	return l.LsTLV.Serialize(l.IP)
}

func (l *LsTLVRemoteIPv4RouterID) String() string {
	return fmt.Sprintf("{Remote RouterID IPv4: %v}", l.IP)
}

func (l *LsTLVRemoteIPv4RouterID) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  LsTLVType `json:"type"`
		Value string    `json:"node_remote_router_id_ipv4"`
	}{
		Type:  l.Type,
		Value: fmt.Sprintf("%v", l.IP),
	})
}

type LsTLVLocalIPv6RouterID struct {
	LsTLV
	IP net.IP
}

func (l *LsTLVLocalIPv6RouterID) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_IPV6_LOCAL_ROUTER_ID {
		return malformedAttrListErr("Unexpected TLV type")
	}

	// https://tools.ietf.org/html/rfc6119#section-4.1
	if len(value) != 16 {
		return malformedAttrListErr("Unexpected address size")
	}

	l.IP = net.IP(value)

	return nil
}

func (l *LsTLVLocalIPv6RouterID) Serialize() ([]byte, error) {
	return l.LsTLV.Serialize(l.IP)
}

func (l *LsTLVLocalIPv6RouterID) String() string {
	return fmt.Sprintf("{Local RouterID IPv6: %v}", l.IP)
}

func (l *LsTLVLocalIPv6RouterID) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  LsTLVType `json:"type"`
		Value string    `json:"node_local_router_id_ipv6"`
	}{
		Type:  l.Type,
		Value: fmt.Sprintf("%v", l.IP),
	})
}

type LsTLVRemoteIPv6RouterID struct {
	LsTLV
	IP net.IP
}

func (l *LsTLVRemoteIPv6RouterID) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_IPV6_REMOTE_ROUTER_ID {
		return malformedAttrListErr("Unexpected TLV type")
	}

	// https://tools.ietf.org/html/rfc6119#section-4.1
	if len(value) != 16 {
		return malformedAttrListErr("Unexpected address size")
	}

	l.IP = net.IP(value)

	return nil
}

func (l *LsTLVRemoteIPv6RouterID) Serialize() ([]byte, error) {
	return l.LsTLV.Serialize(l.IP)
}

func (l *LsTLVRemoteIPv6RouterID) String() string {
	return fmt.Sprintf("{Remote RouterID IPv6: %v}", l.IP)
}

func (l *LsTLVRemoteIPv6RouterID) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  LsTLVType `json:"type"`
		Value string    `json:"node_remote_router_id_ipv6"`
	}{
		Type:  l.Type,
		Value: fmt.Sprintf("%v", l.IP),
	})
}

type LsTLVOpaqueNodeAttr struct {
	LsTLV
	Attr []byte
}

func (l *LsTLVOpaqueNodeAttr) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_OPAQUE_NODE_ATTR {
		return malformedAttrListErr("Unexpected TLV type")
	}

	l.Attr = value

	return nil
}

func (l *LsTLVOpaqueNodeAttr) Serialize() ([]byte, error) {
	return l.LsTLV.Serialize(l.Attr)
}

func (l *LsTLVOpaqueNodeAttr) String() string {
	return fmt.Sprintf("{Opaque attribute: %v}", l.Attr)
}

func (l *LsTLVOpaqueNodeAttr) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  LsTLVType `json:"type"`
		Value string    `json:"node_opaque_attribute"`
	}{
		Type:  l.Type,
		Value: fmt.Sprintf("%v", l.Attr),
	})
}

type LsTLVAutonomousSystem struct {
	LsTLV
	ASN uint32
}

func (l *LsTLVAutonomousSystem) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_AS {
		return malformedAttrListErr("Unexpected TLV type")
	}

	// https://tools.ietf.org/html/rfc7752#section-3.2.1.4
	if len(value) != 4 {
		return malformedAttrListErr("Incorrect AS length")
	}

	l.ASN = binary.BigEndian.Uint32(value)

	return nil
}

func (l *LsTLVAutonomousSystem) Serialize() ([]byte, error) {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:4], l.ASN)

	return l.LsTLV.Serialize(buf[:])
}

func (l *LsTLVAutonomousSystem) String() string {
	return fmt.Sprintf("{ASN: %d}", l.ASN)
}

func (l *LsTLVAutonomousSystem) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type LsTLVType `json:"type"`
		ASN  uint32    `json:"asn"`
	}{
		Type: l.Type,
		ASN:  l.ASN,
	})
}

type LsTLVBgpLsID struct {
	LsTLV
	BGPLsID uint32
}

func (l *LsTLVBgpLsID) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_BGP_LS_ID {
		return malformedAttrListErr("Unexpected TLV type")
	}

	// https://tools.ietf.org/html/rfc7752#section-3.2.1.4
	if len(value) != 4 {
		return malformedAttrListErr("Incorrect BGP-LS ID length")
	}

	l.BGPLsID = binary.BigEndian.Uint32(value)

	return nil
}

func (l *LsTLVBgpLsID) Serialize() ([]byte, error) {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:4], l.BGPLsID)

	return l.LsTLV.Serialize(buf[:4])
}

func (l *LsTLVBgpLsID) String() string {
	return fmt.Sprintf("{BGP LS ID: %d}", l.BGPLsID)
}

func (l *LsTLVBgpLsID) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type    LsTLVType `json:"type"`
		BgpLsID uint32    `json:"bgp_ls_id"`
	}{
		Type:    l.Type,
		BgpLsID: l.BGPLsID,
	})
}

type LsTLVIgpRouterID struct {
	LsTLV
	RouterID []byte
}

func (l *LsTLVIgpRouterID) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_IGP_ROUTER_ID {
		return malformedAttrListErr("Unexpected TLV type")
	}

	// https://tools.ietf.org/html/rfc7752#section-3.2.1.4
	// 4, 6, 7, and 8 are the only valid values.
	switch len(value) {
	case 4, 6, 7, 8:
		break
	default:
		return malformedAttrListErr(fmt.Sprintf("Incorrect IGP Router ID length: %d", len(value)))
	}

	l.RouterID = value

	return nil
}

func (l *LsTLVIgpRouterID) Serialize() ([]byte, error) {
	return l.LsTLV.Serialize(l.RouterID)
}

func (l *LsTLVIgpRouterID) String() string {
	return fmt.Sprintf("{IGP Router ID: %v}", l.RouterID)
}

func (l *LsTLVIgpRouterID) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type     LsTLVType `json:"type"`
		RouterID string    `json:"igp_router_id"`
	}{
		Type:     l.Type,
		RouterID: fmt.Sprintf("%v", l.RouterID),
	})
}

type LsTLVOspfAreaID struct {
	LsTLV
	AreaID uint32
}

func (l *LsTLVOspfAreaID) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_OSPF_AREA {
		return malformedAttrListErr("Unexpected TLV type")
	}

	// https://tools.ietf.org/html/rfc7752#section-3.2.1.4
	if len(value) != 4 {
		return malformedAttrListErr("Incorrect OSPF Area ID length")
	}

	l.AreaID = binary.BigEndian.Uint32(value)

	return nil
}

func (l *LsTLVOspfAreaID) Serialize() ([]byte, error) {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:4], l.AreaID)

	return l.LsTLV.Serialize(buf[:4])
}

func (l *LsTLVOspfAreaID) String() string {
	return fmt.Sprintf("{OSPF Area ID: %d}", l.AreaID)
}

func (l *LsTLVOspfAreaID) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type   LsTLVType `json:"type"`
		AreaID uint32    `json:"ospf_area_id"`
	}{
		Type:   l.Type,
		AreaID: l.AreaID,
	})
}

type LsOspfRouteType uint8

const (
	LS_OSPF_ROUTE_TYPE_UNKNOWN = iota
	LS_OSPF_ROUTE_TYPE_INTRA_AREA
	LS_OSPF_ROUTE_TYPE_INTER_AREA
	LS_OSPF_ROUTE_TYPE_EXTERNAL1
	LS_OSPF_ROUTE_TYPE_EXTERNAL2
	LS_OSPF_ROUTE_TYPE_NSSA1
	LS_OSPF_ROUTE_TYPE_NSSA2
)

func (l LsOspfRouteType) String() string {
	switch l {
	case LS_OSPF_ROUTE_TYPE_INTRA_AREA:
		return "INTRA-AREA"
	case LS_OSPF_ROUTE_TYPE_INTER_AREA:
		return "INTER-AREA"
	case LS_OSPF_ROUTE_TYPE_EXTERNAL1:
		return "EXTERNAL1"
	case LS_OSPF_ROUTE_TYPE_EXTERNAL2:
		return "EXTERNAL2"
	case LS_OSPF_ROUTE_TYPE_NSSA1:
		return "NSSA1"
	case LS_OSPF_ROUTE_TYPE_NSSA2:
		return "NSSA2"
	default:
		return fmt.Sprintf("LsOspfRouteType(%d)", uint8(l))
	}
}

type LsTLVOspfRouteType struct {
	LsTLV
	RouteType LsOspfRouteType
}

func (l *LsTLVOspfRouteType) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_OSPF_ROUTE_TYPE {
		return malformedAttrListErr("Unexpected TLV type")
	}

	// https://tools.ietf.org/html/rfc7752#section-3.2.3.1
	if len(value) != 1 {
		return malformedAttrListErr("Incorrect OSPF Route type length")
	}

	if value[0] < byte(LS_OSPF_ROUTE_TYPE_INTRA_AREA) || value[0] > LS_OSPF_ROUTE_TYPE_NSSA2 {
		return malformedAttrListErr("Incorrect OSPF Route type")
	}

	l.RouteType = LsOspfRouteType(value[0])

	return nil
}

func (l *LsTLVOspfRouteType) Serialize() ([]byte, error) {
	var buf [1]byte
	buf[0] = byte(l.RouteType)

	return l.LsTLV.Serialize(buf[:])
}

func (l *LsTLVOspfRouteType) String() string {
	return fmt.Sprintf("{OSPF Route Type: %v}", l.RouteType)
}

func (l *LsTLVOspfRouteType) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type      LsTLVType `json:"type"`
		RouteType string    `json:"ospf_route_type"`
	}{
		Type:      l.Type,
		RouteType: l.RouteType.String(),
	})
}

type LsTLVIPReachability struct {
	LsTLV
	PrefixLength uint8
	Prefix       []byte
}

func (l *LsTLVIPReachability) ToIPNet(ipv6 bool) net.IPNet {
	b := make([]byte, 16)
	for i := 0; i < int(((l.PrefixLength-1)/8)+1); i++ {
		b[i] = l.Prefix[i]
	}

	ip := net.IPv4(b[0], b[1], b[2], b[3]).To4()
	if ipv6 {
		ip = net.IP(b).To16()
	}

	_, n, err := net.ParseCIDR(fmt.Sprintf("%v/%v", ip, l.PrefixLength))
	if err != nil {
		return net.IPNet{}
	}

	return *n
}

func (l *LsTLVIPReachability) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_IP_REACH_INFO {
		return malformedAttrListErr("Unexpected TLV type")
	}

	if len(value) < 2 {
		return malformedAttrListErr("Incorrect IP reachability Info length")
	}

	// https://tools.ietf.org/html/rfc7752#section-3.2.3.2
	if value[0] > 128 || value[0] == 0 {
		return malformedAttrListErr("Incorrect IP prefix length")
	}

	ll := int(((value[0] - 1) / 8) + 1)
	if len(value[1:]) != ll {
		return malformedAttrListErr("Malformed IP reachability TLV")
	}

	l.PrefixLength = value[0]
	l.Prefix = value[1 : 1+ll]

	return nil
}

func (l *LsTLVIPReachability) Serialize() ([]byte, error) {
	b := []byte{l.PrefixLength}

	return l.LsTLV.Serialize(append(b, l.Prefix...))
}

func (l *LsTLVIPReachability) String() string {
	return fmt.Sprintf("{IP Reachability: %v/%v}", l.Prefix, l.PrefixLength)
}

func (l *LsTLVIPReachability) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type         LsTLVType `json:"type"`
		PrefixLength uint8     `json:"prefix_length"`
		Prefix       string    `json:"prefix"`
	}{
		Type:         l.Type,
		PrefixLength: l.PrefixLength,
		Prefix:       fmt.Sprintf("%v", l.Prefix),
	})
}

type LsTLVAdminGroup struct {
	LsTLV
	AdminGroup uint32
}

func (l *LsTLVAdminGroup) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_ADMIN_GROUP {
		return malformedAttrListErr("Unexpected TLV type")
	}

	// https://tools.ietf.org/html/rfc5305#section-3.1
	if len(value) != 4 {
		return malformedAttrListErr("Incorrect Admin Group length")
	}

	l.AdminGroup = binary.BigEndian.Uint32(value)

	return nil
}

func (l *LsTLVAdminGroup) Serialize() ([]byte, error) {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:4], l.AdminGroup)

	return l.LsTLV.Serialize(buf[:])
}

func (l *LsTLVAdminGroup) String() string {
	return fmt.Sprintf("{Admin Group: %08x}", l.AdminGroup)
}

func (l *LsTLVAdminGroup) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type       LsTLVType `json:"type"`
		AdminGroup string    `json:"admin_group"`
	}{
		Type:       l.Type,
		AdminGroup: fmt.Sprintf("%08x", l.AdminGroup),
	})
}

type LsTLVMaxLinkBw struct {
	LsTLV
	Bandwidth float32
}

func (l *LsTLVMaxLinkBw) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_MAX_LINK_BANDWIDTH {
		return malformedAttrListErr("Unexpected TLV type")
	}

	// https://tools.ietf.org/html/rfc5305#section-3.4
	if len(value) != 4 {
		return malformedAttrListErr("Incorrect maximum link bandwidth length")
	}

	l.Bandwidth = math.Float32frombits(binary.BigEndian.Uint32(value))

	if l.Bandwidth < 0 || math.IsNaN(float64(l.Bandwidth)) || math.IsInf(float64(l.Bandwidth), 0) {
		return malformedAttrListErr("Incorrect maximum link bandwidth value")
	}

	return nil
}

func (l *LsTLVMaxLinkBw) Serialize() ([]byte, error) {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:4], math.Float32bits(l.Bandwidth))

	return l.LsTLV.Serialize(buf[:])
}

func (l *LsTLVMaxLinkBw) String() string {
	return fmt.Sprintf("{Max Link BW: %v}", l.Bandwidth)
}

func (l *LsTLVMaxLinkBw) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type      LsTLVType `json:"type"`
		Bandwidth float32   `json:"max_link_bw"`
	}{
		Type:      l.Type,
		Bandwidth: l.Bandwidth,
	})
}

type LsTLVMaxReservableLinkBw struct {
	LsTLV
	Bandwidth float32
}

func (l *LsTLVMaxReservableLinkBw) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_MAX_RESERVABLE_BANDWIDTH {
		return malformedAttrListErr("Unexpected TLV type")
	}

	// https://tools.ietf.org/html/rfc5305#section-3.5
	if len(value) != 4 {
		return malformedAttrListErr("Incorrect maximum reservable link bandwidth length")
	}

	l.Bandwidth = math.Float32frombits(binary.BigEndian.Uint32(value))

	if l.Bandwidth < 0 || math.IsNaN(float64(l.Bandwidth)) || math.IsInf(float64(l.Bandwidth), 0) {
		return malformedAttrListErr("Incorrect maximum reservable link bandwidth value")
	}

	return nil
}

func (l *LsTLVMaxReservableLinkBw) Serialize() ([]byte, error) {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:4], math.Float32bits(l.Bandwidth))

	return l.LsTLV.Serialize(buf[:])
}

func (l *LsTLVMaxReservableLinkBw) String() string {
	return fmt.Sprintf("{Max Reservable Link BW: %v}", l.Bandwidth)
}

func (l *LsTLVMaxReservableLinkBw) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type      LsTLVType `json:"type"`
		Bandwidth float32   `json:"max_reservable_link_bw"`
	}{
		Type:      l.Type,
		Bandwidth: l.Bandwidth,
	})
}

type LsTLVUnreservedBw struct {
	LsTLV
	Bandwidth [8]float32
}

func (l *LsTLVUnreservedBw) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_UNRESERVED_BANDWIDTH {
		return malformedAttrListErr("Unexpected TLV type")
	}

	// https://tools.ietf.org/html/rfc5305#section-3.6
	if len(value) != 32 {
		return malformedAttrListErr("Incorrect unreserved bandwidth length")
	}

	for i := 0; i < len(l.Bandwidth); i++ {
		l.Bandwidth[i] = math.Float32frombits(binary.BigEndian.Uint32(value[:4]))
		value = value[4:]

		if l.Bandwidth[i] < 0 || math.IsNaN(float64(l.Bandwidth[i])) || math.IsInf(float64(l.Bandwidth[i]), 0) {
			return malformedAttrListErr("Incorrect unreserved bandwidth value")
		}
	}

	return nil
}

func (l *LsTLVUnreservedBw) Serialize() ([]byte, error) {
	buf := make([]byte, 0, 4*len(l.Bandwidth))

	var b [4]byte
	for i := 0; i < len(l.Bandwidth); i++ {
		binary.BigEndian.PutUint32(b[:4], math.Float32bits(l.Bandwidth[i]))
		buf = append(buf, b[:]...)
	}

	return l.LsTLV.Serialize(buf)
}

func (l *LsTLVUnreservedBw) String() string {
	return fmt.Sprintf("{Unreserved BW: %v}", l.Bandwidth)
}

func (l *LsTLVUnreservedBw) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type      LsTLVType  `json:"type"`
		Bandwidth [8]float32 `json:"unreserved_bw"`
	}{
		Type:      l.Type,
		Bandwidth: l.Bandwidth,
	})
}

type LsTLVTEDefaultMetric struct {
	LsTLV
	Metric uint32
}

func (l *LsTLVTEDefaultMetric) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_TE_DEFAULT_METRIC {
		return malformedAttrListErr("Unexpected TLV type")
	}

	// https://tools.ietf.org/html/rfc7752#section-3.3.2.3
	if len(value) != 4 {
		return malformedAttrListErr("Incorrect metric length length")
	}

	l.Metric = binary.BigEndian.Uint32(value)

	return nil
}

func (l *LsTLVTEDefaultMetric) Serialize() ([]byte, error) {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:4], l.Metric)

	return l.LsTLV.Serialize(buf[:])
}

func (l *LsTLVTEDefaultMetric) String() string {
	return fmt.Sprintf("{TE Default metric: %d}", l.Metric)
}

func (l *LsTLVTEDefaultMetric) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type          LsTLVType `json:"type"`
		DefaultMetric uint32    `json:"te_default_metric"`
	}{
		Type:          l.Type,
		DefaultMetric: l.Metric,
	})
}

type LsTLVIGPMetric struct {
	LsTLV
	Metric uint32
}

func (l *LsTLVIGPMetric) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_IGP_METRIC {
		return malformedAttrListErr("Unexpected TLV type")
	}

	// https://tools.ietf.org/html/rfc7752#section-3.3.2.4
	switch len(value) {
	case 1:
		l.Metric = uint32(value[0] & 0x3F)

	case 2:
		l.Metric = uint32(binary.BigEndian.Uint16(value))

	case 3:
		l.Metric = binary.BigEndian.Uint32([]byte{0, value[0], value[1], value[2]})

	default:
		return malformedAttrListErr("Incorrect metric length")
	}

	return nil
}

func (l *LsTLVIGPMetric) Serialize() ([]byte, error) {
	switch l.Length {
	case 1:
		return l.LsTLV.Serialize([]byte{uint8(l.Metric) & 0x3F})

	case 2:
		var buf [2]byte
		binary.BigEndian.PutUint16(buf[:2], uint16(l.Metric))
		return l.LsTLV.Serialize(buf[:])

	case 3:
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:4], l.Metric)
		return l.LsTLV.Serialize(buf[1:])

	default:
		return nil, malformedAttrListErr("Incorrect metric length")
	}
}

func (l *LsTLVIGPMetric) String() string {
	return fmt.Sprintf("{IGP metric: %d}", l.Metric)
}

func (l *LsTLVIGPMetric) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type   LsTLVType `json:"type"`
		Metric uint32    `json:"igp_metric"`
	}{
		Type:   l.Type,
		Metric: l.Metric,
	})
}

type LsTLVLinkName struct {
	LsTLV
	Name string
}

func (l *LsTLVLinkName) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_LINK_NAME {
		return malformedAttrListErr("Unexpected TLV type")
	}

	// https://tools.ietf.org/html/rfc7752#section-3.3.2.7
	if len(value) < 1 || len(value) > 255 {
		return malformedAttrListErr("Incorrect Link Name")
	}

	l.Name = string(value)

	return nil
}

func (l *LsTLVLinkName) Serialize() ([]byte, error) {
	return l.LsTLV.Serialize([]byte(l.Name))
}

func (l *LsTLVLinkName) String() string {
	return fmt.Sprintf("{Link Name: %s}", l.Name)
}

func (l *LsTLVLinkName) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type LsTLVType `json:"type"`
		Name string    `json:"link_name"`
	}{
		Type: l.Type,
		Name: l.Name,
	})
}

type LsTLVSrAlgorithm struct {
	LsTLV
	Algorithm []byte
}

func (l *LsTLVSrAlgorithm) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_SR_ALGORITHM {
		return malformedAttrListErr("Unexpected TLV type")
	}

	if len(value) < 1 {
		return malformedAttrListErr("Incorrect SR algorithm length")
	}

	l.Algorithm = value

	return nil
}

func (l *LsTLVSrAlgorithm) Serialize() ([]byte, error) {
	return l.LsTLV.Serialize(l.Algorithm)
}

func (l *LsTLVSrAlgorithm) String() string {
	return fmt.Sprintf("{SR Algorithms: %v}", l.Algorithm)
}

func (l *LsTLVSrAlgorithm) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type       LsTLVType `json:"type"`
		Algorithms string    `json:"sr_algorithm"`
	}{
		Type:       l.Type,
		Algorithms: fmt.Sprintf("%v", l.Algorithm),
	})
}

type LsSrLabelRange struct {
	Range      uint32
	FirstLabel LsTLVSIDLabel
}

type LsTLVSrCapabilities struct {
	LsTLV
	Flags  uint8
	Ranges []LsSrLabelRange
}

type LsSrRange struct {
	Begin uint32 `json:"begin"`
	End   uint32 `json:"end"`
}

type LsSrCapabilities struct {
	IPv4Supported bool        `json:"ipv4_supported"`
	IPv6Supported bool        `json:"ipv6_supported"`
	Ranges        []LsSrRange `json:"ranges"`
}

func (l *LsTLVSrCapabilities) Extract() *LsSrCapabilities {
	lsc := &LsSrCapabilities{
		IPv4Supported: (l.Flags & (1 << 0)) > 0,
		IPv6Supported: (l.Flags & (1 << 1)) > 0,
	}

	for _, r := range l.Ranges {
		lsc.Ranges = append(lsc.Ranges, LsSrRange{
			Begin: r.FirstLabel.SID,
			End:   r.FirstLabel.SID + r.Range,
		})
	}

	return lsc
}

func (l *LsTLVSrCapabilities) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_SR_CAPABILITIES {
		return malformedAttrListErr("Unexpected TLV type")
	}

	if len(value) < 2 {
		return malformedAttrListErr("Incorrect SR Capabilities length")
	}
	l.Flags = value[0]

	// Skip two bytes: flags and reserved.
	value = value[2:]

	// The value field should be at least eight bytes long. Three bytes
	// for the range size and five or six bytes for the SID/Label TLV.
	for len(value) > 8 {
		// First, parse range size (3 bytes)
		buf := []byte{0, 0, 0, 0}
		for i := 1; i < len(buf); i++ {
			buf[i] = value[i-1]
		}
		r := binary.BigEndian.Uint32(buf)
		value = value[3:]

		// Second, parse SID/Label sub-TLV.
		label := LsTLVSIDLabel{}
		if err := label.DecodeFromBytes(value); err != nil {
			return err
		}

		l.Ranges = append(l.Ranges, LsSrLabelRange{
			Range:      r,
			FirstLabel: label,
		})

		value = value[label.Len():]
	}

	if len(value) > 0 {
		return malformedAttrListErr("Malformed SR Capabilities TLV")
	}

	return nil
}

func (l *LsTLVSrCapabilities) Serialize() ([]byte, error) {
	buf := make([]byte, 0)
	buf = append(buf, l.Flags)
	buf = append(buf, 0)
	var b [4]byte

	for _, r := range l.Ranges {
		binary.BigEndian.PutUint32(b[:4], r.Range)
		buf = append(buf, b[1:]...)
		ser, err := r.FirstLabel.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, ser...)
	}

	return l.LsTLV.Serialize(buf)
}

func (l *LsTLVSrCapabilities) String() string {
	var buf bytes.Buffer

	for _, r := range l.Ranges {
		buf.WriteString(fmt.Sprintf("%v:%v ", r.FirstLabel.SID, r.FirstLabel.SID+r.Range))
	}

	return fmt.Sprintf("{SR Capabilities: Flags:%v SRGB Ranges: %v}", l.Flags, buf.String())
}

func (l *LsTLVSrCapabilities) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type   LsTLVType        `json:"type"`
		Flags  uint8            `json:"flags"`
		Ranges []LsSrLabelRange `json:"ranges"`
	}{
		Type:   l.Type,
		Flags:  l.Flags,
		Ranges: l.Ranges,
	})
}

type LsTLVSrLocalBlock struct {
	LsTLV
	Flags  uint8
	Ranges []LsSrLabelRange
}

type LsSrLocalBlock struct {
	Ranges []LsSrRange `json:"ranges"`
}

func (l *LsTLVSrLocalBlock) Extract() *LsSrLocalBlock {
	lb := &LsSrLocalBlock{}

	for _, r := range l.Ranges {
		lb.Ranges = append(lb.Ranges, LsSrRange{
			Begin: r.FirstLabel.SID,
			End:   r.FirstLabel.SID + r.Range,
		})
	}

	return lb
}

func (l *LsTLVSrLocalBlock) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_SR_LOCAL_BLOCK {
		return malformedAttrListErr("Unexpected TLV type")
	}

	if len(value) < 2 {
		return malformedAttrListErr("Incorrect SR Local Block length")
	}
	l.Flags = value[0]

	// Skip two bytes: flags and reserved.
	value = value[2:]

	// The value field should be at least eight bytes long. Three bytes
	// for the range size and five or six bytes for the SID/Label TLV.
	for len(value) > 8 {
		// First, parse range size (3 bytes)
		buf := []byte{0, 0, 0, 0}
		for i := 1; i < len(buf); i++ {
			buf[i] = value[i-1]
		}
		r := binary.BigEndian.Uint32(buf)
		value = value[3:]

		// Second, parse SID/Label sub-TLV.
		label := LsTLVSIDLabel{}
		if err := label.DecodeFromBytes(value); err != nil {
			return err
		}

		l.Ranges = append(l.Ranges, LsSrLabelRange{
			Range:      r,
			FirstLabel: label,
		})

		value = value[label.Len():]
	}

	if len(value) > 0 {
		return malformedAttrListErr("Malformed SR Local Block TLV")
	}

	return nil
}

func (l *LsTLVSrLocalBlock) Serialize() ([]byte, error) {
	buf := make([]byte, 0)
	buf = append(buf, l.Flags)
	buf = append(buf, 0)
	var b [4]byte

	for _, r := range l.Ranges {
		binary.BigEndian.PutUint32(b[:4], r.Range)
		buf = append(buf, b[1:]...)
		ser, err := r.FirstLabel.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, ser...)
	}

	return l.LsTLV.Serialize(buf)
}

func (l *LsTLVSrLocalBlock) String() string {
	var buf bytes.Buffer

	for _, r := range l.Ranges {
		buf.WriteString(fmt.Sprintf("%v:%v ", r.FirstLabel.SID, r.FirstLabel.SID+r.Range))
	}

	return fmt.Sprintf("{SR LocalBlock: Flags:%v SRGB Ranges: %v}", l.Flags, buf.String())
}

func (l *LsTLVSrLocalBlock) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type   LsTLVType        `json:"type"`
		Flags  uint8            `json:"flags"`
		Ranges []LsSrLabelRange `json:"ranges"`
	}{
		Type:   l.Type,
		Flags:  l.Flags,
		Ranges: l.Ranges,
	})
}

type LsTLVAdjacencySID struct {
	LsTLV
	Flags  uint8
	Weight uint8
	SID    uint32
}

func (l *LsTLVAdjacencySID) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_ADJACENCY_SID {
		return malformedAttrListErr("Unexpected TLV type")
	}

	// https://tools.ietf.org/html/draft-ietf-idr-bgp-ls-segment-routing-ext-08#section-2.2.1
	if len(value) != 7 && len(value) != 8 {
		return malformedAttrListErr("Incorrect Adjacency SID length")
	}

	l.Flags = value[0]
	l.Weight = value[1]

	v := value[4:]
	if len(v) == 4 {
		l.SID = binary.BigEndian.Uint32(v)
	} else {
		buf := []byte{0, 0, 0, 0}
		for i := 1; i < len(buf); i++ {
			buf[i] = v[i-1]
		}
		// Label is represented by 20 rightmost bits.
		l.SID = binary.BigEndian.Uint32(buf) & 0xfffff
	}

	return nil
}

func (l *LsTLVAdjacencySID) Serialize() ([]byte, error) {
	buf := make([]byte, 0)
	buf = append(buf, l.Flags)
	buf = append(buf, l.Weight)
	// Reserved
	buf = append(buf, []byte{0, 0}...)

	var b [4]byte
	binary.BigEndian.PutUint32(b[:4], l.SID)

	if l.Length == 7 {
		return l.LsTLV.Serialize(append(buf, b[1:]...))
	}

	return l.LsTLV.Serialize(append(buf, b[:]...))
}

func (l *LsTLVAdjacencySID) String() string {
	return fmt.Sprintf("{Adjacency SID: %v}", l.SID)
}

func (l *LsTLVAdjacencySID) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type LsTLVType `json:"type"`
		SID  uint32    `json:"adjacency_sid"`
	}{
		Type: l.Type,
		SID:  l.SID,
	})
}

type LsTLVSIDLabel struct {
	LsTLV
	SID uint32
}

func (l *LsTLVSIDLabel) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_SID_LABEL_TLV {
		return malformedAttrListErr("Unexpected TLV type")
	}

	// https://tools.ietf.org/html/draft-ietf-idr-bgp-ls-segment-routing-ext-08#section-2.1.1
	if len(value) != 4 && len(value) != 3 {
		return malformedAttrListErr("Incorrect SID length")
	}

	if len(value) == 4 {
		l.SID = binary.BigEndian.Uint32(value)
	} else {
		buf := []byte{0, 0, 0, 0}
		for i := 1; i < len(buf); i++ {
			buf[i] = value[i-1]
		}
		// Label is represented by 20 rightmost bits.
		l.SID = binary.BigEndian.Uint32(buf) & 0xfffff
	}

	return nil
}

func (l *LsTLVSIDLabel) Serialize() ([]byte, error) {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:4], l.SID)

	if l.Length == 3 {
		return l.LsTLV.Serialize(buf[1:])
	}

	return l.LsTLV.Serialize(buf[:])
}

func (l *LsTLVSIDLabel) String() string {
	return fmt.Sprintf("{SID/Label: %v}", l.SID)
}

func (l *LsTLVSIDLabel) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type LsTLVType `json:"type"`
		SID  uint32    `json:"sid_label"`
	}{
		Type: l.Type,
		SID:  l.SID,
	})
}

type LsTLVPrefixSID struct {
	LsTLV
	Flags     uint8
	Algorithm uint8
	SID       uint32
}

func (l *LsTLVPrefixSID) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_PREFIX_SID {
		return malformedAttrListErr("Unexpected TLV type")
	}

	// https://tools.ietf.org/html/draft-ietf-idr-bgp-ls-segment-routing-ext-08#section-2.3.1
	if len(value) != 7 && len(value) != 8 {
		return malformedAttrListErr("Incorrect Prefix SID length")
	}

	l.Flags = value[0]
	l.Algorithm = value[1]

	// Flags (1) + Algorithm (1) + Reserved (2)
	v := value[4:]
	if len(v) == 4 {
		l.SID = binary.BigEndian.Uint32(v)
	} else {
		buf := []byte{0, 0, 0, 0}
		for i := 1; i < len(buf); i++ {
			buf[i] = v[i-1]
		}
		// Label is represented by 20 rightmost bits.
		l.SID = binary.BigEndian.Uint32(buf) & 0xfffff
	}

	return nil
}

func (l *LsTLVPrefixSID) Serialize() ([]byte, error) {
	buf := make([]byte, 0)
	buf = append(buf, l.Flags)
	buf = append(buf, l.Algorithm)
	// Reserved
	buf = append(buf, []byte{0, 0}...)

	var b [4]byte
	binary.BigEndian.PutUint32(b[:4], l.SID)

	if l.Length == 7 {
		return l.LsTLV.Serialize(append(buf, b[1:]...))
	}

	return l.LsTLV.Serialize(append(buf, b[:]...))
}

func (l *LsTLVPrefixSID) String() string {
	return fmt.Sprintf("{Prefix SID: %v}", l.SID)
}

func (l *LsTLVPrefixSID) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type LsTLVType `json:"type"`
		SID  uint32    `json:"prefix_sid"`
	}{
		Type: l.Type,
		SID:  l.SID,
	})
}

type LsTLVSourceRouterID struct {
	LsTLV
	RouterID []byte
}

func (l *LsTLVSourceRouterID) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_SOURCE_ROUTER_ID {
		return malformedAttrListErr("Unexpected TLV type")
	}

	// https://tools.ietf.org/html/draft-ietf-idr-bgp-ls-segment-routing-ext-08#section-2.3.3
	if len(value) != 4 && len(value) != 16 {
		return malformedAttrListErr("Incorrect Source Router ID length")
	}

	l.RouterID = value

	return nil
}

func (l *LsTLVSourceRouterID) Serialize() ([]byte, error) {
	return l.LsTLV.Serialize(l.RouterID)
}

func (l *LsTLVSourceRouterID) String() string {
	return fmt.Sprintf("{Source Router ID: %v}", net.IP(l.RouterID))
}

func (l *LsTLVSourceRouterID) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type     LsTLVType `json:"type"`
		RouterID string    `json:"source_router_id"`
	}{
		Type:     l.Type,
		RouterID: fmt.Sprintf("%v", net.IP(l.RouterID)),
	})
}

type LsTLVOpaqueLinkAttr struct {
	LsTLV
	Attr []byte
}

func (l *LsTLVOpaqueLinkAttr) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_OPAQUE_LINK_ATTR {
		return malformedAttrListErr("Unexpected TLV type")
	}

	l.Attr = value

	return nil
}

func (l *LsTLVOpaqueLinkAttr) Serialize() ([]byte, error) {
	return l.LsTLV.Serialize(l.Attr)
}

func (l *LsTLVOpaqueLinkAttr) String() string {
	return fmt.Sprintf("{Opaque link attribute: %v}", l.Attr)
}

func (l *LsTLVOpaqueLinkAttr) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  LsTLVType `json:"type"`
		Value string    `json:"link_opaque_attribute"`
	}{
		Type:  l.Type,
		Value: fmt.Sprintf("%v", l.Attr),
	})
}

type LsTLVSrlg struct {
	LsTLV
	Srlgs []uint32
}

func (l *LsTLVSrlg) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_SRLG {
		return malformedAttrListErr("Unexpected TLV type")
	}

	if len(value)%4 != 0 {
		return malformedAttrListErr("Incorrect SRLG length")
	}

	for len(value) > 0 {
		l.Srlgs = append(l.Srlgs, binary.BigEndian.Uint32(value[:4]))
		value = value[4:]
	}

	return nil
}

func (l *LsTLVSrlg) Serialize() ([]byte, error) {
	buf := make([]byte, 0, 4*len(l.Srlgs))

	var b [4]byte
	for i := 0; i < len(l.Srlgs); i++ {
		binary.BigEndian.PutUint32(b[:4], l.Srlgs[i])
		buf = append(buf, b[:]...)
	}

	return l.LsTLV.Serialize(buf)
}

func (l *LsTLVSrlg) String() string {
	return fmt.Sprintf("{SRLG link attribute: %d}", l.Srlgs)
}

func (l *LsTLVSrlg) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  LsTLVType `json:"type"`
		Value []uint32  `json:"link_srlg_attribute"`
	}{
		Type:  l.Type,
		Value: l.Srlgs,
	})
}

type LsTLVIGPFlags struct {
	LsTLV
	Flags uint8
}

// https://tools.ietf.org/html/rfc7752#section-3.3.3.1
type LsIGPFlags struct {
	Down          bool `json:"down"`
	NoUnicast     bool `json:"no_unicast"`
	LocalAddress  bool `json:"local_address"`
	PropagateNSSA bool `json:"propagate_nssa"`
}

func (l *LsTLVIGPFlags) Extract() *LsIGPFlags {
	return &LsIGPFlags{
		Down:          (l.Flags & (1 << 0)) > 0,
		NoUnicast:     (l.Flags & (1 << 1)) > 0,
		LocalAddress:  (l.Flags & (1 << 2)) > 0,
		PropagateNSSA: (l.Flags & (1 << 3)) > 0,
	}
}

func (l *LsTLVIGPFlags) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_IGP_FLAGS {
		return malformedAttrListErr("Unexpected TLV type")
	}

	if l.Length != 1 {
		return malformedAttrListErr("Node Flag Bits TLV malformed")
	}

	l.Flags = value[0]

	return nil
}

func (l *LsTLVIGPFlags) Serialize() ([]byte, error) {
	return l.LsTLV.Serialize([]byte{l.Flags})
}

func (l *LsTLVIGPFlags) String() string {
	flags := "XXXXPLND"

	var buf bytes.Buffer

	for i := 0; i < len(flags); i++ {
		if l.Flags&(1<<uint(i)) > 0 {
			buf.WriteString(flags[i : i+1])
		} else {
			buf.WriteString("*")
		}
	}

	return fmt.Sprintf("{IGP Flags: %s}", buf.String())
}

func (l *LsTLVIGPFlags) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  LsTLVType `json:"type"`
		Flags string    `json:"igp_flags"`
	}{
		Type:  l.Type,
		Flags: l.String(),
	})
}

type LsTLVOpaquePrefixAttr struct {
	LsTLV
	Attr []byte
}

func (l *LsTLVOpaquePrefixAttr) DecodeFromBytes(data []byte) error {
	value, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_OPAQUE_PREFIX_ATTR {
		return malformedAttrListErr("Unexpected TLV type")
	}

	l.Attr = value

	return nil
}

func (l *LsTLVOpaquePrefixAttr) Serialize() ([]byte, error) {
	return l.LsTLV.Serialize(l.Attr)
}

func (l *LsTLVOpaquePrefixAttr) String() string {
	return fmt.Sprintf("{Prefix opaque attribute: %v}", l.Attr)
}

func (l *LsTLVOpaquePrefixAttr) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  LsTLVType `json:"type"`
		Value string    `json:"prefix_opaque_attribute"`
	}{
		Type:  l.Type,
		Value: fmt.Sprintf("%v", l.Attr),
	})
}

type LsTLVNodeDescriptor struct {
	LsTLV
	SubTLVs []LsTLVInterface
}

func (l *LsTLVNodeDescriptor) DecodeFromBytes(data []byte) error {
	tlv, err := l.LsTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	if l.Type != LS_TLV_LOCAL_NODE_DESC && l.Type != LS_TLV_REMOTE_NODE_DESC {
		return malformedAttrListErr("Unexpected TLV type")
	}

	// RFC7752, 3.2.1.4
	// There can be at most one instance of each sub-TLV type present in
	// any Node Descriptor.  The sub-TLVs within a Node Descriptor MUST
	// be arranged in ascending order by sub-TLV type.
	prevType := uint16(0)
	m := make(map[LsTLVType]bool)

	for len(tlv) >= tlvHdrLen {
		sub := &LsTLV{}
		_, err := sub.DecodeFromBytes(tlv)
		if err != nil {
			return err
		}

		if uint16(sub.Type) < prevType {
			return malformedAttrListErr("Incorrect TLV order")
		}
		if _, ok := m[sub.Type]; ok {
			return malformedAttrListErr("Duplicate TLV")
		}
		prevType = uint16(sub.Type)
		m[sub.Type] = true

		var subTLV LsTLVInterface
		switch sub.Type {
		case LS_TLV_AS:
			subTLV = &LsTLVAutonomousSystem{}
		case LS_TLV_BGP_LS_ID:
			subTLV = &LsTLVBgpLsID{}
		case LS_TLV_OSPF_AREA:
			subTLV = &LsTLVOspfAreaID{}
		case LS_TLV_IGP_ROUTER_ID:
			subTLV = &LsTLVIgpRouterID{}

		default:
			tlv = tlv[sub.Len():]
			l.Length -= uint16(sub.Len())
			continue
		}

		if err := subTLV.DecodeFromBytes(tlv); err != nil {
			return err
		}
		l.SubTLVs = append(l.SubTLVs, subTLV)
		tlv = tlv[subTLV.Len():]
	}

	if _, ok := m[LS_TLV_IGP_ROUTER_ID]; !ok {
		return malformedAttrListErr("Required TLV missing")
	}

	return nil
}

func (l *LsTLVNodeDescriptor) Serialize() ([]byte, error) {
	buf := []byte{}
	for _, tlv := range l.SubTLVs {
		ser, err := tlv.Serialize()
		if err != nil {
			return nil, err
		}

		buf = append(buf, ser...)
	}

	return l.LsTLV.Serialize(buf)
}

func (l *LsTLVNodeDescriptor) String() string {
	nd := l.Extract()

	return fmt.Sprintf("{ASN: %v, BGP LS ID: %v, OSPF AREA: %v, IGP ROUTER ID: %v}", nd.Asn, nd.BGPLsID, nd.OspfAreaID, nd.IGPRouterID)
}

func (l *LsTLVNodeDescriptor) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type LsTLVType `json:"type"`
		LsNodeDescriptor
	}{
		l.Type,
		*l.Extract(),
	})
}

type LsNodeDescriptor struct {
	Asn         uint32 `json:"asn"`
	BGPLsID     uint32 `json:"bgp_ls_id"`
	OspfAreaID  uint32 `json:"ospf_area_id"`
	PseudoNode  bool   `json:"pseudo_node"`
	IGPRouterID string `json:"igp_router_id"`
}

func parseIGPRouterID(id []byte) (string, bool) {
	switch len(id) {
	// OSPF or OSPFv3 non-pseudonode
	case 4:
		return net.IP(id).String(), false

	// ISIS non-pseudonode
	case 6:
		return fmt.Sprintf("%0.2x%0.2x.%0.2x%0.2x.%0.2x%0.2x", id[0], id[1], id[2], id[3], id[4], id[5]), false

	// ISIS pseudonode
	case 7:
		return fmt.Sprintf("%0.2x%0.2x.%0.2x%0.2x.%0.2x%0.2x-%0.2x", id[0], id[1], id[2], id[3], id[4], id[5], id[6]), true

	// OSPF or OSPFv3 pseudonode
	case 8:
		return fmt.Sprintf("%v:%v", net.IP(id[:4]).String(), net.IP(id[4:]).String()), true

	default:
		return fmt.Sprintf("%v", id), false
	}
}

func (l *LsTLVNodeDescriptor) Extract() *LsNodeDescriptor {
	nd := &LsNodeDescriptor{}

	for _, tlv := range l.SubTLVs {
		switch v := tlv.(type) {
		case *LsTLVAutonomousSystem:
			nd.Asn = v.ASN
		case *LsTLVBgpLsID:
			nd.BGPLsID = v.BGPLsID
		case *LsTLVOspfAreaID:
			nd.OspfAreaID = v.AreaID
		case *LsTLVIgpRouterID:
			nd.IGPRouterID, nd.PseudoNode = parseIGPRouterID(v.RouterID)
		}
	}

	return nd
}

type LsAddrPrefix struct {
	PrefixDefault
	Type   LsNLRIType
	Length uint16
	NLRI   LsNLRIInterface
}

func (l *LsAddrPrefix) AFI() uint16 {
	return AFI_LS
}

func (l *LsAddrPrefix) SAFI() uint8 {
	return SAFI_LS
}

func (l *LsAddrPrefix) Len(...*MarshallingOption) int {
	return int(4 + l.Length)
}

func (l *LsAddrPrefix) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	if len(data) < 4 {
		return malformedAttrListErr("Malformed BGP-LS Address Prefix")
	}

	l.Type = LsNLRIType(binary.BigEndian.Uint16(data[:2]))
	l.Length = binary.BigEndian.Uint16(data[2:4])

	switch l.Type {
	case LS_NLRI_TYPE_NODE:
		node := &LsNodeNLRI{}
		node.Length = l.Length
		node.NLRIType = LS_NLRI_TYPE_NODE
		l.NLRI = node

	case LS_NLRI_TYPE_LINK:
		link := &LsLinkNLRI{}
		link.Length = l.Length
		link.NLRIType = LS_NLRI_TYPE_LINK
		l.NLRI = link

	case LS_NLRI_TYPE_PREFIX_IPV4:
		prefixv4 := &LsPrefixV4NLRI{}
		prefixv4.Length = l.Length
		prefixv4.NLRIType = LS_NLRI_TYPE_PREFIX_IPV4
		l.NLRI = prefixv4

	case LS_NLRI_TYPE_PREFIX_IPV6:
		prefixv6 := &LsPrefixV6NLRI{}
		prefixv6.Length = l.Length
		prefixv6.NLRIType = LS_NLRI_TYPE_PREFIX_IPV4
		l.NLRI = prefixv6

	default:
		return malformedAttrListErr("Unsupported BGP-LS NLRI")
	}

	if l.NLRI != nil {
		return l.NLRI.DecodeFromBytes(data[4:])
	}

	return nil
}

func (l *LsAddrPrefix) Serialize(options ...*MarshallingOption) ([]byte, error) {
	if l.NLRI == nil {
		return nil, errors.New("empty NLRI")
	}

	ser, err := l.NLRI.Serialize()
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 4+len(ser))
	binary.BigEndian.PutUint16(buf[:2], uint16(l.Type))
	binary.BigEndian.PutUint16(buf[2:], l.Length)
	copy(buf[4:], ser)

	return buf, nil
}

func (l *LsAddrPrefix) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type   LsNLRIType `json:"type"`
		Length uint16     `json:"length"`
		NLRI   string     `json:"nlri"`
	}{
		l.Type,
		l.Length,
		l.String(),
	})
}

func (l *LsAddrPrefix) String() string {
	if l.NLRI == nil {
		return "NLRI: (nil)"
	}

	return fmt.Sprintf("NLRI { %s }", l.NLRI.String())
}

func (l *LsAddrPrefix) Flat() map[string]string {
	return map[string]string{}
}

type LsAttributeNode struct {
	Flags           *LsNodeFlags `json:"flags,omitempty"`
	Opaque          *[]byte      `json:"opaque,omitempty"`
	Name            *string      `json:"name,omitempty"`
	IsisArea        *[]byte      `json:"isis_area,omitempty"`
	LocalRouterID   *net.IP      `json:"local_router_id_ipv4,omitempty"`
	LocalRouterIDv6 *net.IP      `json:"local_router_id_ipv6,omitempty"`

	// Segment Routing
	SrCapabilties *LsSrCapabilities `json:"sr_capabilities,omitempty"`
	SrAlgorithms  *[]byte           `json:"sr_algorithms,omitempty"`
	SrLocalBlock  *LsSrLocalBlock   `json:"sr_local_block,omitempty"`
}

type LsAttributeLink struct {
	Name             *string `json:"name,omitempty"`
	LocalRouterID    *net.IP `json:"local_router_id_ipv4,omitempty"`
	LocalRouterIDv6  *net.IP `json:"local_router_id_ipv6,omitempty"`
	RemoteRouterID   *net.IP `json:"remote_router_id_ipv4,omitempty"`
	RemoteRouterIDv6 *net.IP `json:"remote_router_id_ipv6,omitempty"`
	AdminGroup       *uint32 `json:"admin_group,omitempty"`
	DefaultTEMetric  *uint32 `json:"default_te_metric,omitempty"`
	IGPMetric        *uint32 `json:"igp_metric,omitempty"`
	Opaque           *[]byte `json:"opaque,omitempty"`

	// Bandwidth is expressed in bytes (not bits) per second.
	Bandwidth           *float32    `json:"bandwidth,omitempty"`
	ReservableBandwidth *float32    `json:"reservable_bandwidth,omitempty"`
	UnreservedBandwidth *[8]float32 `json:"unreserved_bandwidth,omitempty"`
	Srlgs               *[]uint32   `json:"srlgs,omitempty"`

	SrAdjacencySID *uint32 `json:"adjacency_sid,omitempty"`
}

type LsAttributePrefix struct {
	IGPFlags *LsIGPFlags `json:"igp_flags,omitempty"`
	Opaque   *[]byte     `json:"opaque,omitempty"`

	SrPrefixSID *uint32 `json:"sr_prefix_sid,omitempty"`
}

type LsAttribute struct {
	Node   LsAttributeNode   `json:"node"`
	Link   LsAttributeLink   `json:"link"`
	Prefix LsAttributePrefix `json:"prefix"`
}

type PathAttributeLs struct {
	PathAttribute
	TLVs []LsTLVInterface
}

func (p *PathAttributeLs) Extract() *LsAttribute {
	l := &LsAttribute{}

	for _, tlv := range p.TLVs {
		switch v := tlv.(type) {
		case *LsTLVNodeFlagBits:
			l.Node.Flags = v.Extract()

		case *LsTLVOpaqueNodeAttr:
			l.Node.Opaque = &v.Attr

		case *LsTLVNodeName:
			l.Node.Name = &v.Name

		case *LsTLVIsisArea:
			l.Node.IsisArea = &v.Area

		case *LsTLVLocalIPv4RouterID:
			l.Node.LocalRouterID = &v.IP
			l.Link.LocalRouterID = &v.IP

		case *LsTLVLocalIPv6RouterID:
			l.Node.LocalRouterIDv6 = &v.IP
			l.Link.LocalRouterIDv6 = &v.IP

		case *LsTLVSrCapabilities:
			l.Node.SrCapabilties = v.Extract()

		case *LsTLVSrAlgorithm:
			l.Node.SrAlgorithms = &v.Algorithm

		case *LsTLVSrLocalBlock:
			l.Node.SrLocalBlock = v.Extract()

		case *LsTLVRemoteIPv4RouterID:
			l.Link.RemoteRouterID = &v.IP

		case *LsTLVRemoteIPv6RouterID:
			l.Link.RemoteRouterIDv6 = &v.IP

		case *LsTLVAdminGroup:
			l.Link.AdminGroup = &v.AdminGroup

		case *LsTLVMaxLinkBw:
			l.Link.Bandwidth = &v.Bandwidth

		case *LsTLVMaxReservableLinkBw:
			l.Link.ReservableBandwidth = &v.Bandwidth

		case *LsTLVUnreservedBw:
			l.Link.UnreservedBandwidth = &v.Bandwidth

		case *LsTLVSrlg:
			l.Link.Srlgs = &v.Srlgs

		case *LsTLVTEDefaultMetric:
			l.Link.DefaultTEMetric = &v.Metric

		case *LsTLVIGPMetric:
			l.Link.IGPMetric = &v.Metric

		case *LsTLVOpaqueLinkAttr:
			l.Link.Opaque = &v.Attr

		case *LsTLVLinkName:
			l.Link.Name = &v.Name

		case *LsTLVAdjacencySID:
			l.Link.SrAdjacencySID = &v.SID

		case *LsTLVIGPFlags:
			l.Prefix.IGPFlags = v.Extract()

		case *LsTLVOpaquePrefixAttr:
			l.Prefix.Opaque = &v.Attr

		case *LsTLVPrefixSID:
			l.Prefix.SrPrefixSID = &v.SID
		}
	}

	return l
}

func (p *PathAttributeLs) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	tlvs, err := p.PathAttribute.DecodeFromBytes(data)
	if err != nil {
		return err
	}

	for len(tlvs) >= tlvHdrLen {
		t := &LsTLV{}
		_, err := t.DecodeFromBytes(tlvs)
		if err != nil {
			return err
		}

		var tlv LsTLVInterface
		switch t.Type {
		// Node NLRI-related TLVs (https://tools.ietf.org/html/rfc7752#section-3.3.1)
		case LS_TLV_NODE_FLAG_BITS:
			tlv = &LsTLVNodeFlagBits{}

		case LS_TLV_OPAQUE_NODE_ATTR:
			tlv = &LsTLVOpaqueNodeAttr{}

		case LS_TLV_NODE_NAME:
			tlv = &LsTLVNodeName{}

		case LS_TLV_ISIS_AREA:
			tlv = &LsTLVIsisArea{}

		// Used by Link NLRI as well.
		case LS_TLV_IPV4_LOCAL_ROUTER_ID:
			tlv = &LsTLVLocalIPv4RouterID{}

		// Used by Link NLRI as well.
		case LS_TLV_IPV6_LOCAL_ROUTER_ID:
			tlv = &LsTLVLocalIPv6RouterID{}

		// SR-related TLVs (draft-ietf-idr-bgp-ls-segment-routing-ext-08) for Node NLRI
		case LS_TLV_SR_CAPABILITIES:
			tlv = &LsTLVSrCapabilities{}

		case LS_TLV_SR_ALGORITHM:
			tlv = &LsTLVSrAlgorithm{}

		case LS_TLV_SR_LOCAL_BLOCK:
			tlv = &LsTLVSrLocalBlock{}

		// Link NLRI-related TLVs (https://tools.ietf.org/html/rfc7752#section-3.3.2)
		case LS_TLV_IPV4_REMOTE_ROUTER_ID:
			tlv = &LsTLVRemoteIPv4RouterID{}

		case LS_TLV_IPV6_REMOTE_ROUTER_ID:
			tlv = &LsTLVRemoteIPv6RouterID{}

		case LS_TLV_ADMIN_GROUP:
			tlv = &LsTLVAdminGroup{}

		case LS_TLV_MAX_LINK_BANDWIDTH:
			tlv = &LsTLVMaxLinkBw{}

		case LS_TLV_MAX_RESERVABLE_BANDWIDTH:
			tlv = &LsTLVMaxReservableLinkBw{}

		case LS_TLV_UNRESERVED_BANDWIDTH:
			tlv = &LsTLVUnreservedBw{}

		case LS_TLV_SRLG:
			tlv = &LsTLVSrlg{}

		case LS_TLV_TE_DEFAULT_METRIC:
			tlv = &LsTLVTEDefaultMetric{}

		case LS_TLV_IGP_METRIC:
			tlv = &LsTLVIGPMetric{}

		case LS_TLV_OPAQUE_LINK_ATTR:
			tlv = &LsTLVOpaqueLinkAttr{}

		case LS_TLV_LINK_NAME:
			tlv = &LsTLVLinkName{}

		// SR-related TLVs (draft-ietf-idr-bgp-ls-segment-routing-ext-08) for Link NLRI
		case LS_TLV_ADJACENCY_SID:
			tlv = &LsTLVAdjacencySID{}

		// Prefix NLRI-related TLVs (https://tools.ietf.org/html/rfc7752#section-3.3.3)
		case LS_TLV_IGP_FLAGS:
			tlv = &LsTLVIGPFlags{}

		case LS_TLV_OPAQUE_PREFIX_ATTR:
			tlv = &LsTLVOpaquePrefixAttr{}

		// SR-related TLVs (draft-ietf-idr-bgp-ls-segment-routing-ext-08) for Prefix NLRI
		case LS_TLV_PREFIX_SID:
			tlv = &LsTLVPrefixSID{}

		default:
			tlvs = tlvs[t.Len():]
			continue
		}

		if err := tlv.DecodeFromBytes(tlvs); err != nil {
			return err
		}
		tlvs = tlvs[t.Len():]

		p.TLVs = append(p.TLVs, tlv)
	}

	return nil
}

func (p *PathAttributeLs) Serialize(options ...*MarshallingOption) ([]byte, error) {
	buf := []byte{}

	for _, tlv := range p.TLVs {
		s, err := tlv.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, s...)
	}

	return p.PathAttribute.Serialize(buf, options...)
}

func (p *PathAttributeLs) String() string {
	var buf bytes.Buffer

	for _, tlv := range p.TLVs {
		buf.WriteString(fmt.Sprintf("%s ", tlv.String()))
	}

	return fmt.Sprintf("{LsAttributes: %s}", buf.String())
}

func (p *PathAttributeLs) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  BGPAttrType `json:"type"`
		Flags BGPAttrFlag `json:"flags"`
		LsAttribute
	}{
		p.GetType(),
		p.GetFlags(),
		*p.Extract(),
	})
}

func AfiSafiToRouteFamily(afi uint16, safi uint8) RouteFamily {
	return RouteFamily(int(afi)<<16 | int(safi))
}

func RouteFamilyToAfiSafi(rf RouteFamily) (uint16, uint8) {
	return uint16(int(rf) >> 16), uint8(int(rf) & 0xff)
}

type RouteFamily int

func (f RouteFamily) String() string {
	if n, y := AddressFamilyNameMap[f]; y {
		return n
	}
	return fmt.Sprintf("UnknownFamily(%d)", f)
}

const (
	RF_IPv4_UC        RouteFamily = AFI_IP<<16 | SAFI_UNICAST
	RF_IPv6_UC        RouteFamily = AFI_IP6<<16 | SAFI_UNICAST
	RF_IPv4_MC        RouteFamily = AFI_IP<<16 | SAFI_MULTICAST
	RF_IPv6_MC        RouteFamily = AFI_IP6<<16 | SAFI_MULTICAST
	RF_IPv4_VPN       RouteFamily = AFI_IP<<16 | SAFI_MPLS_VPN
	RF_IPv6_VPN       RouteFamily = AFI_IP6<<16 | SAFI_MPLS_VPN
	RF_IPv4_VPN_MC    RouteFamily = AFI_IP<<16 | SAFI_MPLS_VPN_MULTICAST
	RF_IPv6_VPN_MC    RouteFamily = AFI_IP6<<16 | SAFI_MPLS_VPN_MULTICAST
	RF_IPv4_MPLS      RouteFamily = AFI_IP<<16 | SAFI_MPLS_LABEL
	RF_IPv6_MPLS      RouteFamily = AFI_IP6<<16 | SAFI_MPLS_LABEL
	RF_VPLS           RouteFamily = AFI_L2VPN<<16 | SAFI_VPLS
	RF_EVPN           RouteFamily = AFI_L2VPN<<16 | SAFI_EVPN
	RF_RTC_UC         RouteFamily = AFI_IP<<16 | SAFI_ROUTE_TARGET_CONSTRAINTS
	RF_IPv4_ENCAP     RouteFamily = AFI_IP<<16 | SAFI_ENCAPSULATION
	RF_IPv6_ENCAP     RouteFamily = AFI_IP6<<16 | SAFI_ENCAPSULATION
	RF_FS_IPv4_UC     RouteFamily = AFI_IP<<16 | SAFI_FLOW_SPEC_UNICAST
	RF_FS_IPv4_VPN    RouteFamily = AFI_IP<<16 | SAFI_FLOW_SPEC_VPN
	RF_FS_IPv6_UC     RouteFamily = AFI_IP6<<16 | SAFI_FLOW_SPEC_UNICAST
	RF_FS_IPv6_VPN    RouteFamily = AFI_IP6<<16 | SAFI_FLOW_SPEC_VPN
	RF_FS_L2_VPN      RouteFamily = AFI_L2VPN<<16 | SAFI_FLOW_SPEC_VPN
	RF_OPAQUE         RouteFamily = AFI_OPAQUE<<16 | SAFI_KEY_VALUE
	RF_LS             RouteFamily = AFI_LS<<16 | SAFI_LS
	RF_SR_POLICY_IPv4 RouteFamily = AFI_IP<<16 | SAFI_SRPOLICY
	RF_SR_POLICY_IPv6 RouteFamily = AFI_IP6<<16 | SAFI_SRPOLICY
	RF_MUP_IPv4       RouteFamily = AFI_IP<<16 | SAFI_MUP
	RF_MUP_IPv6       RouteFamily = AFI_IP6<<16 | SAFI_MUP
)

var AddressFamilyNameMap = map[RouteFamily]string{
	RF_IPv4_UC:        "ipv4-unicast",
	RF_IPv6_UC:        "ipv6-unicast",
	RF_IPv4_MC:        "ipv4-multicast",
	RF_IPv6_MC:        "ipv6-multicast",
	RF_IPv4_MPLS:      "ipv4-labelled-unicast",
	RF_IPv6_MPLS:      "ipv6-labelled-unicast",
	RF_IPv4_VPN:       "l3vpn-ipv4-unicast",
	RF_IPv6_VPN:       "l3vpn-ipv6-unicast",
	RF_IPv4_VPN_MC:    "l3vpn-ipv4-multicast",
	RF_IPv6_VPN_MC:    "l3vpn-ipv6-multicast",
	RF_VPLS:           "l2vpn-vpls",
	RF_EVPN:           "l2vpn-evpn",
	RF_RTC_UC:         "rtc",
	RF_IPv4_ENCAP:     "ipv4-encap",
	RF_IPv6_ENCAP:     "ipv6-encap",
	RF_FS_IPv4_UC:     "ipv4-flowspec",
	RF_FS_IPv4_VPN:    "l3vpn-ipv4-flowspec",
	RF_FS_IPv6_UC:     "ipv6-flowspec",
	RF_FS_IPv6_VPN:    "l3vpn-ipv6-flowspec",
	RF_FS_L2_VPN:      "l2vpn-flowspec",
	RF_OPAQUE:         "opaque",
	RF_LS:             "ls",
	RF_SR_POLICY_IPv4: "ipv4-srpolicy",
	RF_SR_POLICY_IPv6: "ipv6-srpolicy",
	RF_MUP_IPv4:       "ipv4-mup",
	RF_MUP_IPv6:       "ipv6-mup",
}

var AddressFamilyValueMap = map[string]RouteFamily{
	AddressFamilyNameMap[RF_IPv4_UC]:        RF_IPv4_UC,
	AddressFamilyNameMap[RF_IPv6_UC]:        RF_IPv6_UC,
	AddressFamilyNameMap[RF_IPv4_MC]:        RF_IPv4_MC,
	AddressFamilyNameMap[RF_IPv6_MC]:        RF_IPv6_MC,
	AddressFamilyNameMap[RF_IPv4_MPLS]:      RF_IPv4_MPLS,
	AddressFamilyNameMap[RF_IPv6_MPLS]:      RF_IPv6_MPLS,
	AddressFamilyNameMap[RF_IPv4_VPN]:       RF_IPv4_VPN,
	AddressFamilyNameMap[RF_IPv6_VPN]:       RF_IPv6_VPN,
	AddressFamilyNameMap[RF_IPv4_VPN_MC]:    RF_IPv4_VPN_MC,
	AddressFamilyNameMap[RF_IPv6_VPN_MC]:    RF_IPv6_VPN_MC,
	AddressFamilyNameMap[RF_VPLS]:           RF_VPLS,
	AddressFamilyNameMap[RF_EVPN]:           RF_EVPN,
	AddressFamilyNameMap[RF_RTC_UC]:         RF_RTC_UC,
	AddressFamilyNameMap[RF_IPv4_ENCAP]:     RF_IPv4_ENCAP,
	AddressFamilyNameMap[RF_IPv6_ENCAP]:     RF_IPv6_ENCAP,
	AddressFamilyNameMap[RF_FS_IPv4_UC]:     RF_FS_IPv4_UC,
	AddressFamilyNameMap[RF_FS_IPv4_VPN]:    RF_FS_IPv4_VPN,
	AddressFamilyNameMap[RF_FS_IPv6_UC]:     RF_FS_IPv6_UC,
	AddressFamilyNameMap[RF_FS_IPv6_VPN]:    RF_FS_IPv6_VPN,
	AddressFamilyNameMap[RF_FS_L2_VPN]:      RF_FS_L2_VPN,
	AddressFamilyNameMap[RF_OPAQUE]:         RF_OPAQUE,
	AddressFamilyNameMap[RF_LS]:             RF_LS,
	AddressFamilyNameMap[RF_SR_POLICY_IPv4]: RF_SR_POLICY_IPv4,
	AddressFamilyNameMap[RF_SR_POLICY_IPv6]: RF_SR_POLICY_IPv6,
	AddressFamilyNameMap[RF_MUP_IPv4]:       RF_MUP_IPv4,
	AddressFamilyNameMap[RF_MUP_IPv6]:       RF_MUP_IPv6,
}

func GetRouteFamily(name string) (RouteFamily, error) {
	if v, ok := AddressFamilyValueMap[name]; ok {
		return v, nil
	}
	return RouteFamily(0), fmt.Errorf("%s isn't a valid route family name", name)
}

func NewPrefixFromRouteFamily(afi uint16, safi uint8, prefixStr ...string) (prefix AddrPrefixInterface, err error) {
	family := AfiSafiToRouteFamily(afi, safi)

	f := func(s string) AddrPrefixInterface {
		addr, net, _ := net.ParseCIDR(s)
		len, _ := net.Mask.Size()
		switch family {
		case RF_IPv4_UC, RF_IPv4_MC:
			return NewIPAddrPrefix(uint8(len), addr.String())
		}
		return NewIPv6AddrPrefix(uint8(len), addr.String())
	}

	switch family {
	case RF_IPv4_UC, RF_IPv4_MC:
		if len(prefixStr) > 0 {
			prefix = f(prefixStr[0])
		} else {
			prefix = NewIPAddrPrefix(0, "")
		}
	case RF_IPv6_UC, RF_IPv6_MC:
		if len(prefixStr) > 0 {
			prefix = f(prefixStr[0])
		} else {
			prefix = NewIPv6AddrPrefix(0, "")
		}
	case RF_IPv4_VPN:
		prefix = NewLabeledVPNIPAddrPrefix(0, "", *NewMPLSLabelStack(), nil)
	case RF_IPv6_VPN:
		prefix = NewLabeledVPNIPv6AddrPrefix(0, "", *NewMPLSLabelStack(), nil)
	case RF_IPv4_MPLS:
		prefix = NewLabeledIPAddrPrefix(0, "", *NewMPLSLabelStack())
	case RF_IPv6_MPLS:
		prefix = NewLabeledIPv6AddrPrefix(0, "", *NewMPLSLabelStack())
	case RF_EVPN:
		prefix = NewEVPNNLRI(0, nil)

	// TODO (sbezverk) Add processing SR Policy NLRI
	case RF_SR_POLICY_IPv4:
		prefix = &SRPolicyIPv4{
			SRPolicyNLRI: SRPolicyNLRI{
				rf: RF_SR_POLICY_IPv4,
			},
		}
	case RF_SR_POLICY_IPv6:
		prefix = &SRPolicyIPv6{
			SRPolicyNLRI: SRPolicyNLRI{
				rf: RF_SR_POLICY_IPv6,
			},
		}
	case RF_RTC_UC:
		prefix = &RouteTargetMembershipNLRI{}
	case RF_IPv4_ENCAP:
		prefix = NewEncapNLRI("")
	case RF_IPv6_ENCAP:
		prefix = NewEncapv6NLRI("")
	case RF_FS_IPv4_UC:
		prefix = &FlowSpecIPv4Unicast{FlowSpecNLRI{rf: RF_FS_IPv4_UC}}
	case RF_FS_IPv4_VPN:
		prefix = &FlowSpecIPv4VPN{FlowSpecNLRI{rf: RF_FS_IPv4_VPN}}
	case RF_FS_IPv6_UC:
		prefix = &FlowSpecIPv6Unicast{FlowSpecNLRI{rf: RF_FS_IPv6_UC}}
	case RF_FS_IPv6_VPN:
		prefix = &FlowSpecIPv6VPN{FlowSpecNLRI{rf: RF_FS_IPv6_VPN}}
	case RF_FS_L2_VPN:
		prefix = &FlowSpecL2VPN{FlowSpecNLRI{rf: RF_FS_L2_VPN}}
	case RF_OPAQUE:
		prefix = &OpaqueNLRI{}
	case RF_LS:
		prefix = &LsAddrPrefix{}
	case RF_MUP_IPv4:
		prefix = NewMUPNLRI(0, 0, nil)
	case RF_MUP_IPv6:
		prefix = NewMUPNLRI(0, 0, nil)
	default:
		err = fmt.Errorf("unknown route family. AFI: %d, SAFI: %d", afi, safi)
	}
	return prefix, err
}

type BGPAttrFlag uint8

const (
	BGP_ATTR_FLAG_EXTENDED_LENGTH BGPAttrFlag = 1 << 4
	BGP_ATTR_FLAG_PARTIAL         BGPAttrFlag = 1 << 5
	BGP_ATTR_FLAG_TRANSITIVE      BGPAttrFlag = 1 << 6
	BGP_ATTR_FLAG_OPTIONAL        BGPAttrFlag = 1 << 7
)

func (f BGPAttrFlag) String() string {
	strs := make([]string, 0, 4)
	if f&BGP_ATTR_FLAG_EXTENDED_LENGTH > 0 {
		strs = append(strs, "EXTENDED_LENGTH")
	}
	if f&BGP_ATTR_FLAG_PARTIAL > 0 {
		strs = append(strs, "PARTIAL")
	}
	if f&BGP_ATTR_FLAG_TRANSITIVE > 0 {
		strs = append(strs, "TRANSITIVE")
	}
	if f&BGP_ATTR_FLAG_OPTIONAL > 0 {
		strs = append(strs, "OPTIONAL")
	}
	return strings.Join(strs, "|")
}

//go:generate stringer -type=BGPAttrType
type BGPAttrType uint8

const (
	_ BGPAttrType = iota
	BGP_ATTR_TYPE_ORIGIN
	BGP_ATTR_TYPE_AS_PATH
	BGP_ATTR_TYPE_NEXT_HOP
	BGP_ATTR_TYPE_MULTI_EXIT_DISC
	BGP_ATTR_TYPE_LOCAL_PREF
	BGP_ATTR_TYPE_ATOMIC_AGGREGATE
	BGP_ATTR_TYPE_AGGREGATOR
	BGP_ATTR_TYPE_COMMUNITIES
	BGP_ATTR_TYPE_ORIGINATOR_ID
	BGP_ATTR_TYPE_CLUSTER_LIST
	_
	_
	_
	BGP_ATTR_TYPE_MP_REACH_NLRI // = 14
	BGP_ATTR_TYPE_MP_UNREACH_NLRI
	BGP_ATTR_TYPE_EXTENDED_COMMUNITIES
	BGP_ATTR_TYPE_AS4_PATH
	BGP_ATTR_TYPE_AS4_AGGREGATOR
	_
	_
	_
	BGP_ATTR_TYPE_PMSI_TUNNEL // = 22
	BGP_ATTR_TYPE_TUNNEL_ENCAP
	_
	BGP_ATTR_TYPE_IP6_EXTENDED_COMMUNITIES // = 25
	BGP_ATTR_TYPE_AIGP                     // = 26
	_
	_
	BGP_ATTR_TYPE_LS                          // = 29
	BGP_ATTR_TYPE_LARGE_COMMUNITY BGPAttrType = 32
	BGP_ATTR_TYPE_PREFIX_SID      BGPAttrType = 40
)

// NOTIFICATION Error Code  RFC 4271 4.5.
const (
	_ = iota
	BGP_ERROR_MESSAGE_HEADER_ERROR
	BGP_ERROR_OPEN_MESSAGE_ERROR
	BGP_ERROR_UPDATE_MESSAGE_ERROR
	BGP_ERROR_HOLD_TIMER_EXPIRED
	BGP_ERROR_FSM_ERROR
	BGP_ERROR_CEASE
	BGP_ERROR_ROUTE_REFRESH_MESSAGE_ERROR
)

// NOTIFICATION Error Subcode for BGP_ERROR_MESSAGE_HEADER_ERROR
const (
	_ = iota
	BGP_ERROR_SUB_CONNECTION_NOT_SYNCHRONIZED
	BGP_ERROR_SUB_BAD_MESSAGE_LENGTH
	BGP_ERROR_SUB_BAD_MESSAGE_TYPE
)

// NOTIFICATION Error Subcode for BGP_ERROR_OPEN_MESSAGE_ERROR
const (
	_ = iota
	BGP_ERROR_SUB_UNSUPPORTED_VERSION_NUMBER
	BGP_ERROR_SUB_BAD_PEER_AS
	BGP_ERROR_SUB_BAD_BGP_IDENTIFIER
	BGP_ERROR_SUB_UNSUPPORTED_OPTIONAL_PARAMETER
	BGP_ERROR_SUB_DEPRECATED_AUTHENTICATION_FAILURE
	BGP_ERROR_SUB_UNACCEPTABLE_HOLD_TIME
	BGP_ERROR_SUB_UNSUPPORTED_CAPABILITY
)

// NOTIFICATION Error Subcode for BGP_ERROR_UPDATE_MESSAGE_ERROR
const (
	_ = iota
	BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST
	BGP_ERROR_SUB_UNRECOGNIZED_WELL_KNOWN_ATTRIBUTE
	BGP_ERROR_SUB_MISSING_WELL_KNOWN_ATTRIBUTE
	BGP_ERROR_SUB_ATTRIBUTE_FLAGS_ERROR
	BGP_ERROR_SUB_ATTRIBUTE_LENGTH_ERROR
	BGP_ERROR_SUB_INVALID_ORIGIN_ATTRIBUTE
	BGP_ERROR_SUB_DEPRECATED_ROUTING_LOOP
	BGP_ERROR_SUB_INVALID_NEXT_HOP_ATTRIBUTE
	BGP_ERROR_SUB_OPTIONAL_ATTRIBUTE_ERROR
	BGP_ERROR_SUB_INVALID_NETWORK_FIELD
	BGP_ERROR_SUB_MALFORMED_AS_PATH
)

// NOTIFICATION Error Subcode for BGP_ERROR_HOLD_TIMER_EXPIRED
const (
	_ = iota
	BGP_ERROR_SUB_HOLD_TIMER_EXPIRED
)

// NOTIFICATION Error Subcode for BGP_ERROR_FSM_ERROR
const (
	_ = iota
	BGP_ERROR_SUB_RECEIVE_UNEXPECTED_MESSAGE_IN_OPENSENT_STATE
	BGP_ERROR_SUB_RECEIVE_UNEXPECTED_MESSAGE_IN_OPENCONFIRM_STATE
	BGP_ERROR_SUB_RECEIVE_UNEXPECTED_MESSAGE_IN_ESTABLISHED_STATE
)

// NOTIFICATION Error Subcode for BGP_ERROR_CEASE  (RFC 4486)
const (
	_ = iota
	BGP_ERROR_SUB_MAXIMUM_NUMBER_OF_PREFIXES_REACHED
	BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN
	BGP_ERROR_SUB_PEER_DECONFIGURED
	BGP_ERROR_SUB_ADMINISTRATIVE_RESET
	BGP_ERROR_SUB_CONNECTION_REJECTED
	BGP_ERROR_SUB_OTHER_CONFIGURATION_CHANGE
	BGP_ERROR_SUB_CONNECTION_COLLISION_RESOLUTION
	BGP_ERROR_SUB_OUT_OF_RESOURCES
	BGP_ERROR_SUB_HARD_RESET //draft-ietf-idr-bgp-gr-notification-07
)

// Constants for BGP_ERROR_SUB_ADMINISTRATIVE_SHUTDOWN and BGP_ERROR_SUB_ADMINISTRATIVE_RESET
const (
	BGP_ERROR_ADMINISTRATIVE_COMMUNICATION_MAX = 128
)

// NOTIFICATION Error Subcode for BGP_ERROR_ROUTE_REFRESH
const (
	_ = iota
	BGP_ERROR_SUB_INVALID_MESSAGE_LENGTH
)

type NotificationErrorCode uint16

func (c NotificationErrorCode) String() string {
	code := uint8(uint16(c) >> 8)
	subcode := uint8(uint16(c) & 0xff)
	UNDEFINED := "undefined"
	codeStr := UNDEFINED
	subcodeList := []string{}
	switch code {
	case BGP_ERROR_MESSAGE_HEADER_ERROR:
		codeStr = "header"
		subcodeList = []string{
			UNDEFINED,
			"connection not synchronized",
			"bad message length",
			"bad message type"}
	case BGP_ERROR_OPEN_MESSAGE_ERROR:
		codeStr = "open"
		subcodeList = []string{
			UNDEFINED,
			"unsupported version number",
			"bad peer as",
			"bad bgp identifier",
			"unsupported optional parameter",
			"deprecated authentication failure",
			"unacceptable hold time",
			"unsupported capability"}
	case BGP_ERROR_UPDATE_MESSAGE_ERROR:
		codeStr = "update"
		subcodeList = []string{
			UNDEFINED,
			"malformed attribute list",
			"unrecognized well known attribute",
			"missing well known attribute",
			"attribute flags error",
			"attribute length error",
			"invalid origin attribute",
			"deprecated routing loop",
			"invalid next hop attribute",
			"optional attribute error",
			"invalid network field",
			"sub malformed as path"}
	case BGP_ERROR_HOLD_TIMER_EXPIRED:
		codeStr = "hold timer expired"
		subcodeList = []string{
			UNDEFINED,
			"hold timer expired"}
	case BGP_ERROR_FSM_ERROR:
		codeStr = "fsm"
		subcodeList = []string{
			UNDEFINED,
			"receive unexpected message in opensent state",
			"receive unexpected message in openconfirm state",
			"receive unexpected message in established state"}
	case BGP_ERROR_CEASE:
		codeStr = "cease"
		subcodeList = []string{
			UNDEFINED,
			"maximum number of prefixes reached",
			"administrative shutdown",
			"peer deconfigured",
			"administrative reset",
			"connection rejected",
			"other configuration change",
			"connection collision resolution",
			"out of resources"}
	case BGP_ERROR_ROUTE_REFRESH_MESSAGE_ERROR:
		codeStr = "route refresh"
		subcodeList = []string{"invalid message length"}
	}
	subcodeStr := func(idx uint8, l []string) string {
		if len(l) == 0 || int(idx) > len(l)-1 {
			return UNDEFINED
		}
		return l[idx]
	}(subcode, subcodeList)
	return fmt.Sprintf("code %v(%v) subcode %v(%v)", code, codeStr, subcode, subcodeStr)
}

func NewNotificationErrorCode(code, subcode uint8) NotificationErrorCode {
	return NotificationErrorCode(uint16(code)<<8 | uint16(subcode))
}

var PathAttrFlags map[BGPAttrType]BGPAttrFlag = map[BGPAttrType]BGPAttrFlag{
	BGP_ATTR_TYPE_ORIGIN:                   BGP_ATTR_FLAG_TRANSITIVE,
	BGP_ATTR_TYPE_AS_PATH:                  BGP_ATTR_FLAG_TRANSITIVE,
	BGP_ATTR_TYPE_NEXT_HOP:                 BGP_ATTR_FLAG_TRANSITIVE,
	BGP_ATTR_TYPE_MULTI_EXIT_DISC:          BGP_ATTR_FLAG_OPTIONAL,
	BGP_ATTR_TYPE_LOCAL_PREF:               BGP_ATTR_FLAG_TRANSITIVE,
	BGP_ATTR_TYPE_ATOMIC_AGGREGATE:         BGP_ATTR_FLAG_TRANSITIVE,
	BGP_ATTR_TYPE_AGGREGATOR:               BGP_ATTR_FLAG_TRANSITIVE | BGP_ATTR_FLAG_OPTIONAL,
	BGP_ATTR_TYPE_COMMUNITIES:              BGP_ATTR_FLAG_TRANSITIVE | BGP_ATTR_FLAG_OPTIONAL,
	BGP_ATTR_TYPE_ORIGINATOR_ID:            BGP_ATTR_FLAG_OPTIONAL,
	BGP_ATTR_TYPE_CLUSTER_LIST:             BGP_ATTR_FLAG_OPTIONAL,
	BGP_ATTR_TYPE_MP_REACH_NLRI:            BGP_ATTR_FLAG_OPTIONAL,
	BGP_ATTR_TYPE_MP_UNREACH_NLRI:          BGP_ATTR_FLAG_OPTIONAL,
	BGP_ATTR_TYPE_EXTENDED_COMMUNITIES:     BGP_ATTR_FLAG_TRANSITIVE | BGP_ATTR_FLAG_OPTIONAL,
	BGP_ATTR_TYPE_AS4_PATH:                 BGP_ATTR_FLAG_TRANSITIVE | BGP_ATTR_FLAG_OPTIONAL,
	BGP_ATTR_TYPE_AS4_AGGREGATOR:           BGP_ATTR_FLAG_TRANSITIVE | BGP_ATTR_FLAG_OPTIONAL,
	BGP_ATTR_TYPE_PMSI_TUNNEL:              BGP_ATTR_FLAG_TRANSITIVE | BGP_ATTR_FLAG_OPTIONAL,
	BGP_ATTR_TYPE_TUNNEL_ENCAP:             BGP_ATTR_FLAG_TRANSITIVE | BGP_ATTR_FLAG_OPTIONAL,
	BGP_ATTR_TYPE_IP6_EXTENDED_COMMUNITIES: BGP_ATTR_FLAG_TRANSITIVE | BGP_ATTR_FLAG_OPTIONAL,
	BGP_ATTR_TYPE_AIGP:                     BGP_ATTR_FLAG_OPTIONAL,
	BGP_ATTR_TYPE_LARGE_COMMUNITY:          BGP_ATTR_FLAG_TRANSITIVE | BGP_ATTR_FLAG_OPTIONAL,
	BGP_ATTR_TYPE_LS:                       BGP_ATTR_FLAG_OPTIONAL,
	BGP_ATTR_TYPE_PREFIX_SID:               BGP_ATTR_FLAG_TRANSITIVE | BGP_ATTR_FLAG_OPTIONAL,
}

// getPathAttrFlags returns BGP Path Attribute flags value from its type and
// length (byte length of value field).
func getPathAttrFlags(typ BGPAttrType, length int) BGPAttrFlag {
	flags := PathAttrFlags[typ]
	if length > 255 {
		flags |= BGP_ATTR_FLAG_EXTENDED_LENGTH
	}
	return flags
}

type PathAttributeInterface interface {
	DecodeFromBytes([]byte, ...*MarshallingOption) error
	Serialize(...*MarshallingOption) ([]byte, error)
	Len(...*MarshallingOption) int
	GetFlags() BGPAttrFlag
	GetType() BGPAttrType
	String() string
	MarshalJSON() ([]byte, error)
	Flat() map[string]string
}

type PathAttribute struct {
	Flags  BGPAttrFlag
	Type   BGPAttrType
	Length uint16 // length of Value
}

func (p *PathAttribute) Len(options ...*MarshallingOption) int {
	if p.Flags&BGP_ATTR_FLAG_EXTENDED_LENGTH != 0 {
		return 4 + int(p.Length)
	}
	return 3 + int(p.Length)
}

func (p *PathAttribute) GetFlags() BGPAttrFlag {
	return p.Flags
}

func (p *PathAttribute) GetType() BGPAttrType {
	return p.Type
}

func (p *PathAttribute) DecodeFromBytes(data []byte, options ...*MarshallingOption) (value []byte, err error) {
	eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
	eSubCode := uint8(BGP_ERROR_SUB_ATTRIBUTE_LENGTH_ERROR)
	if len(data) < 2 {
		return nil, NewMessageError(eCode, eSubCode, data, "attribute header length is short")
	}
	p.Flags = BGPAttrFlag(data[0])
	p.Type = BGPAttrType(data[1])
	if eMsg := validatePathAttributeFlags(p.Type, p.Flags); eMsg != "" {
		return nil, NewMessageError(eCode, BGP_ERROR_SUB_ATTRIBUTE_FLAGS_ERROR, data, eMsg)
	}

	if p.Flags&BGP_ATTR_FLAG_EXTENDED_LENGTH != 0 {
		if len(data) < 4 {
			return nil, NewMessageError(eCode, eSubCode, data, "attribute header length is short")
		}
		p.Length = binary.BigEndian.Uint16(data[2:4])
		data = data[4:]
	} else {
		if len(data) < 3 {
			return nil, NewMessageError(eCode, eSubCode, data, "attribute header length is short")
		}
		p.Length = uint16(data[2])
		data = data[3:]
	}
	if len(data) < int(p.Length) {
		return nil, NewMessageError(eCode, eSubCode, data, "attribute value length is short")
	}

	return data[:p.Length], nil
}

func (p *PathAttribute) Serialize(value []byte, options ...*MarshallingOption) ([]byte, error) {
	// Note: Do not update "p.Flags" and "p.Length" to avoid data race.
	flags := p.Flags
	length := uint16(len(value))
	if flags&BGP_ATTR_FLAG_EXTENDED_LENGTH == 0 && length > 255 {
		flags |= BGP_ATTR_FLAG_EXTENDED_LENGTH
	}
	var buf []byte
	if flags&BGP_ATTR_FLAG_EXTENDED_LENGTH != 0 {
		buf = append(make([]byte, 4), value...)
		binary.BigEndian.PutUint16(buf[2:4], length)
	} else {
		buf = append(make([]byte, 3), value...)
		buf[2] = byte(length)
	}
	buf[0] = uint8(flags)
	buf[1] = uint8(p.Type)
	return buf, nil
}

type PathAttributeOrigin struct {
	PathAttribute
	Value uint8
}

func (p *PathAttributeOrigin) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	value, err := p.PathAttribute.DecodeFromBytes(data, options...)
	if err != nil {
		return err
	}
	if p.Length != 1 {
		eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
		eSubCode := uint8(BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST)
		return NewMessageError(eCode, eSubCode, nil, "Origin attribute length is incorrect")
	}
	p.Value = value[0]
	return nil
}

func (p *PathAttributeOrigin) Serialize(options ...*MarshallingOption) ([]byte, error) {
	return p.PathAttribute.Serialize([]byte{p.Value}, options...)
}

func (p *PathAttributeOrigin) String() string {
	typ := "-"
	switch p.Value {
	case BGP_ORIGIN_ATTR_TYPE_IGP:
		typ = "i"
	case BGP_ORIGIN_ATTR_TYPE_EGP:
		typ = "e"
	case BGP_ORIGIN_ATTR_TYPE_INCOMPLETE:
		typ = "?"
	}
	return fmt.Sprintf("{Origin: %s}", typ)
}

func (p *PathAttributeOrigin) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  BGPAttrType `json:"type"`
		Value uint8       `json:"value"`
	}{
		Type:  p.GetType(),
		Value: p.Value,
	})
}

func NewPathAttributeOrigin(value uint8) *PathAttributeOrigin {
	t := BGP_ATTR_TYPE_ORIGIN
	return &PathAttributeOrigin{
		PathAttribute: PathAttribute{
			Flags:  PathAttrFlags[t],
			Type:   t,
			Length: 1,
		},
		Value: value,
	}
}

type AsPathParamFormat struct {
	start     string
	end       string
	separator string
}

var asPathParamFormatMap = map[uint8]*AsPathParamFormat{
	BGP_ASPATH_ATTR_TYPE_SET:        {"{", "}", ","},
	BGP_ASPATH_ATTR_TYPE_SEQ:        {"", "", " "},
	BGP_ASPATH_ATTR_TYPE_CONFED_SET: {"(", ")", " "},
	BGP_ASPATH_ATTR_TYPE_CONFED_SEQ: {"[", "]", ","},
}

type AsPathParamInterface interface {
	GetType() uint8
	GetAS() []uint32
	Serialize() ([]byte, error)
	DecodeFromBytes([]byte) error
	Len() int
	ASLen() int
	MarshalJSON() ([]byte, error)
	String() string
}

func AsPathString(aspath *PathAttributeAsPath) string {
	s := bytes.NewBuffer(make([]byte, 0, 64))
	for i, param := range aspath.Value {
		segType := param.GetType()
		asList := param.GetAS()
		if i != 0 {
			s.WriteString(" ")
		}

		sep := " "
		switch segType {
		case BGP_ASPATH_ATTR_TYPE_CONFED_SEQ:
			s.WriteString("(")
		case BGP_ASPATH_ATTR_TYPE_CONFED_SET:
			s.WriteString("[")
			sep = ","
		case BGP_ASPATH_ATTR_TYPE_SET:
			s.WriteString("{")
			sep = ","
		}
		for j, as := range asList {
			s.WriteString(fmt.Sprintf("%d", as))
			if j != len(asList)-1 {
				s.WriteString(sep)
			}
		}
		switch segType {
		case BGP_ASPATH_ATTR_TYPE_CONFED_SEQ:
			s.WriteString(")")
		case BGP_ASPATH_ATTR_TYPE_CONFED_SET:
			s.WriteString("]")
		case BGP_ASPATH_ATTR_TYPE_SET:
			s.WriteString("}")
		}
	}
	return s.String()
}

type AsPathParam struct {
	Type uint8
	Num  uint8
	AS   []uint16
}

func (a *AsPathParam) GetType() uint8 {
	return a.Type
}

func (a *AsPathParam) GetAS() []uint32 {
	nums := make([]uint32, 0, len(a.AS))
	for _, as := range a.AS {
		nums = append(nums, uint32(as))
	}
	return nums
}

func (a *AsPathParam) Serialize() ([]byte, error) {
	buf := make([]byte, 2+len(a.AS)*2)
	buf[0] = uint8(a.Type)
	buf[1] = a.Num
	for j, as := range a.AS {
		binary.BigEndian.PutUint16(buf[2+j*2:], as)
	}
	return buf, nil
}

func (a *AsPathParam) DecodeFromBytes(data []byte) error {
	eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
	eSubCode := uint8(BGP_ERROR_SUB_MALFORMED_AS_PATH)
	if len(data) < 2 {
		return NewMessageError(eCode, eSubCode, nil, "AS param header length is short")
	}
	a.Type = data[0]
	a.Num = data[1]
	data = data[2:]
	if len(data) < int(a.Num*2) {
		return NewMessageError(eCode, eSubCode, nil, "AS param data length is short")
	}
	for i := 0; i < int(a.Num); i++ {
		a.AS = append(a.AS, binary.BigEndian.Uint16(data))
		data = data[2:]
	}
	return nil
}

func (a *AsPathParam) Len() int {
	return 2 + len(a.AS)*2
}

func (a *AsPathParam) ASLen() int {
	switch a.Type {
	case BGP_ASPATH_ATTR_TYPE_SEQ:
		return len(a.AS)
	case BGP_ASPATH_ATTR_TYPE_SET:
		return 1
	case BGP_ASPATH_ATTR_TYPE_CONFED_SET, BGP_ASPATH_ATTR_TYPE_CONFED_SEQ:
		return 0
	}
	return 0
}

func (a *AsPathParam) String() string {
	format, ok := asPathParamFormatMap[a.Type]
	if !ok {
		return fmt.Sprintf("%v", a.AS)
	}
	aspath := make([]string, 0, len(a.AS))
	for _, asn := range a.AS {
		aspath = append(aspath, strconv.FormatUint(uint64(asn), 10))
	}
	s := bytes.NewBuffer(make([]byte, 0, 32))
	s.WriteString(format.start)
	s.WriteString(strings.Join(aspath, format.separator))
	s.WriteString(format.end)
	return s.String()
}

func (a *AsPathParam) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type uint8    `json:"segment_type"`
		Num  uint8    `json:"num"`
		AS   []uint16 `json:"asns"`
	}{
		Type: a.Type,
		Num:  a.Num,
		AS:   a.AS,
	})
}

func NewAsPathParam(segType uint8, as []uint16) *AsPathParam {
	return &AsPathParam{
		Type: segType,
		Num:  uint8(len(as)),
		AS:   as,
	}
}

type As4PathParam struct {
	Type uint8
	Num  uint8
	AS   []uint32
}

func (a *As4PathParam) GetType() uint8 {
	return a.Type
}

func (a *As4PathParam) GetAS() []uint32 {
	return a.AS
}

func (a *As4PathParam) Serialize() ([]byte, error) {
	buf := make([]byte, 2+len(a.AS)*4)
	buf[0] = a.Type
	buf[1] = a.Num
	for j, as := range a.AS {
		binary.BigEndian.PutUint32(buf[2+j*4:], as)
	}
	return buf, nil
}

func (a *As4PathParam) DecodeFromBytes(data []byte) error {
	eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
	eSubCode := uint8(BGP_ERROR_SUB_MALFORMED_AS_PATH)
	if len(data) < 2 {
		return NewMessageError(eCode, eSubCode, nil, "AS4 param header length is short")
	}
	a.Type = data[0]
	a.Num = data[1]
	data = data[2:]
	if len(data) < int(a.Num)*4 {
		return NewMessageError(eCode, eSubCode, nil, "AS4 param data length is short")
	}
	for i := 0; i < int(a.Num); i++ {
		a.AS = append(a.AS, binary.BigEndian.Uint32(data))
		data = data[4:]
	}
	return nil
}

func (a *As4PathParam) Len() int {
	return 2 + len(a.AS)*4
}

func (a *As4PathParam) ASLen() int {
	switch a.Type {
	case BGP_ASPATH_ATTR_TYPE_SEQ:
		return len(a.AS)
	case BGP_ASPATH_ATTR_TYPE_SET:
		return 1
	case BGP_ASPATH_ATTR_TYPE_CONFED_SET, BGP_ASPATH_ATTR_TYPE_CONFED_SEQ:
		return 0
	}
	return 0
}

func (a *As4PathParam) String() string {
	format, ok := asPathParamFormatMap[a.Type]
	if !ok {
		return fmt.Sprintf("%v", a.AS)
	}
	aspath := make([]string, 0, len(a.AS))
	for _, asn := range a.AS {
		aspath = append(aspath, strconv.FormatUint(uint64(asn), 10))
	}
	s := bytes.NewBuffer(make([]byte, 0, 32))
	s.WriteString(format.start)
	s.WriteString(strings.Join(aspath, format.separator))
	s.WriteString(format.end)
	return s.String()
}

func (a *As4PathParam) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type uint8    `json:"segment_type"`
		Num  uint8    `json:"num"`
		AS   []uint32 `json:"asns"`
	}{
		Type: a.Type,
		Num:  a.Num,
		AS:   a.AS,
	})
}

func NewAs4PathParam(segType uint8, as []uint32) *As4PathParam {
	return &As4PathParam{
		Type: segType,
		Num:  uint8(len(as)),
		AS:   as,
	}
}

type PathAttributeAsPath struct {
	PathAttribute
	Value []AsPathParamInterface
}

func (p *PathAttributeAsPath) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	value, err := p.PathAttribute.DecodeFromBytes(data, options...)
	if err != nil {
		return err
	}
	if p.Length == 0 {
		// ibgp or something
		return nil
	}
	isAs4, err := validateAsPathValueBytes(value)
	if err != nil {
		err.(*MessageError).Data, _ = p.PathAttribute.Serialize(value, options...)
		return err
	}
	for len(value) > 0 {
		var tuple AsPathParamInterface
		if isAs4 {
			tuple = &As4PathParam{}
		} else {
			tuple = &AsPathParam{}
		}
		err := tuple.DecodeFromBytes(value)
		if err != nil {
			return err
		}
		p.Value = append(p.Value, tuple)
		value = value[tuple.Len():]
	}
	return nil
}

func (p *PathAttributeAsPath) Serialize(options ...*MarshallingOption) ([]byte, error) {
	buf := make([]byte, 0)
	for _, v := range p.Value {
		vbuf, err := v.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, vbuf...)
	}
	return p.PathAttribute.Serialize(buf, options...)
}

func (p *PathAttributeAsPath) String() string {
	params := make([]string, 0, len(p.Value))
	for _, param := range p.Value {
		params = append(params, param.String())
	}
	return strings.Join(params, " ")
}

func (p *PathAttributeAsPath) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  BGPAttrType            `json:"type"`
		Value []AsPathParamInterface `json:"as_paths"`
	}{
		Type:  p.GetType(),
		Value: p.Value,
	})
}

func NewPathAttributeAsPath(value []AsPathParamInterface) *PathAttributeAsPath {
	var l int
	for _, v := range value {
		l += v.Len()
	}
	t := BGP_ATTR_TYPE_AS_PATH
	return &PathAttributeAsPath{
		PathAttribute: PathAttribute{
			Flags:  getPathAttrFlags(t, l),
			Type:   t,
			Length: uint16(l),
		},
		Value: value,
	}
}

type PathAttributeNextHop struct {
	PathAttribute
	Value net.IP
}

func (p *PathAttributeNextHop) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	value, err := p.PathAttribute.DecodeFromBytes(data, options...)
	if err != nil {
		return err
	}
	if p.Length != 4 && p.Length != 16 {
		eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
		eSubCode := uint8(BGP_ERROR_SUB_ATTRIBUTE_LENGTH_ERROR)
		return NewMessageError(eCode, eSubCode, nil, "nexthop length isn't correct")
	}
	p.Value = value
	return nil
}

func (p *PathAttributeNextHop) Serialize(options ...*MarshallingOption) ([]byte, error) {
	return p.PathAttribute.Serialize(p.Value, options...)
}

func (p *PathAttributeNextHop) String() string {
	return fmt.Sprintf("{Nexthop: %s}", p.Value)
}

func (p *PathAttributeNextHop) MarshalJSON() ([]byte, error) {
	value := "0.0.0.0"
	if p.Value != nil {
		value = p.Value.String()
	}
	return json.Marshal(struct {
		Type  BGPAttrType `json:"type"`
		Value string      `json:"nexthop"`
	}{
		Type:  p.GetType(),
		Value: value,
	})
}

func NewPathAttributeNextHop(addr string) *PathAttributeNextHop {
	t := BGP_ATTR_TYPE_NEXT_HOP
	ip := net.ParseIP(addr)
	l := net.IPv4len
	if ip.To4() == nil {
		l = net.IPv6len
	} else {
		ip = ip.To4()
	}
	return &PathAttributeNextHop{
		PathAttribute: PathAttribute{
			Flags:  PathAttrFlags[t],
			Type:   t,
			Length: uint16(l),
		},
		Value: ip,
	}
}

type PathAttributeMultiExitDisc struct {
	PathAttribute
	Value uint32
}

func (p *PathAttributeMultiExitDisc) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	value, err := p.PathAttribute.DecodeFromBytes(data, options...)
	if err != nil {
		return err
	}
	if p.Length != 4 {
		eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
		eSubCode := uint8(BGP_ERROR_SUB_ATTRIBUTE_LENGTH_ERROR)
		return NewMessageError(eCode, eSubCode, nil, "med length isn't correct")
	}
	p.Value = binary.BigEndian.Uint32(value)
	return nil
}

func (p *PathAttributeMultiExitDisc) Serialize(options ...*MarshallingOption) ([]byte, error) {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], p.Value)
	return p.PathAttribute.Serialize(buf[:], options...)
}

func (p *PathAttributeMultiExitDisc) String() string {
	return fmt.Sprintf("{Med: %d}", p.Value)
}

func (p *PathAttributeMultiExitDisc) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  BGPAttrType `json:"type"`
		Value uint32      `json:"metric"`
	}{
		Type:  p.GetType(),
		Value: p.Value,
	})
}

func NewPathAttributeMultiExitDisc(value uint32) *PathAttributeMultiExitDisc {
	t := BGP_ATTR_TYPE_MULTI_EXIT_DISC
	return &PathAttributeMultiExitDisc{
		PathAttribute: PathAttribute{
			Flags:  PathAttrFlags[t],
			Type:   t,
			Length: 4,
		},
		Value: value,
	}
}

type PathAttributeLocalPref struct {
	PathAttribute
	Value uint32
}

func (p *PathAttributeLocalPref) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	value, err := p.PathAttribute.DecodeFromBytes(data, options...)
	if err != nil {
		return err
	}
	if p.Length != 4 {
		eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
		eSubCode := uint8(BGP_ERROR_SUB_ATTRIBUTE_LENGTH_ERROR)
		return NewMessageError(eCode, eSubCode, nil, "local pref length isn't correct")
	}
	p.Value = binary.BigEndian.Uint32(value)
	return nil
}

func (p *PathAttributeLocalPref) Serialize(options ...*MarshallingOption) ([]byte, error) {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], p.Value)
	return p.PathAttribute.Serialize(buf[:], options...)
}

func (p *PathAttributeLocalPref) String() string {
	return fmt.Sprintf("{LocalPref: %d}", p.Value)
}

func (p *PathAttributeLocalPref) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  BGPAttrType `json:"type"`
		Value uint32      `json:"value"`
	}{
		Type:  p.GetType(),
		Value: p.Value,
	})
}

func NewPathAttributeLocalPref(value uint32) *PathAttributeLocalPref {
	t := BGP_ATTR_TYPE_LOCAL_PREF
	return &PathAttributeLocalPref{
		PathAttribute: PathAttribute{
			Flags:  PathAttrFlags[t],
			Type:   t,
			Length: 4,
		},
		Value: value,
	}
}

type PathAttributeAtomicAggregate struct {
	PathAttribute
}

func (p *PathAttributeAtomicAggregate) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	_, err := p.PathAttribute.DecodeFromBytes(data, options...)
	if err != nil {
		return err
	}
	if p.Length != 0 {
		eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
		eSubCode := uint8(BGP_ERROR_SUB_ATTRIBUTE_LENGTH_ERROR)
		return NewMessageError(eCode, eSubCode, nil, "atomic aggregate should have no value")
	}
	return nil
}

func (p *PathAttributeAtomicAggregate) Serialize(options ...*MarshallingOption) ([]byte, error) {
	return p.PathAttribute.Serialize(nil, options...)
}

func (p *PathAttributeAtomicAggregate) String() string {
	return "{AtomicAggregate}"
}

func (p *PathAttributeAtomicAggregate) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type BGPAttrType `json:"type"`
	}{
		Type: p.GetType(),
	})
}

func NewPathAttributeAtomicAggregate() *PathAttributeAtomicAggregate {
	t := BGP_ATTR_TYPE_ATOMIC_AGGREGATE
	return &PathAttributeAtomicAggregate{
		PathAttribute: PathAttribute{
			Flags:  PathAttrFlags[t],
			Type:   t,
			Length: 0,
		},
	}
}

type PathAttributeAggregatorParam struct {
	AS      uint32
	Askind  reflect.Kind
	Address net.IP
}

type PathAttributeAggregator struct {
	PathAttribute
	Value PathAttributeAggregatorParam
}

func (p *PathAttributeAggregator) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	value, err := p.PathAttribute.DecodeFromBytes(data, options...)
	if err != nil {
		return err
	}
	switch p.Length {
	case 6:
		p.Value.Askind = reflect.Uint16
		p.Value.AS = uint32(binary.BigEndian.Uint16(value[0:2]))
		p.Value.Address = value[2:]
	case 8:
		p.Value.Askind = reflect.Uint32
		p.Value.AS = binary.BigEndian.Uint32(value[0:4])
		p.Value.Address = value[4:]
	default:
		eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
		eSubCode := uint8(BGP_ERROR_SUB_ATTRIBUTE_LENGTH_ERROR)
		return NewMessageError(eCode, eSubCode, nil, "aggregator length isn't correct")
	}
	return nil
}

func (p *PathAttributeAggregator) Serialize(options ...*MarshallingOption) ([]byte, error) {
	var buf []byte
	switch p.Value.Askind {
	case reflect.Uint16:
		buf = make([]byte, 6)
		binary.BigEndian.PutUint16(buf, uint16(p.Value.AS))
		copy(buf[2:], p.Value.Address)
	case reflect.Uint32:
		buf = make([]byte, 8)
		binary.BigEndian.PutUint32(buf, p.Value.AS)
		copy(buf[4:], p.Value.Address)
	}
	return p.PathAttribute.Serialize(buf, options...)
}

func (p *PathAttributeAggregator) String() string {
	return fmt.Sprintf("{Aggregate: {AS: %d, Address: %s}}", p.Value.AS, p.Value.Address)
}

func (p *PathAttributeAggregator) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type    BGPAttrType `json:"type"`
		AS      uint32      `json:"as"`
		Address string      `json:"address"`
	}{
		Type:    p.GetType(),
		AS:      p.Value.AS,
		Address: p.Value.Address.String(),
	})
}

func NewPathAttributeAggregator(as interface{}, address string) *PathAttributeAggregator {
	v := reflect.ValueOf(as)
	asKind := v.Kind()
	var l uint16
	switch asKind {
	case reflect.Uint16:
		l = 6
	case reflect.Uint32:
		l = 8
	default:
		// Invalid type
		return nil
	}
	t := BGP_ATTR_TYPE_AGGREGATOR
	return &PathAttributeAggregator{
		PathAttribute: PathAttribute{
			Flags:  PathAttrFlags[t],
			Type:   t,
			Length: l,
		},
		Value: PathAttributeAggregatorParam{
			AS:      uint32(v.Uint()),
			Askind:  asKind,
			Address: net.ParseIP(address).To4(),
		},
	}
}

type PathAttributeCommunities struct {
	PathAttribute
	Value []uint32
}

func (p *PathAttributeCommunities) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	value, err := p.PathAttribute.DecodeFromBytes(data, options...)
	if err != nil {
		return err
	}
	if p.Length%4 != 0 {
		eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
		eSubCode := uint8(BGP_ERROR_SUB_ATTRIBUTE_LENGTH_ERROR)
		return NewMessageError(eCode, eSubCode, nil, "communities length isn't correct")
	}
	for len(value) >= 4 {
		p.Value = append(p.Value, binary.BigEndian.Uint32(value))
		value = value[4:]
	}
	return nil
}

func (p *PathAttributeCommunities) Serialize(options ...*MarshallingOption) ([]byte, error) {
	buf := make([]byte, len(p.Value)*4)
	for i, v := range p.Value {
		binary.BigEndian.PutUint32(buf[i*4:], v)
	}
	return p.PathAttribute.Serialize(buf, options...)
}

type WellKnownCommunity uint32

const (
	COMMUNITY_INTERNET                   WellKnownCommunity = 0x00000000
	COMMUNITY_PLANNED_SHUT               WellKnownCommunity = 0xffff0000
	COMMUNITY_ACCEPT_OWN                 WellKnownCommunity = 0xffff0001
	COMMUNITY_ROUTE_FILTER_TRANSLATED_v4 WellKnownCommunity = 0xffff0002
	COMMUNITY_ROUTE_FILTER_v4            WellKnownCommunity = 0xffff0003
	COMMUNITY_ROUTE_FILTER_TRANSLATED_v6 WellKnownCommunity = 0xffff0004
	COMMUNITY_ROUTE_FILTER_v6            WellKnownCommunity = 0xffff0005
	COMMUNITY_LLGR_STALE                 WellKnownCommunity = 0xffff0006
	COMMUNITY_NO_LLGR                    WellKnownCommunity = 0xffff0007
	COMMUNITY_BLACKHOLE                  WellKnownCommunity = 0xffff029a
	COMMUNITY_NO_EXPORT                  WellKnownCommunity = 0xffffff01
	COMMUNITY_NO_ADVERTISE               WellKnownCommunity = 0xffffff02
	COMMUNITY_NO_EXPORT_SUBCONFED        WellKnownCommunity = 0xffffff03
	COMMUNITY_NO_PEER                    WellKnownCommunity = 0xffffff04
)

var WellKnownCommunityNameMap = map[WellKnownCommunity]string{
	COMMUNITY_INTERNET:                   "internet",
	COMMUNITY_PLANNED_SHUT:               "planned-shut",
	COMMUNITY_ACCEPT_OWN:                 "accept-own",
	COMMUNITY_ROUTE_FILTER_TRANSLATED_v4: "route-filter-translated-v4",
	COMMUNITY_ROUTE_FILTER_v4:            "route-filter-v4",
	COMMUNITY_ROUTE_FILTER_TRANSLATED_v6: "route-filter-translated-v6",
	COMMUNITY_ROUTE_FILTER_v6:            "route-filter-v6",
	COMMUNITY_LLGR_STALE:                 "llgr-stale",
	COMMUNITY_NO_LLGR:                    "no-llgr",
	COMMUNITY_BLACKHOLE:                  "blackhole",
	COMMUNITY_NO_EXPORT:                  "no-export",
	COMMUNITY_NO_ADVERTISE:               "no-advertise",
	COMMUNITY_NO_EXPORT_SUBCONFED:        "no-export-subconfed",
	COMMUNITY_NO_PEER:                    "no-peer",
}

var WellKnownCommunityValueMap = map[string]WellKnownCommunity{
	WellKnownCommunityNameMap[COMMUNITY_INTERNET]:                   COMMUNITY_INTERNET,
	WellKnownCommunityNameMap[COMMUNITY_PLANNED_SHUT]:               COMMUNITY_PLANNED_SHUT,
	WellKnownCommunityNameMap[COMMUNITY_ACCEPT_OWN]:                 COMMUNITY_ACCEPT_OWN,
	WellKnownCommunityNameMap[COMMUNITY_ROUTE_FILTER_TRANSLATED_v4]: COMMUNITY_ROUTE_FILTER_TRANSLATED_v4,
	WellKnownCommunityNameMap[COMMUNITY_ROUTE_FILTER_v4]:            COMMUNITY_ROUTE_FILTER_v4,
	WellKnownCommunityNameMap[COMMUNITY_ROUTE_FILTER_TRANSLATED_v6]: COMMUNITY_ROUTE_FILTER_TRANSLATED_v6,
	WellKnownCommunityNameMap[COMMUNITY_ROUTE_FILTER_v6]:            COMMUNITY_ROUTE_FILTER_v6,
	WellKnownCommunityNameMap[COMMUNITY_LLGR_STALE]:                 COMMUNITY_LLGR_STALE,
	WellKnownCommunityNameMap[COMMUNITY_NO_LLGR]:                    COMMUNITY_NO_LLGR,
	WellKnownCommunityNameMap[COMMUNITY_NO_EXPORT]:                  COMMUNITY_NO_EXPORT,
	WellKnownCommunityNameMap[COMMUNITY_BLACKHOLE]:                  COMMUNITY_BLACKHOLE,
	WellKnownCommunityNameMap[COMMUNITY_NO_ADVERTISE]:               COMMUNITY_NO_ADVERTISE,
	WellKnownCommunityNameMap[COMMUNITY_NO_EXPORT_SUBCONFED]:        COMMUNITY_NO_EXPORT_SUBCONFED,
	WellKnownCommunityNameMap[COMMUNITY_NO_PEER]:                    COMMUNITY_NO_PEER,
}

func (p *PathAttributeCommunities) String() string {
	l := make([]string, 0, len(p.Value))
	for _, v := range p.Value {
		n, ok := WellKnownCommunityNameMap[WellKnownCommunity(v)]
		if ok {
			l = append(l, n)
		} else {
			l = append(l, fmt.Sprintf("%d:%d", (0xffff0000&v)>>16, 0xffff&v))
		}
	}
	return fmt.Sprintf("{Communities: %s}", strings.Join(l, ", "))
}

func (p *PathAttributeCommunities) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  BGPAttrType `json:"type"`
		Value []uint32    `json:"communities"`
	}{
		Type:  p.GetType(),
		Value: p.Value,
	})
}

func NewPathAttributeCommunities(value []uint32) *PathAttributeCommunities {
	l := len(value) * 4
	t := BGP_ATTR_TYPE_COMMUNITIES
	return &PathAttributeCommunities{
		PathAttribute: PathAttribute{
			Flags:  getPathAttrFlags(t, l),
			Type:   t,
			Length: uint16(l),
		},
		Value: value,
	}
}

type PathAttributeOriginatorId struct {
	PathAttribute
	Value net.IP
}

func (p *PathAttributeOriginatorId) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	value, err := p.PathAttribute.DecodeFromBytes(data, options...)
	if err != nil {
		return err
	}
	if p.Length != 4 {
		eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
		eSubCode := uint8(BGP_ERROR_SUB_ATTRIBUTE_LENGTH_ERROR)
		return NewMessageError(eCode, eSubCode, nil, "originator id length isn't correct")
	}
	p.Value = value
	return nil
}

func (p *PathAttributeOriginatorId) String() string {
	return fmt.Sprintf("{Originator: %s}", p.Value)
}

func (p *PathAttributeOriginatorId) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  BGPAttrType `json:"type"`
		Value string      `json:"value"`
	}{
		Type:  p.GetType(),
		Value: p.Value.String(),
	})
}

func (p *PathAttributeOriginatorId) Serialize(options ...*MarshallingOption) ([]byte, error) {
	var buf [4]byte
	copy(buf[:], p.Value)
	return p.PathAttribute.Serialize(buf[:], options...)
}

func NewPathAttributeOriginatorId(value string) *PathAttributeOriginatorId {
	t := BGP_ATTR_TYPE_ORIGINATOR_ID
	return &PathAttributeOriginatorId{
		PathAttribute: PathAttribute{
			Flags:  PathAttrFlags[t],
			Type:   t,
			Length: 4,
		},
		Value: net.ParseIP(value).To4(),
	}
}

type PathAttributeClusterList struct {
	PathAttribute
	Value []net.IP
}

func (p *PathAttributeClusterList) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	value, err := p.PathAttribute.DecodeFromBytes(data, options...)
	if err != nil {
		return err
	}
	if p.Length%4 != 0 {
		eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
		eSubCode := uint8(BGP_ERROR_SUB_ATTRIBUTE_LENGTH_ERROR)
		return NewMessageError(eCode, eSubCode, nil, "clusterlist length isn't correct")
	}
	for len(value) >= 4 {
		p.Value = append(p.Value, value[:4])
		value = value[4:]
	}
	return nil
}

func (p *PathAttributeClusterList) Serialize(options ...*MarshallingOption) ([]byte, error) {
	buf := make([]byte, len(p.Value)*4)
	for i, v := range p.Value {
		copy(buf[i*4:], v)
	}
	return p.PathAttribute.Serialize(buf, options...)
}

func (p *PathAttributeClusterList) String() string {
	return fmt.Sprintf("{ClusterList: %v}", p.Value)
}

func (p *PathAttributeClusterList) MarshalJSON() ([]byte, error) {
	value := make([]string, 0, len(p.Value))
	for _, v := range p.Value {
		value = append(value, v.String())
	}
	return json.Marshal(struct {
		Type  BGPAttrType `json:"type"`
		Value []string    `json:"value"`
	}{
		Type:  p.GetType(),
		Value: value,
	})
}

func NewPathAttributeClusterList(value []string) *PathAttributeClusterList {
	l := len(value) * 4
	list := make([]net.IP, len(value))
	for i, v := range value {
		list[i] = net.ParseIP(v).To4()
	}
	t := BGP_ATTR_TYPE_CLUSTER_LIST
	return &PathAttributeClusterList{
		PathAttribute: PathAttribute{
			Flags:  getPathAttrFlags(t, l),
			Type:   t,
			Length: uint16(l),
		},
		Value: list,
	}
}

type PathAttributeMpReachNLRI struct {
	PathAttribute
	Nexthop          net.IP
	LinkLocalNexthop net.IP
	AFI              uint16
	SAFI             uint8
	Value            []AddrPrefixInterface
}

func (p *PathAttributeMpReachNLRI) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {

	value, err := p.PathAttribute.DecodeFromBytes(data, options...)
	if err != nil {
		return err
	}
	eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
	eSubCode := uint8(BGP_ERROR_SUB_ATTRIBUTE_LENGTH_ERROR)
	eData, _ := p.PathAttribute.Serialize(value, options...)
	if p.Length < 3 {
		return NewMessageError(eCode, eSubCode, value, "mpreach header length is short")
	}
	afi := binary.BigEndian.Uint16(value[0:2])
	safi := value[2]
	p.AFI = afi
	p.SAFI = safi
	_, err = NewPrefixFromRouteFamily(afi, safi)
	if err != nil {
		return NewMessageError(eCode, BGP_ERROR_SUB_INVALID_NETWORK_FIELD, eData, err.Error())
	}
	nexthoplen := int(value[3])
	if len(value) < 4+nexthoplen {
		return NewMessageError(eCode, eSubCode, value, "mpreach nexthop length is short")
	}
	nexthopbin := value[4 : 4+nexthoplen]
	if nexthoplen > 0 {
		v4addrlen := 4
		v6addrlen := 16
		offset := 0
		if safi == SAFI_MPLS_VPN {
			offset = 8
		}
		switch nexthoplen {
		case 2 * (offset + v6addrlen):
			p.LinkLocalNexthop = nexthopbin[offset+v6addrlen+offset : 2*(offset+v6addrlen)]
			fallthrough
		case offset + v6addrlen:
			p.Nexthop = nexthopbin[offset : offset+v6addrlen]
		case offset + v4addrlen:
			p.Nexthop = nexthopbin[offset : offset+v4addrlen]
		default:
			return NewMessageError(eCode, eSubCode, value, "mpreach nexthop length is incorrect")
		}
	}
	value = value[4+nexthoplen:]
	// skip reserved
	if len(value) == 0 {
		return NewMessageError(eCode, eSubCode, value, "no skip byte")
	}
	value = value[1:]
	addpathLen := 0
	if IsAddPathEnabled(true, AfiSafiToRouteFamily(afi, safi), options) {
		addpathLen = 4
	}
	for len(value) > 0 {
		prefix, err := NewPrefixFromRouteFamily(afi, safi)
		if err != nil {
			return NewMessageError(eCode, BGP_ERROR_SUB_INVALID_NETWORK_FIELD, eData, err.Error())
		}
		err = prefix.DecodeFromBytes(value, options...)
		if err != nil {
			return err
		}
		if prefix.Len(options...)+addpathLen > len(value) {
			return NewMessageError(eCode, eSubCode, value, "prefix length is incorrect")
		}
		value = value[prefix.Len(options...)+addpathLen:]
		p.Value = append(p.Value, prefix)
	}
	return nil
}

func (p *PathAttributeMpReachNLRI) Serialize(options ...*MarshallingOption) ([]byte, error) {
	afi := p.AFI
	safi := p.SAFI
	nexthoplen := 4
	if afi == AFI_IP6 || p.Nexthop.To4() == nil {
		nexthoplen = BGP_ATTR_NHLEN_IPV6_GLOBAL
	}
	offset := 0
	switch safi {
	case SAFI_MPLS_VPN:
		offset = 8
		nexthoplen += offset
	case SAFI_FLOW_SPEC_VPN, SAFI_FLOW_SPEC_UNICAST:
		nexthoplen = 0
	}
	if p.LinkLocalNexthop != nil && p.LinkLocalNexthop.IsLinkLocalUnicast() {
		nexthoplen = BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL
	}
	buf := make([]byte, 4+nexthoplen)
	binary.BigEndian.PutUint16(buf[0:], afi)
	buf[2] = safi
	buf[3] = uint8(nexthoplen)
	if nexthoplen != 0 {
		if p.Nexthop.To4() == nil {
			copy(buf[4+offset:], p.Nexthop.To16())
			if nexthoplen == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL {
				copy(buf[4+offset+16:], p.LinkLocalNexthop.To16())
			}
		} else {
			copy(buf[4+offset:], p.Nexthop)
		}
	}
	buf = append(buf, 0)
	for _, prefix := range p.Value {
		pbuf, err := prefix.Serialize(options...)
		if err != nil {
			return nil, err
		}
		buf = append(buf, pbuf...)
	}
	return p.PathAttribute.Serialize(buf, options...)
}

func (p *PathAttributeMpReachNLRI) MarshalJSON() ([]byte, error) {
	nexthop := p.Nexthop.String()
	if p.Nexthop == nil {
		switch p.AFI {
		case AFI_IP:
			nexthop = "0.0.0.0"
		case AFI_IP6:
			nexthop = "::"
		default:
			nexthop = "fictitious"
		}
	}
	return json.Marshal(struct {
		Type    BGPAttrType           `json:"type"`
		Nexthop string                `json:"nexthop"`
		AFI     uint16                `json:"afi"`
		SAFI    uint8                 `json:"safi"`
		Value   []AddrPrefixInterface `json:"value"`
	}{
		Type:    p.GetType(),
		Nexthop: nexthop,
		AFI:     p.AFI,
		SAFI:    p.SAFI,
		Value:   p.Value,
	})
}

func (p *PathAttributeMpReachNLRI) String() string {
	return fmt.Sprintf("{MpReach(%s): {Nexthop: %s, NLRIs: %s}}", AfiSafiToRouteFamily(p.AFI, p.SAFI), p.Nexthop, p.Value)
}

func NewPathAttributeMpReachNLRI(nexthop string, nlri []AddrPrefixInterface) *PathAttributeMpReachNLRI {
	// AFI(2) + SAFI(1) + NexthopLength(1) + Nexthop(variable)
	// + Reserved(1) + NLRI(variable)
	l := 5
	var afi uint16
	var safi uint8
	if len(nlri) > 0 {
		afi = nlri[0].AFI()
		safi = nlri[0].SAFI()
	}
	nh := net.ParseIP(nexthop)
	if nh.To4() != nil && afi != AFI_IP6 {
		nh = nh.To4()
		switch safi {
		case SAFI_MPLS_VPN:
			l += 12
		case SAFI_FLOW_SPEC_VPN, SAFI_FLOW_SPEC_UNICAST:
			// Should not have Nexthop
		default:
			l += 4
		}
	} else {
		switch safi {
		case SAFI_MPLS_VPN:
			l += 24
		case SAFI_FLOW_SPEC_VPN, SAFI_FLOW_SPEC_UNICAST:
			// Should not have Nexthop
		default:
			l += 16
		}
	}
	var nlriLen int
	for _, n := range nlri {
		l += n.Len()
		nBuf, _ := n.Serialize()
		nlriLen += len(nBuf)
	}
	t := BGP_ATTR_TYPE_MP_REACH_NLRI
	return &PathAttributeMpReachNLRI{
		PathAttribute: PathAttribute{
			Flags:  getPathAttrFlags(t, l),
			Type:   t,
			Length: uint16(l),
		},
		Nexthop: nh,
		AFI:     afi,
		SAFI:    safi,
		Value:   nlri,
	}
}

type PathAttributeMpUnreachNLRI struct {
	PathAttribute
	AFI   uint16
	SAFI  uint8
	Value []AddrPrefixInterface
}

func (p *PathAttributeMpUnreachNLRI) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	value, err := p.PathAttribute.DecodeFromBytes(data, options...)
	if err != nil {
		return err
	}
	eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
	eSubCode := uint8(BGP_ERROR_SUB_ATTRIBUTE_LENGTH_ERROR)
	eData, _ := p.PathAttribute.Serialize(value, options...)
	if p.Length < 3 {
		return NewMessageError(eCode, eSubCode, value, "unreach header length is incorrect")
	}
	afi := binary.BigEndian.Uint16(value[0:2])
	safi := value[2]
	_, err = NewPrefixFromRouteFamily(afi, safi)
	if err != nil {
		return NewMessageError(eCode, BGP_ERROR_SUB_INVALID_NETWORK_FIELD, eData, err.Error())
	}
	value = value[3:]
	p.AFI = afi
	p.SAFI = safi
	addpathLen := 0
	if IsAddPathEnabled(true, AfiSafiToRouteFamily(afi, safi), options) {
		addpathLen = 4
	}
	for len(value) > 0 {
		prefix, err := NewPrefixFromRouteFamily(afi, safi)
		if err != nil {
			return NewMessageError(eCode, BGP_ERROR_SUB_INVALID_NETWORK_FIELD, eData, err.Error())
		}
		err = prefix.DecodeFromBytes(value, options...)
		if err != nil {
			return err
		}
		if prefix.Len(options...)+addpathLen > len(value) {
			return NewMessageError(eCode, eSubCode, eData, "prefix length is incorrect")
		}
		value = value[prefix.Len(options...)+addpathLen:]
		p.Value = append(p.Value, prefix)
	}
	return nil
}

func (p *PathAttributeMpUnreachNLRI) Serialize(options ...*MarshallingOption) ([]byte, error) {
	buf := make([]byte, 3)
	binary.BigEndian.PutUint16(buf, p.AFI)
	buf[2] = p.SAFI
	for _, prefix := range p.Value {
		pbuf, err := prefix.Serialize(options...)
		if err != nil {
			return nil, err
		}
		buf = append(buf, pbuf...)
	}
	return p.PathAttribute.Serialize(buf, options...)
}

func (p *PathAttributeMpUnreachNLRI) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  BGPAttrType           `json:"type"`
		AFI   uint16                `json:"afi"`
		SAFI  uint8                 `json:"safi"`
		Value []AddrPrefixInterface `json:"value"`
	}{
		Type:  p.GetType(),
		AFI:   p.AFI,
		SAFI:  p.SAFI,
		Value: p.Value,
	})
}

func (p *PathAttributeMpUnreachNLRI) String() string {
	if len(p.Value) > 0 {
		return fmt.Sprintf("{MpUnreach(%s): {NLRIs: %s}}", AfiSafiToRouteFamily(p.AFI, p.SAFI), p.Value)
	}
	return fmt.Sprintf("{MpUnreach(%s): End-of-Rib}", AfiSafiToRouteFamily(p.AFI, p.SAFI))
}

func NewPathAttributeMpUnreachNLRI(nlri []AddrPrefixInterface) *PathAttributeMpUnreachNLRI {
	// AFI(2) + SAFI(1) + NLRI(variable)
	l := 3
	var afi uint16
	var safi uint8
	if len(nlri) > 0 {
		afi = nlri[0].AFI()
		safi = nlri[0].SAFI()
	}
	for _, n := range nlri {
		l += n.Len()
	}
	t := BGP_ATTR_TYPE_MP_UNREACH_NLRI
	return &PathAttributeMpUnreachNLRI{
		PathAttribute: PathAttribute{
			Flags:  getPathAttrFlags(t, l),
			Type:   t,
			Length: uint16(l),
		},
		AFI:   afi,
		SAFI:  safi,
		Value: nlri,
	}
}

type ExtendedCommunityInterface interface {
	Serialize() ([]byte, error)
	String() string
	GetTypes() (ExtendedCommunityAttrType, ExtendedCommunityAttrSubType)
	MarshalJSON() ([]byte, error)
	Flat() map[string]string
}

type TwoOctetAsSpecificExtended struct {
	SubType      ExtendedCommunityAttrSubType
	AS           uint16
	LocalAdmin   uint32
	IsTransitive bool
}

func (e *TwoOctetAsSpecificExtended) Serialize() ([]byte, error) {
	buf := make([]byte, 8)
	if e.IsTransitive {
		buf[0] = byte(EC_TYPE_TRANSITIVE_TWO_OCTET_AS_SPECIFIC)
	} else {
		buf[0] = byte(EC_TYPE_NON_TRANSITIVE_TWO_OCTET_AS_SPECIFIC)
	}
	buf[1] = byte(e.SubType)
	binary.BigEndian.PutUint16(buf[2:], e.AS)
	binary.BigEndian.PutUint32(buf[4:], e.LocalAdmin)
	return buf, nil
}

func (e *TwoOctetAsSpecificExtended) String() string {
	return fmt.Sprintf("%d:%d", e.AS, e.LocalAdmin)
}

func (e *TwoOctetAsSpecificExtended) MarshalJSON() ([]byte, error) {
	t, s := e.GetTypes()
	return json.Marshal(struct {
		Type    ExtendedCommunityAttrType    `json:"type"`
		Subtype ExtendedCommunityAttrSubType `json:"subtype"`
		Value   string                       `json:"value"`
	}{
		Type:    t,
		Subtype: s,
		Value:   e.String(),
	})
}

func (e *TwoOctetAsSpecificExtended) GetTypes() (ExtendedCommunityAttrType, ExtendedCommunityAttrSubType) {
	t := EC_TYPE_TRANSITIVE_TWO_OCTET_AS_SPECIFIC
	if !e.IsTransitive {
		t = EC_TYPE_NON_TRANSITIVE_TWO_OCTET_AS_SPECIFIC
	}
	return t, e.SubType
}

func NewTwoOctetAsSpecificExtended(subtype ExtendedCommunityAttrSubType, as uint16, localAdmin uint32, isTransitive bool) *TwoOctetAsSpecificExtended {
	return &TwoOctetAsSpecificExtended{
		SubType:      subtype,
		AS:           as,
		LocalAdmin:   localAdmin,
		IsTransitive: isTransitive,
	}
}

type IPv4AddressSpecificExtended struct {
	SubType      ExtendedCommunityAttrSubType
	IPv4         net.IP
	LocalAdmin   uint16
	IsTransitive bool
}

func (e *IPv4AddressSpecificExtended) Serialize() ([]byte, error) {
	buf := make([]byte, 8)
	if e.IsTransitive {
		buf[0] = byte(EC_TYPE_TRANSITIVE_IP4_SPECIFIC)
	} else {
		buf[0] = byte(EC_TYPE_NON_TRANSITIVE_IP4_SPECIFIC)
	}
	buf[1] = byte(e.SubType)
	copy(buf[2:6], e.IPv4)
	binary.BigEndian.PutUint16(buf[6:], e.LocalAdmin)
	return buf, nil
}

func (e *IPv4AddressSpecificExtended) String() string {
	return fmt.Sprintf("%s:%d", e.IPv4.String(), e.LocalAdmin)
}

func (e *IPv4AddressSpecificExtended) MarshalJSON() ([]byte, error) {
	t, s := e.GetTypes()
	return json.Marshal(struct {
		Type    ExtendedCommunityAttrType    `json:"type"`
		Subtype ExtendedCommunityAttrSubType `json:"subtype"`
		Value   string                       `json:"value"`
	}{
		Type:    t,
		Subtype: s,
		Value:   e.String(),
	})
}

func (e *IPv4AddressSpecificExtended) GetTypes() (ExtendedCommunityAttrType, ExtendedCommunityAttrSubType) {
	t := EC_TYPE_TRANSITIVE_IP4_SPECIFIC
	if !e.IsTransitive {
		t = EC_TYPE_NON_TRANSITIVE_IP4_SPECIFIC
	}
	return t, e.SubType
}

func NewIPv4AddressSpecificExtended(subtype ExtendedCommunityAttrSubType, ip string, localAdmin uint16, isTransitive bool) *IPv4AddressSpecificExtended {
	ipv4 := net.ParseIP(ip)
	if ipv4.To4() == nil {
		return nil
	}
	return &IPv4AddressSpecificExtended{
		SubType:      subtype,
		IPv4:         ipv4.To4(),
		LocalAdmin:   localAdmin,
		IsTransitive: isTransitive,
	}
}

type IPv6AddressSpecificExtended struct {
	SubType      ExtendedCommunityAttrSubType
	IPv6         net.IP
	LocalAdmin   uint16
	IsTransitive bool
}

func (e *IPv6AddressSpecificExtended) Serialize() ([]byte, error) {
	buf := make([]byte, 20)
	if e.IsTransitive {
		buf[0] = byte(EC_TYPE_TRANSITIVE_IP6_SPECIFIC)
	} else {
		buf[0] = byte(EC_TYPE_NON_TRANSITIVE_IP6_SPECIFIC)
	}
	buf[1] = byte(e.SubType)
	copy(buf[2:18], e.IPv6)
	binary.BigEndian.PutUint16(buf[18:], e.LocalAdmin)
	return buf, nil
}

func (e *IPv6AddressSpecificExtended) String() string {
	return fmt.Sprintf("%s:%d", e.IPv6.String(), e.LocalAdmin)
}

func (e *IPv6AddressSpecificExtended) MarshalJSON() ([]byte, error) {
	t, s := e.GetTypes()
	return json.Marshal(struct {
		Type    ExtendedCommunityAttrType    `json:"type"`
		Subtype ExtendedCommunityAttrSubType `json:"subtype"`
		Value   string                       `json:"value"`
	}{
		Type:    t,
		Subtype: s,
		Value:   e.String(),
	})
}

func (e *IPv6AddressSpecificExtended) GetTypes() (ExtendedCommunityAttrType, ExtendedCommunityAttrSubType) {
	t := EC_TYPE_TRANSITIVE_IP6_SPECIFIC
	if !e.IsTransitive {
		t = EC_TYPE_NON_TRANSITIVE_IP6_SPECIFIC
	}
	return t, e.SubType
}

func NewIPv6AddressSpecificExtended(subtype ExtendedCommunityAttrSubType, ip string, localAdmin uint16, isTransitive bool) *IPv6AddressSpecificExtended {
	ipv6 := net.ParseIP(ip)
	if ipv6.To16() == nil {
		return nil
	}
	return &IPv6AddressSpecificExtended{
		SubType:      subtype,
		IPv6:         ipv6.To16(),
		LocalAdmin:   localAdmin,
		IsTransitive: isTransitive,
	}
}

type FourOctetAsSpecificExtended struct {
	SubType      ExtendedCommunityAttrSubType
	AS           uint32
	LocalAdmin   uint16
	IsTransitive bool
}

func (e *FourOctetAsSpecificExtended) Serialize() ([]byte, error) {
	buf := make([]byte, 8)
	if e.IsTransitive {
		buf[0] = byte(EC_TYPE_TRANSITIVE_FOUR_OCTET_AS_SPECIFIC)
	} else {
		buf[0] = byte(EC_TYPE_NON_TRANSITIVE_FOUR_OCTET_AS_SPECIFIC)
	}
	buf[1] = byte(e.SubType)
	binary.BigEndian.PutUint32(buf[2:], e.AS)
	binary.BigEndian.PutUint16(buf[6:], e.LocalAdmin)
	return buf, nil
}

func (e *FourOctetAsSpecificExtended) String() string {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:4], e.AS)
	asUpper := binary.BigEndian.Uint16(buf[0:2])
	asLower := binary.BigEndian.Uint16(buf[2:4])
	return fmt.Sprintf("%d.%d:%d", asUpper, asLower, e.LocalAdmin)
}

func (e *FourOctetAsSpecificExtended) MarshalJSON() ([]byte, error) {
	t, s := e.GetTypes()
	return json.Marshal(struct {
		Type    ExtendedCommunityAttrType    `json:"type"`
		Subtype ExtendedCommunityAttrSubType `json:"subtype"`
		Value   string                       `json:"value"`
	}{
		Type:    t,
		Subtype: s,
		Value:   e.String(),
	})
}

func (e *FourOctetAsSpecificExtended) GetTypes() (ExtendedCommunityAttrType, ExtendedCommunityAttrSubType) {
	t := EC_TYPE_TRANSITIVE_FOUR_OCTET_AS_SPECIFIC
	if !e.IsTransitive {
		t = EC_TYPE_NON_TRANSITIVE_FOUR_OCTET_AS_SPECIFIC
	}
	return t, e.SubType
}

func NewFourOctetAsSpecificExtended(subtype ExtendedCommunityAttrSubType, as uint32, localAdmin uint16, isTransitive bool) *FourOctetAsSpecificExtended {
	return &FourOctetAsSpecificExtended{
		SubType:      subtype,
		AS:           as,
		LocalAdmin:   localAdmin,
		IsTransitive: isTransitive,
	}
}

func ParseExtendedCommunity(subtype ExtendedCommunityAttrSubType, com string) (ExtendedCommunityInterface, error) {
	if subtype == EC_SUBTYPE_ENCAPSULATION {
		var t TunnelType
		switch com {
		case TUNNEL_TYPE_L2TP3.String():
			t = TUNNEL_TYPE_L2TP3
		case TUNNEL_TYPE_GRE.String():
			t = TUNNEL_TYPE_GRE
		case TUNNEL_TYPE_IP_IN_IP.String():
			t = TUNNEL_TYPE_IP_IN_IP
		case TUNNEL_TYPE_VXLAN.String():
			t = TUNNEL_TYPE_VXLAN
		case TUNNEL_TYPE_NVGRE.String():
			t = TUNNEL_TYPE_NVGRE
		case TUNNEL_TYPE_MPLS.String():
			t = TUNNEL_TYPE_MPLS
		case TUNNEL_TYPE_MPLS_IN_GRE.String():
			t = TUNNEL_TYPE_MPLS_IN_GRE
		case TUNNEL_TYPE_VXLAN_GRE.String():
			t = TUNNEL_TYPE_VXLAN_GRE
		case TUNNEL_TYPE_MPLS_IN_UDP.String():
			t = TUNNEL_TYPE_MPLS_IN_UDP
		case TUNNEL_TYPE_GENEVE.String():
			t = TUNNEL_TYPE_GENEVE
		case "L2TPv3 over IP":
			t = TUNNEL_TYPE_L2TP3
		case "GRE":
			t = TUNNEL_TYPE_GRE
		case "IP in IP":
			t = TUNNEL_TYPE_IP_IN_IP
		case "VXLAN":
			t = TUNNEL_TYPE_VXLAN
		case "NVGRE":
			t = TUNNEL_TYPE_NVGRE
		case "MPLS":
			t = TUNNEL_TYPE_MPLS
		case "MPLS in GRE":
			t = TUNNEL_TYPE_MPLS_IN_GRE
		case "VXLAN GRE":
			t = TUNNEL_TYPE_VXLAN_GRE
		case "MPLS in UDP":
			t = TUNNEL_TYPE_MPLS_IN_UDP
		case "GENEVE":
			t = TUNNEL_TYPE_GENEVE
		default:
			return nil, fmt.Errorf("invalid encap type %s", com)
		}
		return NewEncapExtended(t), nil
	}

	if subtype == EC_SUBTYPE_ORIGIN_VALIDATION {
		var state ValidationState
		switch com {
		case VALIDATION_STATE_VALID.String():
			state = VALIDATION_STATE_VALID
		case VALIDATION_STATE_NOT_FOUND.String():
			state = VALIDATION_STATE_NOT_FOUND
		case VALIDATION_STATE_INVALID.String():
			state = VALIDATION_STATE_INVALID
		default:
			return nil, errors.New("invalid validation state")
		}
		return &ValidationExtended{
			State: state,
		}, nil
	}
	elems, err := parseRdAndRt(com)
	if err != nil {
		return nil, err
	}
	localAdmin, _ := strconv.ParseUint(elems[10], 10, 32)
	if subtype == EC_SUBTYPE_SOURCE_AS {
		localAdmin = 0
	}
	ip := net.ParseIP(elems[1])
	isTransitive := true
	switch {
	case subtype == EC_SUBTYPE_LINK_BANDWIDTH:
		asn, _ := strconv.ParseUint(elems[8], 10, 16)
		return NewLinkBandwidthExtended(uint16(asn), float32(localAdmin)), nil
	case ip.To4() != nil:
		return NewIPv4AddressSpecificExtended(subtype, elems[1], uint16(localAdmin), isTransitive), nil
	case ip.To16() != nil:
		return NewIPv6AddressSpecificExtended(subtype, elems[1], uint16(localAdmin), isTransitive), nil
	case elems[6] == "" && elems[7] == "":
		asn, _ := strconv.ParseUint(elems[8], 10, 16)
		return NewTwoOctetAsSpecificExtended(subtype, uint16(asn), uint32(localAdmin), isTransitive), nil
	default:
		fst, _ := strconv.ParseUint(elems[7], 10, 16)
		snd, _ := strconv.ParseUint(elems[8], 10, 16)
		asn := fst<<16 | snd
		return NewFourOctetAsSpecificExtended(subtype, uint32(asn), uint16(localAdmin), isTransitive), nil
	}
}

func ParseRouteTarget(rt string) (ExtendedCommunityInterface, error) {
	return ParseExtendedCommunity(EC_SUBTYPE_ROUTE_TARGET, rt)
}

func SerializeExtendedCommunities(comms []ExtendedCommunityInterface) ([][]byte, error) {
	bufs := make([][]byte, len(comms))
	var err error
	for i, c := range comms {
		bufs[i], err = c.Serialize()
		if err != nil {
			return nil, err
		}
	}
	return bufs, err
}

type ValidationState uint8

const (
	VALIDATION_STATE_VALID     ValidationState = 0
	VALIDATION_STATE_NOT_FOUND ValidationState = 1
	VALIDATION_STATE_INVALID   ValidationState = 2
)

func (s ValidationState) String() string {
	switch s {
	case VALIDATION_STATE_VALID:
		return "valid"
	case VALIDATION_STATE_NOT_FOUND:
		return "not-found"
	case VALIDATION_STATE_INVALID:
		return "invalid"
	}
	return fmt.Sprintf("unknown validation state(%d)", s)
}

type ValidationExtended struct {
	State ValidationState
}

func (e *ValidationExtended) Serialize() ([]byte, error) {
	buf := make([]byte, 8)
	typ, subType := e.GetTypes()
	buf[0] = byte(typ)
	buf[1] = byte(subType)
	buf[7] = byte(e.State)
	return buf, nil
}

func (e *ValidationExtended) String() string {
	return e.State.String()
}

func (e *ValidationExtended) GetTypes() (ExtendedCommunityAttrType, ExtendedCommunityAttrSubType) {
	return EC_TYPE_NON_TRANSITIVE_OPAQUE, EC_SUBTYPE_ORIGIN_VALIDATION
}

func (e *ValidationExtended) MarshalJSON() ([]byte, error) {
	t, s := e.GetTypes()
	return json.Marshal(struct {
		Type    ExtendedCommunityAttrType    `json:"type"`
		SubType ExtendedCommunityAttrSubType `json:"subtype"`
		State   ValidationState              `json:"value"`
	}{
		Type:    t,
		SubType: s,
		State:   e.State,
	})
}

func NewValidationExtended(state ValidationState) *ValidationExtended {
	return &ValidationExtended{
		State: state,
	}
}

type LinkBandwidthExtended struct {
	AS        uint16
	Bandwidth float32
}

func (e *LinkBandwidthExtended) GetTypes() (ExtendedCommunityAttrType, ExtendedCommunityAttrSubType) {
	return EC_TYPE_NON_TRANSITIVE_LINK_BANDWIDTH, EC_SUBTYPE_LINK_BANDWIDTH
}

func (e *LinkBandwidthExtended) Serialize() ([]byte, error) {
	buf := make([]byte, 8)
	typ, subType := e.GetTypes()
	buf[0] = byte(typ)
	buf[1] = byte(subType)
	binary.BigEndian.PutUint16(buf[2:4], e.AS)
	binary.BigEndian.PutUint32(buf[4:8], math.Float32bits(e.Bandwidth))
	return buf, nil
}

func (e *LinkBandwidthExtended) String() string {
	return fmt.Sprintf("%d:%d", e.AS, uint32(e.Bandwidth))
}

func (e *LinkBandwidthExtended) MarshalJSON() ([]byte, error) {
	t, s := e.GetTypes()
	return json.Marshal(struct {
		Type      ExtendedCommunityAttrType    `json:"type"`
		SubType   ExtendedCommunityAttrSubType `json:"subtype"`
		AS        uint16                       `json:"asn"`
		Bandwidth float32                      `json:"bandwidth"`
	}{
		Type:      t,
		SubType:   s,
		AS:        e.AS,
		Bandwidth: e.Bandwidth,
	})
}

func NewLinkBandwidthExtended(as uint16, bw float32) *LinkBandwidthExtended {
	return &LinkBandwidthExtended{
		AS:        as,
		Bandwidth: bw,
	}
}

type ColorExtended struct {
	Color uint32
}

func (e *ColorExtended) Serialize() ([]byte, error) {
	buf := make([]byte, 8)
	typ, subType := e.GetTypes()
	buf[0] = byte(typ)
	buf[1] = byte(subType)
	binary.BigEndian.PutUint32(buf[4:8], uint32(e.Color))
	return buf, nil
}

func (e *ColorExtended) String() string {
	return fmt.Sprintf("%d", e.Color)
}

func (e *ColorExtended) GetTypes() (ExtendedCommunityAttrType, ExtendedCommunityAttrSubType) {
	return EC_TYPE_TRANSITIVE_OPAQUE, EC_SUBTYPE_COLOR
}

func (e *ColorExtended) MarshalJSON() ([]byte, error) {
	t, s := e.GetTypes()
	return json.Marshal(struct {
		Type    ExtendedCommunityAttrType    `json:"type"`
		SubType ExtendedCommunityAttrSubType `json:"subtype"`
		Color   uint32                       `json:"color"`
	}{
		Type:    t,
		SubType: s,
		Color:   e.Color,
	})
}

func NewColorExtended(color uint32) *ColorExtended {
	return &ColorExtended{
		Color: color,
	}
}

type EncapExtended struct {
	TunnelType TunnelType
}

func (e *EncapExtended) Serialize() ([]byte, error) {
	buf := make([]byte, 8)
	typ, subType := e.GetTypes()
	buf[0] = byte(typ)
	buf[1] = byte(subType)
	binary.BigEndian.PutUint16(buf[6:8], uint16(e.TunnelType))
	return buf, nil
}

func (e *EncapExtended) String() string {
	switch e.TunnelType {
	case TUNNEL_TYPE_L2TP3:
		return "L2TPv3 over IP"
	case TUNNEL_TYPE_GRE:
		return "GRE"
	case TUNNEL_TYPE_IP_IN_IP:
		return "IP in IP"
	case TUNNEL_TYPE_VXLAN:
		return "VXLAN"
	case TUNNEL_TYPE_NVGRE:
		return "NVGRE"
	case TUNNEL_TYPE_MPLS:
		return "MPLS"
	case TUNNEL_TYPE_MPLS_IN_GRE:
		return "MPLS in GRE"
	case TUNNEL_TYPE_VXLAN_GRE:
		return "VXLAN GRE"
	case TUNNEL_TYPE_MPLS_IN_UDP:
		return "MPLS in UDP"
	case TUNNEL_TYPE_SR_POLICY:
		return "SR Policy"
	case TUNNEL_TYPE_GENEVE:
		return "GENEVE"
	default:
		return fmt.Sprintf("tunnel: %d", e.TunnelType)
	}
}

func (e *EncapExtended) GetTypes() (ExtendedCommunityAttrType, ExtendedCommunityAttrSubType) {
	return EC_TYPE_TRANSITIVE_OPAQUE, EC_SUBTYPE_ENCAPSULATION
}

func (e *EncapExtended) MarshalJSON() ([]byte, error) {
	t, s := e.GetTypes()
	return json.Marshal(struct {
		Type       ExtendedCommunityAttrType    `json:"type"`
		SubType    ExtendedCommunityAttrSubType `json:"subtype"`
		TunnelType TunnelType                   `json:"tunnel_type"`
	}{
		Type:       t,
		SubType:    s,
		TunnelType: e.TunnelType,
	})
}

func NewEncapExtended(tunnelType TunnelType) *EncapExtended {
	return &EncapExtended{
		TunnelType: tunnelType,
	}
}

type DefaultGatewayExtended struct {
}

func (e *DefaultGatewayExtended) Serialize() ([]byte, error) {
	buf := make([]byte, 8)
	typ, subType := e.GetTypes()
	buf[0] = byte(typ)
	buf[1] = byte(subType)
	return buf, nil
}

func (e *DefaultGatewayExtended) String() string {
	return "default-gateway"
}

func (e *DefaultGatewayExtended) GetTypes() (ExtendedCommunityAttrType, ExtendedCommunityAttrSubType) {
	return EC_TYPE_TRANSITIVE_OPAQUE, EC_SUBTYPE_DEFAULT_GATEWAY
}

func (e *DefaultGatewayExtended) MarshalJSON() ([]byte, error) {
	t, s := e.GetTypes()
	return json.Marshal(struct {
		Type    ExtendedCommunityAttrType    `json:"type"`
		SubType ExtendedCommunityAttrSubType `json:"subtype"`
	}{
		Type:    t,
		SubType: s,
	})
}

func NewDefaultGatewayExtended() *DefaultGatewayExtended {
	return &DefaultGatewayExtended{}
}

type OpaqueExtended struct {
	IsTransitive bool
	Value        []byte
}

func (e *OpaqueExtended) Serialize() ([]byte, error) {
	if len(e.Value) != 7 {
		return nil, fmt.Errorf("invalid value length for opaque extended community: %d", len(e.Value))
	}
	buf := make([]byte, 8)
	if e.IsTransitive {
		buf[0] = byte(EC_TYPE_TRANSITIVE_OPAQUE)
	} else {
		buf[0] = byte(EC_TYPE_NON_TRANSITIVE_OPAQUE)
	}
	copy(buf[1:], e.Value)
	return buf, nil
}

func (e *OpaqueExtended) String() string {
	var buf [8]byte
	copy(buf[1:], e.Value)
	return fmt.Sprintf("%d", binary.BigEndian.Uint64(buf[:]))
}

func (e *OpaqueExtended) GetTypes() (ExtendedCommunityAttrType, ExtendedCommunityAttrSubType) {
	var subType ExtendedCommunityAttrSubType
	if len(e.Value) > 0 {
		// Use the first byte of value as the sub type
		subType = ExtendedCommunityAttrSubType(e.Value[0])
	}
	if e.IsTransitive {
		return EC_TYPE_TRANSITIVE_OPAQUE, subType
	}
	return EC_TYPE_NON_TRANSITIVE_OPAQUE, subType
}

func (e *OpaqueExtended) MarshalJSON() ([]byte, error) {
	t, s := e.GetTypes()
	return json.Marshal(struct {
		Type    ExtendedCommunityAttrType    `json:"type"`
		Subtype ExtendedCommunityAttrSubType `json:"subtype"`
		Value   []byte                       `json:"value"`
	}{
		Type:    t,
		Subtype: s,
		Value:   e.Value,
	})
}

func NewOpaqueExtended(isTransitive bool, value []byte) *OpaqueExtended {
	v := make([]byte, 7)
	copy(v, value)
	return &OpaqueExtended{
		IsTransitive: isTransitive,
		Value:        v,
	}
}

func parseOpaqueExtended(data []byte) (ExtendedCommunityInterface, error) {
	typ := ExtendedCommunityAttrType(data[0])
	isTransitive := false
	switch typ {
	case EC_TYPE_TRANSITIVE_OPAQUE:
		isTransitive = true
	case EC_TYPE_NON_TRANSITIVE_OPAQUE:
		// isTransitive = false
	default:
		return nil, NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, fmt.Sprintf("invalid opaque extended community type: %d", data[0]))
	}
	subType := ExtendedCommunityAttrSubType(data[1])

	if isTransitive {
		switch subType {
		case EC_SUBTYPE_COLOR:
			return &ColorExtended{
				Color: binary.BigEndian.Uint32(data[4:8]),
			}, nil
		case EC_SUBTYPE_ENCAPSULATION:
			return &EncapExtended{
				TunnelType: TunnelType(binary.BigEndian.Uint16(data[6:8])),
			}, nil
		case EC_SUBTYPE_DEFAULT_GATEWAY:
			return &DefaultGatewayExtended{}, nil
		}
	} else {
		switch subType {
		case EC_SUBTYPE_ORIGIN_VALIDATION:
			return &ValidationExtended{
				State: ValidationState(data[7]),
			}, nil
		}
	}
	return NewOpaqueExtended(isTransitive, data[1:8]), nil
}

type ESILabelExtended struct {
	Label          uint32
	IsSingleActive bool
}

func (e *ESILabelExtended) Serialize() ([]byte, error) {
	buf := make([]byte, 8)
	buf[0] = byte(EC_TYPE_EVPN)
	buf[1] = byte(EC_SUBTYPE_ESI_LABEL)
	if e.IsSingleActive {
		buf[2] = byte(1)
	}
	buf[3] = 0
	buf[4] = 0
	buf[5] = byte((e.Label >> 16) & 0xff)
	buf[6] = byte((e.Label >> 8) & 0xff)
	buf[7] = byte(e.Label & 0xff)
	return buf, nil
}

func (e *ESILabelExtended) String() string {
	buf := bytes.NewBuffer(make([]byte, 0, 32))
	buf.WriteString(fmt.Sprintf("esi-label: %d", e.Label))
	if e.IsSingleActive {
		buf.WriteString(", single-active")
	}
	return buf.String()
}

func (e *ESILabelExtended) MarshalJSON() ([]byte, error) {
	t, s := e.GetTypes()
	return json.Marshal(struct {
		Type           ExtendedCommunityAttrType    `json:"type"`
		Subtype        ExtendedCommunityAttrSubType `json:"subtype"`
		Label          uint32                       `json:"label"`
		IsSingleActive bool                         `json:"is_single_active"`
	}{
		Type:           t,
		Subtype:        s,
		Label:          e.Label,
		IsSingleActive: e.IsSingleActive,
	})
}

func (e *ESILabelExtended) GetTypes() (ExtendedCommunityAttrType, ExtendedCommunityAttrSubType) {
	return EC_TYPE_EVPN, EC_SUBTYPE_ESI_LABEL
}

func NewESILabelExtended(label uint32, isSingleActive bool) *ESILabelExtended {
	return &ESILabelExtended{
		Label:          label,
		IsSingleActive: isSingleActive,
	}
}

type ESImportRouteTarget struct {
	ESImport net.HardwareAddr
}

func (e *ESImportRouteTarget) Serialize() ([]byte, error) {
	buf := make([]byte, 8)
	buf[0] = byte(EC_TYPE_EVPN)
	buf[1] = byte(EC_SUBTYPE_ES_IMPORT)
	copy(buf[2:], e.ESImport)
	return buf, nil
}

func (e *ESImportRouteTarget) String() string {
	return fmt.Sprintf("es-import rt: %s", e.ESImport.String())
}

func (e *ESImportRouteTarget) MarshalJSON() ([]byte, error) {
	t, s := e.GetTypes()
	return json.Marshal(struct {
		Type    ExtendedCommunityAttrType    `json:"type"`
		Subtype ExtendedCommunityAttrSubType `json:"subtype"`
		Value   string                       `json:"value"`
	}{
		Type:    t,
		Subtype: s,
		Value:   e.ESImport.String(),
	})
}

func (e *ESImportRouteTarget) GetTypes() (ExtendedCommunityAttrType, ExtendedCommunityAttrSubType) {
	return EC_TYPE_EVPN, EC_SUBTYPE_ES_IMPORT
}

func NewESImportRouteTarget(mac string) *ESImportRouteTarget {
	esImport, err := net.ParseMAC(mac)
	if err != nil {
		return nil
	}
	return &ESImportRouteTarget{
		ESImport: esImport,
	}
}

type MacMobilityExtended struct {
	Sequence uint32
	IsSticky bool
}

func (e *MacMobilityExtended) Serialize() ([]byte, error) {
	buf := make([]byte, 8)
	buf[0] = byte(EC_TYPE_EVPN)
	buf[1] = byte(EC_SUBTYPE_MAC_MOBILITY)
	if e.IsSticky {
		buf[2] = byte(1)
	}
	binary.BigEndian.PutUint32(buf[4:], e.Sequence)
	return buf, nil
}

func (e *MacMobilityExtended) String() string {
	buf := bytes.NewBuffer(make([]byte, 0, 32))
	buf.WriteString(fmt.Sprintf("mac-mobility: %d", e.Sequence))
	if e.IsSticky {
		buf.WriteString(", sticky")
	}
	return buf.String()
}

func (e *MacMobilityExtended) MarshalJSON() ([]byte, error) {
	t, s := e.GetTypes()
	return json.Marshal(struct {
		Type     ExtendedCommunityAttrType    `json:"type"`
		Subtype  ExtendedCommunityAttrSubType `json:"subtype"`
		Sequence uint32                       `json:"sequence"`
		IsSticky bool                         `json:"is_sticky"`
	}{
		Type:     t,
		Subtype:  s,
		Sequence: e.Sequence,
		IsSticky: e.IsSticky,
	})
}

func (e *MacMobilityExtended) GetTypes() (ExtendedCommunityAttrType, ExtendedCommunityAttrSubType) {
	return EC_TYPE_EVPN, EC_SUBTYPE_MAC_MOBILITY
}

func NewMacMobilityExtended(seq uint32, isSticky bool) *MacMobilityExtended {
	return &MacMobilityExtended{
		Sequence: seq,
		IsSticky: isSticky,
	}
}

type RouterMacExtended struct {
	Mac net.HardwareAddr
}

func (e *RouterMacExtended) Serialize() ([]byte, error) {
	buf := make([]byte, 2, 8)
	buf[0] = byte(EC_TYPE_EVPN)
	buf[1] = byte(EC_SUBTYPE_ROUTER_MAC)
	buf = append(buf, e.Mac...)
	return buf, nil
}

func (e *RouterMacExtended) String() string {
	return fmt.Sprintf("router's mac: %s", e.Mac.String())
}

func (e *RouterMacExtended) MarshalJSON() ([]byte, error) {
	t, s := e.GetTypes()
	return json.Marshal(struct {
		Type    ExtendedCommunityAttrType    `json:"type"`
		Subtype ExtendedCommunityAttrSubType `json:"subtype"`
		Mac     string                       `json:"mac"`
	}{
		Type:    t,
		Subtype: s,
		Mac:     e.Mac.String(),
	})
}

func (e *RouterMacExtended) GetTypes() (ExtendedCommunityAttrType, ExtendedCommunityAttrSubType) {
	return EC_TYPE_EVPN, EC_SUBTYPE_ROUTER_MAC
}

func NewRoutersMacExtended(mac string) *RouterMacExtended {
	hw, err := net.ParseMAC(mac)
	if err != nil {
		return nil
	}
	return &RouterMacExtended{
		Mac: hw,
	}
}

func parseEvpnExtended(data []byte) (ExtendedCommunityInterface, error) {
	if ExtendedCommunityAttrType(data[0]) != EC_TYPE_EVPN {
		return nil, NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, fmt.Sprintf("ext comm type is not EC_TYPE_EVPN: %d", data[0]))
	}
	subType := ExtendedCommunityAttrSubType(data[1])
	switch subType {
	case EC_SUBTYPE_ESI_LABEL:
		var isSingleActive bool
		if data[2] > 0 {
			isSingleActive = true
		}
		label := uint32(data[5])<<16 | uint32(data[6])<<8 | uint32(data[7])
		return &ESILabelExtended{
			IsSingleActive: isSingleActive,
			Label:          label,
		}, nil
	case EC_SUBTYPE_ES_IMPORT:
		return &ESImportRouteTarget{
			ESImport: net.HardwareAddr(data[2:8]),
		}, nil
	case EC_SUBTYPE_MAC_MOBILITY:
		var isSticky bool
		if data[2] > 0 {
			isSticky = true
		}
		seq := binary.BigEndian.Uint32(data[4:8])
		return &MacMobilityExtended{
			Sequence: seq,
			IsSticky: isSticky,
		}, nil
	case EC_SUBTYPE_ROUTER_MAC:
		return &RouterMacExtended{
			Mac: net.HardwareAddr(data[2:8]),
		}, nil
	}
	return nil, NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, fmt.Sprintf("unknown evpn subtype: %d", subType))
}

type TrafficRateExtended struct {
	AS   uint16
	Rate float32
}

func (e *TrafficRateExtended) Serialize() ([]byte, error) {
	buf := make([]byte, 8)
	buf[0] = byte(EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL)
	buf[1] = byte(EC_SUBTYPE_FLOWSPEC_TRAFFIC_RATE)
	binary.BigEndian.PutUint16(buf[2:4], e.AS)
	binary.BigEndian.PutUint32(buf[4:8], math.Float32bits(e.Rate))
	return buf, nil
}

func (e *TrafficRateExtended) String() string {
	buf := bytes.NewBuffer(make([]byte, 0, 32))
	if e.Rate == 0 {
		buf.WriteString("discard")
	} else {
		buf.WriteString(fmt.Sprintf("rate: %f", e.Rate))
	}
	if e.AS != 0 {
		buf.WriteString(fmt.Sprintf("(as: %d)", e.AS))
	}
	return buf.String()
}

func (e *TrafficRateExtended) MarshalJSON() ([]byte, error) {
	t, s := e.GetTypes()
	return json.Marshal(struct {
		Type    ExtendedCommunityAttrType    `json:"type"`
		Subtype ExtendedCommunityAttrSubType `json:"subtype"`
		As      uint16                       `json:"as"`
		Rate    float32                      `json:"rate"`
	}{t, s, e.AS, e.Rate})
}

func (e *TrafficRateExtended) GetTypes() (ExtendedCommunityAttrType, ExtendedCommunityAttrSubType) {
	return EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL, EC_SUBTYPE_FLOWSPEC_TRAFFIC_RATE
}

func NewTrafficRateExtended(as uint16, rate float32) *TrafficRateExtended {
	return &TrafficRateExtended{
		AS:   as,
		Rate: rate,
	}
}

type TrafficActionExtended struct {
	Terminal bool
	Sample   bool
}

func (e *TrafficActionExtended) Serialize() ([]byte, error) {
	buf := make([]byte, 8)
	buf[0] = byte(EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL)
	buf[1] = byte(EC_SUBTYPE_FLOWSPEC_TRAFFIC_ACTION)
	if e.Terminal {
		buf[7] = 0x01
	}
	if e.Sample {
		buf[7] = buf[7] | 0x2
	}
	return buf, nil
}

func (e *TrafficActionExtended) String() string {
	ss := make([]string, 0, 2)
	if e.Terminal {
		ss = append(ss, "terminal")
	}
	if e.Sample {
		ss = append(ss, "sample")
	}
	return fmt.Sprintf("action: %s", strings.Join(ss, "-"))
}

func (e *TrafficActionExtended) MarshalJSON() ([]byte, error) {
	t, s := e.GetTypes()
	return json.Marshal(struct {
		Type     ExtendedCommunityAttrType    `json:"type"`
		Subtype  ExtendedCommunityAttrSubType `json:"subtype"`
		Terminal bool                         `json:"terminal"`
		Sample   bool                         `json:"sample"`
	}{t, s, e.Terminal, e.Sample})
}

func (e *TrafficActionExtended) GetTypes() (ExtendedCommunityAttrType, ExtendedCommunityAttrSubType) {
	return EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL, EC_SUBTYPE_FLOWSPEC_TRAFFIC_ACTION
}

func NewTrafficActionExtended(terminal bool, sample bool) *TrafficActionExtended {
	return &TrafficActionExtended{
		Terminal: terminal,
		Sample:   sample,
	}
}

type RedirectTwoOctetAsSpecificExtended struct {
	TwoOctetAsSpecificExtended
}

func (e *RedirectTwoOctetAsSpecificExtended) Serialize() ([]byte, error) {
	buf, err := e.TwoOctetAsSpecificExtended.Serialize()
	buf[0] = byte(EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL)
	buf[1] = byte(EC_SUBTYPE_FLOWSPEC_REDIRECT)
	return buf, err
}

func (e *RedirectTwoOctetAsSpecificExtended) String() string {
	return fmt.Sprintf("redirect: %s", e.TwoOctetAsSpecificExtended.String())
}

func (e *RedirectTwoOctetAsSpecificExtended) MarshalJSON() ([]byte, error) {
	t, s := e.GetTypes()
	return json.Marshal(struct {
		Type    ExtendedCommunityAttrType    `json:"type"`
		Subtype ExtendedCommunityAttrSubType `json:"subtype"`
		Value   string                       `json:"value"`
	}{t, s, e.TwoOctetAsSpecificExtended.String()})
}

func (e *RedirectTwoOctetAsSpecificExtended) GetTypes() (ExtendedCommunityAttrType, ExtendedCommunityAttrSubType) {
	return EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL, EC_SUBTYPE_FLOWSPEC_REDIRECT
}

func NewRedirectTwoOctetAsSpecificExtended(as uint16, localAdmin uint32) *RedirectTwoOctetAsSpecificExtended {
	return &RedirectTwoOctetAsSpecificExtended{*NewTwoOctetAsSpecificExtended(EC_SUBTYPE_ROUTE_TARGET, as, localAdmin, false)}
}

type RedirectIPv4AddressSpecificExtended struct {
	IPv4AddressSpecificExtended
}

func (e *RedirectIPv4AddressSpecificExtended) Serialize() ([]byte, error) {
	buf, err := e.IPv4AddressSpecificExtended.Serialize()
	buf[0] = byte(EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL2)
	buf[1] = byte(EC_SUBTYPE_FLOWSPEC_REDIRECT)
	return buf, err
}

func (e *RedirectIPv4AddressSpecificExtended) String() string {
	return fmt.Sprintf("redirect: %s", e.IPv4AddressSpecificExtended.String())
}

func (e *RedirectIPv4AddressSpecificExtended) MarshalJSON() ([]byte, error) {
	t, s := e.GetTypes()
	return json.Marshal(struct {
		Type    ExtendedCommunityAttrType    `json:"type"`
		Subtype ExtendedCommunityAttrSubType `json:"subtype"`
		Value   string                       `json:"value"`
	}{t, s, e.IPv4AddressSpecificExtended.String()})
}

func (e *RedirectIPv4AddressSpecificExtended) GetTypes() (ExtendedCommunityAttrType, ExtendedCommunityAttrSubType) {
	return EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL2, EC_SUBTYPE_FLOWSPEC_REDIRECT
}

func NewRedirectIPv4AddressSpecificExtended(ipv4 string, localAdmin uint16) *RedirectIPv4AddressSpecificExtended {
	e := NewIPv4AddressSpecificExtended(EC_SUBTYPE_ROUTE_TARGET, ipv4, localAdmin, false)
	if e == nil {
		return nil
	}
	return &RedirectIPv4AddressSpecificExtended{*e}
}

type RedirectIPv6AddressSpecificExtended struct {
	IPv6AddressSpecificExtended
}

func (e *RedirectIPv6AddressSpecificExtended) Serialize() ([]byte, error) {
	buf, err := e.IPv6AddressSpecificExtended.Serialize()
	buf[0] = byte(EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL)
	buf[1] = byte(EC_SUBTYPE_FLOWSPEC_REDIRECT_IP6)
	return buf, err
}

func (e *RedirectIPv6AddressSpecificExtended) String() string {
	return fmt.Sprintf("redirect: %s", e.IPv6AddressSpecificExtended.String())
}

func (e *RedirectIPv6AddressSpecificExtended) MarshalJSON() ([]byte, error) {
	t, s := e.GetTypes()
	return json.Marshal(struct {
		Type    ExtendedCommunityAttrType    `json:"type"`
		Subtype ExtendedCommunityAttrSubType `json:"subtype"`
		Value   string                       `json:"value"`
	}{t, s, e.IPv6AddressSpecificExtended.String()})
}

func (e *RedirectIPv6AddressSpecificExtended) GetTypes() (ExtendedCommunityAttrType, ExtendedCommunityAttrSubType) {
	return EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL, EC_SUBTYPE_FLOWSPEC_REDIRECT_IP6
}

func NewRedirectIPv6AddressSpecificExtended(ipv6 string, localAdmin uint16) *RedirectIPv6AddressSpecificExtended {
	e := NewIPv6AddressSpecificExtended(EC_SUBTYPE_ROUTE_TARGET, ipv6, localAdmin, false)
	if e == nil {
		return nil
	}
	return &RedirectIPv6AddressSpecificExtended{*e}
}

type RedirectFourOctetAsSpecificExtended struct {
	FourOctetAsSpecificExtended
}

func (e *RedirectFourOctetAsSpecificExtended) Serialize() ([]byte, error) {
	buf, err := e.FourOctetAsSpecificExtended.Serialize()
	buf[0] = byte(EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL3)
	buf[1] = byte(EC_SUBTYPE_FLOWSPEC_REDIRECT)
	return buf, err
}

func (e *RedirectFourOctetAsSpecificExtended) String() string {
	return fmt.Sprintf("redirect: %s", e.FourOctetAsSpecificExtended.String())
}

func (e *RedirectFourOctetAsSpecificExtended) MarshalJSON() ([]byte, error) {
	t, s := e.GetTypes()
	return json.Marshal(struct {
		Type    ExtendedCommunityAttrType    `json:"type"`
		Subtype ExtendedCommunityAttrSubType `json:"subtype"`
		Value   string                       `json:"value"`
	}{t, s, e.FourOctetAsSpecificExtended.String()})
}

func (e *RedirectFourOctetAsSpecificExtended) GetTypes() (ExtendedCommunityAttrType, ExtendedCommunityAttrSubType) {
	return EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL3, EC_SUBTYPE_FLOWSPEC_REDIRECT
}

func NewRedirectFourOctetAsSpecificExtended(as uint32, localAdmin uint16) *RedirectFourOctetAsSpecificExtended {
	return &RedirectFourOctetAsSpecificExtended{*NewFourOctetAsSpecificExtended(EC_SUBTYPE_ROUTE_TARGET, as, localAdmin, false)}
}

type TrafficRemarkExtended struct {
	DSCP uint8
}

func (e *TrafficRemarkExtended) Serialize() ([]byte, error) {
	buf := make([]byte, 8)
	buf[0] = byte(EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL)
	buf[1] = byte(EC_SUBTYPE_FLOWSPEC_TRAFFIC_REMARK)
	buf[7] = byte(e.DSCP)
	return buf, nil
}

func (e *TrafficRemarkExtended) String() string {
	return fmt.Sprintf("remark: %d", e.DSCP)
}

func (e *TrafficRemarkExtended) MarshalJSON() ([]byte, error) {
	t, s := e.GetTypes()
	return json.Marshal(struct {
		Type    ExtendedCommunityAttrType    `json:"type"`
		Subtype ExtendedCommunityAttrSubType `json:"subtype"`
		Value   uint8                        `json:"value"`
	}{t, s, e.DSCP})
}

func (e *TrafficRemarkExtended) GetTypes() (ExtendedCommunityAttrType, ExtendedCommunityAttrSubType) {
	return EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL, EC_SUBTYPE_FLOWSPEC_TRAFFIC_REMARK
}

func NewTrafficRemarkExtended(dscp uint8) *TrafficRemarkExtended {
	return &TrafficRemarkExtended{
		DSCP: dscp,
	}
}

func parseFlowSpecExtended(data []byte) (ExtendedCommunityInterface, error) {
	typ := ExtendedCommunityAttrType(data[0])
	if typ != EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL && typ != EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL2 && typ != EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL3 {
		return nil, NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, fmt.Sprintf("ext comm type is not EC_TYPE_FLOWSPEC: %d", data[0]))
	}
	subType := ExtendedCommunityAttrSubType(data[1])
	switch subType {
	case EC_SUBTYPE_FLOWSPEC_TRAFFIC_RATE:
		asn := binary.BigEndian.Uint16(data[2:4])
		bits := binary.BigEndian.Uint32(data[4:8])
		rate := math.Float32frombits(bits)
		return NewTrafficRateExtended(asn, rate), nil
	case EC_SUBTYPE_FLOWSPEC_TRAFFIC_ACTION:
		terminal := data[7]&0x1 == 1
		sample := (data[7]>>1)&0x1 == 1
		return NewTrafficActionExtended(terminal, sample), nil
	case EC_SUBTYPE_FLOWSPEC_REDIRECT:
		// RFC7674
		switch typ {
		case EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL:
			as := binary.BigEndian.Uint16(data[2:4])
			localAdmin := binary.BigEndian.Uint32(data[4:8])
			return NewRedirectTwoOctetAsSpecificExtended(as, localAdmin), nil
		case EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL2:
			ipv4 := net.IP(data[2:6]).String()
			localAdmin := binary.BigEndian.Uint16(data[6:8])
			return NewRedirectIPv4AddressSpecificExtended(ipv4, localAdmin), nil
		case EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL3:
			as := binary.BigEndian.Uint32(data[2:6])
			localAdmin := binary.BigEndian.Uint16(data[6:8])
			return NewRedirectFourOctetAsSpecificExtended(as, localAdmin), nil
		}
	case EC_SUBTYPE_FLOWSPEC_TRAFFIC_REMARK:
		dscp := data[7]
		return NewTrafficRemarkExtended(dscp), nil
	case EC_SUBTYPE_FLOWSPEC_REDIRECT_IP6:
		ipv6 := net.IP(data[2:18]).String()
		localAdmin := binary.BigEndian.Uint16(data[18:20])
		return NewRedirectIPv6AddressSpecificExtended(ipv6, localAdmin), nil
	}
	return &UnknownExtended{
		Type:  ExtendedCommunityAttrType(data[0]),
		Value: data[1:8],
	}, nil
}

func parseIP6FlowSpecExtended(data []byte) (ExtendedCommunityInterface, error) {
	typ := ExtendedCommunityAttrType(data[0])
	if typ != EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL && typ != EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL2 && typ != EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL3 {
		return nil, NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, fmt.Sprintf("ext comm type is not EC_TYPE_FLOWSPEC: %d", data[0]))
	}
	subType := ExtendedCommunityAttrSubType(data[1])
	switch subType {
	case EC_SUBTYPE_FLOWSPEC_REDIRECT_IP6:
		// RFC7674
		switch typ {
		case EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL:
			ipv6 := net.IP(data[2:18]).String()
			localAdmin := binary.BigEndian.Uint16(data[18:20])
			return NewRedirectIPv6AddressSpecificExtended(ipv6, localAdmin), nil
		}
	}
	return &UnknownExtended{
		Type:  ExtendedCommunityAttrType(data[0]),
		Value: data[1:20],
	}, nil
}

type UnknownExtended struct {
	Type  ExtendedCommunityAttrType
	Value []byte
}

func (e *UnknownExtended) Serialize() ([]byte, error) {
	if len(e.Value) != 7 {
		return nil, fmt.Errorf("invalid value length for unknown extended community: %d", len(e.Value))
	}
	buf := make([]byte, 8)
	buf[0] = uint8(e.Type)
	copy(buf[1:], e.Value)
	return buf, nil
}

func (e *UnknownExtended) String() string {
	var buf [8]byte
	copy(buf[1:], e.Value)
	return fmt.Sprintf("%d", binary.BigEndian.Uint64(buf[:]))
}

func (e *UnknownExtended) MarshalJSON() ([]byte, error) {
	t, s := e.GetTypes()
	return json.Marshal(struct {
		Type    ExtendedCommunityAttrType    `json:"type"`
		Subtype ExtendedCommunityAttrSubType `json:"subtype"`
		Value   []byte                       `json:"value"`
	}{
		Type:    t,
		Subtype: s,
		Value:   e.Value,
	})
}

func (e *UnknownExtended) GetTypes() (ExtendedCommunityAttrType, ExtendedCommunityAttrSubType) {
	var subType ExtendedCommunityAttrSubType
	if len(e.Value) > 0 {
		// Use the first byte of value as the sub type
		subType = ExtendedCommunityAttrSubType(e.Value[0])
	}
	return e.Type, subType
}

func NewUnknownExtended(typ ExtendedCommunityAttrType, value []byte) *UnknownExtended {
	v := make([]byte, 7)
	copy(v, value)
	return &UnknownExtended{
		Type:  typ,
		Value: v,
	}
}

type PathAttributeExtendedCommunities struct {
	PathAttribute
	Value []ExtendedCommunityInterface
}

func ParseExtended(data []byte) (ExtendedCommunityInterface, error) {
	if len(data) < 8 {
		return nil, NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "not all extended community bytes are available")
	}
	attrType := ExtendedCommunityAttrType(data[0])
	subtype := ExtendedCommunityAttrSubType(data[1])
	transitive := false
	switch attrType {
	case EC_TYPE_TRANSITIVE_TWO_OCTET_AS_SPECIFIC:
		transitive = true
		fallthrough
	case EC_TYPE_NON_TRANSITIVE_TWO_OCTET_AS_SPECIFIC:
		as := binary.BigEndian.Uint16(data[2:4])
		localAdmin := binary.BigEndian.Uint32(data[4:8])

		if subtype == EC_SUBTYPE_LINK_BANDWIDTH {
			return NewLinkBandwidthExtended(as, math.Float32frombits(localAdmin)), nil
		} else {
			return NewTwoOctetAsSpecificExtended(subtype, as, localAdmin, transitive), nil
		}
	case EC_TYPE_TRANSITIVE_IP4_SPECIFIC:
		transitive = true
		fallthrough
	case EC_TYPE_NON_TRANSITIVE_IP4_SPECIFIC:
		ipv4 := net.IP(data[2:6]).String()
		localAdmin := binary.BigEndian.Uint16(data[6:8])
		return NewIPv4AddressSpecificExtended(subtype, ipv4, localAdmin, transitive), nil
	case EC_TYPE_TRANSITIVE_FOUR_OCTET_AS_SPECIFIC:
		transitive = true
		fallthrough
	case EC_TYPE_NON_TRANSITIVE_FOUR_OCTET_AS_SPECIFIC:
		as := binary.BigEndian.Uint32(data[2:6])
		localAdmin := binary.BigEndian.Uint16(data[6:8])
		return NewFourOctetAsSpecificExtended(subtype, as, localAdmin, transitive), nil
	case EC_TYPE_TRANSITIVE_OPAQUE:
		transitive = true
		fallthrough
	case EC_TYPE_NON_TRANSITIVE_OPAQUE:
		return parseOpaqueExtended(data)
	case EC_TYPE_EVPN:
		return parseEvpnExtended(data)
	case EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL, EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL2, EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL3:
		return parseFlowSpecExtended(data)
	case EC_TYPE_MUP:
		return parseMUPExtended(data)
	default:
		return &UnknownExtended{
			Type:  ExtendedCommunityAttrType(data[0]),
			Value: data[1:8],
		}, nil
	}
}

func (p *PathAttributeExtendedCommunities) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	value, err := p.PathAttribute.DecodeFromBytes(data, options...)
	if err != nil {
		return err
	}
	if p.Length%8 != 0 {
		eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
		eSubCode := uint8(BGP_ERROR_SUB_ATTRIBUTE_LENGTH_ERROR)
		return NewMessageError(eCode, eSubCode, nil, "extendedcommunities length isn't correct")
	}
	for len(value) >= 8 {
		e, err := ParseExtended(value)
		if err != nil {
			return err
		}
		p.Value = append(p.Value, e)
		value = value[8:]
	}
	return nil
}

func (p *PathAttributeExtendedCommunities) Serialize(options ...*MarshallingOption) ([]byte, error) {
	buf := make([]byte, 0)
	for _, p := range p.Value {
		ebuf, err := p.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, ebuf...)
	}
	return p.PathAttribute.Serialize(buf, options...)
}

func (p *PathAttributeExtendedCommunities) String() string {
	buf := bytes.NewBuffer(make([]byte, 0, 32))
	for idx, v := range p.Value {
		buf.WriteString("[")
		buf.WriteString(v.String())
		buf.WriteString("]")
		if idx < len(p.Value)-1 {
			buf.WriteString(", ")
		}
	}
	return fmt.Sprintf("{Extcomms: %s}", buf.String())
}

func (p *PathAttributeExtendedCommunities) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  BGPAttrType                  `json:"type"`
		Value []ExtendedCommunityInterface `json:"value"`
	}{
		Type:  p.GetType(),
		Value: p.Value,
	})
}

func NewPathAttributeExtendedCommunities(value []ExtendedCommunityInterface) *PathAttributeExtendedCommunities {
	l := len(value) * 8
	t := BGP_ATTR_TYPE_EXTENDED_COMMUNITIES
	return &PathAttributeExtendedCommunities{
		PathAttribute: PathAttribute{
			Flags:  getPathAttrFlags(t, l),
			Type:   t,
			Length: uint16(l),
		},
		Value: value,
	}
}

type PathAttributeAs4Path struct {
	PathAttribute
	Value []*As4PathParam
}

func (p *PathAttributeAs4Path) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	value, err := p.PathAttribute.DecodeFromBytes(data, options...)
	if err != nil {
		return err
	}
	if p.Length == 0 {
		// ibgp or something
		return nil
	}
	eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
	eSubCode := uint8(BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST)
	isAs4, err := validateAsPathValueBytes(value)
	if err != nil {
		return err
	}

	if !isAs4 {
		return NewMessageError(eCode, eSubCode, nil, "AS4 PATH param is malformed")
	}

	for len(value) > 0 {
		tuple := &As4PathParam{}
		tuple.DecodeFromBytes(value)
		p.Value = append(p.Value, tuple)
		if len(value) < tuple.Len() {
			return NewMessageError(eCode, eSubCode, nil, "AS4 PATH param is malformed")
		}
		value = value[tuple.Len():]
	}
	return nil
}

func (p *PathAttributeAs4Path) Serialize(options ...*MarshallingOption) ([]byte, error) {
	buf := make([]byte, 0)
	for _, v := range p.Value {
		vbuf, err := v.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, vbuf...)
	}
	return p.PathAttribute.Serialize(buf, options...)
}

func (p *PathAttributeAs4Path) String() string {
	params := make([]string, 0, len(p.Value))
	for _, param := range p.Value {
		params = append(params, param.String())
	}
	return strings.Join(params, " ")
}

func (p *PathAttributeAs4Path) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  BGPAttrType     `json:"type"`
		Value []*As4PathParam `json:"as_paths"`
	}{
		Type:  p.GetType(),
		Value: p.Value,
	})
}

func NewPathAttributeAs4Path(value []*As4PathParam) *PathAttributeAs4Path {
	var l int
	for _, v := range value {
		l += v.Len()
	}
	t := BGP_ATTR_TYPE_AS4_PATH
	return &PathAttributeAs4Path{
		PathAttribute: PathAttribute{
			Flags:  getPathAttrFlags(t, l),
			Type:   t,
			Length: uint16(l),
		},
		Value: value,
	}
}

type PathAttributeAs4Aggregator struct {
	PathAttribute
	Value PathAttributeAggregatorParam
}

func (p *PathAttributeAs4Aggregator) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	value, err := p.PathAttribute.DecodeFromBytes(data, options...)
	if err != nil {
		return err
	}
	if p.Length != 8 {
		eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
		eSubCode := uint8(BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST)
		return NewMessageError(eCode, eSubCode, nil, "AS4 Aggregator length is incorrect")
	}
	p.Value.AS = binary.BigEndian.Uint32(value[0:4])
	p.Value.Address = value[4:]
	return nil
}

func (p *PathAttributeAs4Aggregator) Serialize(options ...*MarshallingOption) ([]byte, error) {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint32(buf[0:], p.Value.AS)
	copy(buf[4:], p.Value.Address.To4())
	return p.PathAttribute.Serialize(buf, options...)
}

func (p *PathAttributeAs4Aggregator) String() string {
	return fmt.Sprintf("{As4Aggregator: {AS: %d, Address: %s}}", p.Value.AS, p.Value.Address)
}

func (p *PathAttributeAs4Aggregator) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type    BGPAttrType `json:"type"`
		AS      uint32      `json:"as"`
		Address string      `json:"address"`
	}{
		Type:    p.GetType(),
		AS:      p.Value.AS,
		Address: p.Value.Address.String(),
	})
}

func NewPathAttributeAs4Aggregator(as uint32, address string) *PathAttributeAs4Aggregator {
	t := BGP_ATTR_TYPE_AS4_AGGREGATOR
	return &PathAttributeAs4Aggregator{
		PathAttribute: PathAttribute{
			Flags:  PathAttrFlags[t],
			Type:   t,
			Length: 8,
		},
		Value: PathAttributeAggregatorParam{
			AS:      as,
			Address: net.ParseIP(address).To4(),
		},
	}
}

type TunnelEncapSubTLVInterface interface {
	Len() int
	DecodeFromBytes([]byte) error
	Serialize() ([]byte, error)
	String() string
	MarshalJSON() ([]byte, error)
}

type TunnelEncapSubTLV struct {
	Type   EncapSubTLVType
	Length uint16
}

func (t *TunnelEncapSubTLV) Len() int {
	if t.Type >= 0x80 {
		return 3 + int(t.Length)
	}
	return 2 + int(t.Length)
}

func (t *TunnelEncapSubTLV) DecodeFromBytes(data []byte) (value []byte, err error) {
	t.Type = EncapSubTLVType(data[0])
	if t.Type >= 0x80 {
		t.Length = binary.BigEndian.Uint16(data[1:3])
		data = data[3:]
	} else {
		t.Length = uint16(data[1])
		data = data[2:]
	}
	if len(data) < int(t.Length) {
		return nil, NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "Not all TunnelEncapSubTLV bytes available")
	}
	return data[:t.Length], nil
}

func (t *TunnelEncapSubTLV) Serialize(value []byte) (buf []byte, err error) {
	t.Length = uint16(len(value))
	if t.Type >= 0x80 {
		buf = append(make([]byte, 3), value...)
		binary.BigEndian.PutUint16(buf[1:3], t.Length)
	} else {
		buf = append(make([]byte, 2), value...)
		buf[1] = uint8(t.Length)
	}
	buf[0] = uint8(t.Type)
	return buf, nil
}

type TunnelEncapSubTLVUnknown struct {
	TunnelEncapSubTLV
	Value []byte
}

func (t *TunnelEncapSubTLVUnknown) DecodeFromBytes(data []byte) error {
	value, err := t.TunnelEncapSubTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	t.Value = value
	return nil
}

func (t *TunnelEncapSubTLVUnknown) Serialize() ([]byte, error) {
	return t.TunnelEncapSubTLV.Serialize(t.Value)
}

func (t *TunnelEncapSubTLVUnknown) String() string {
	return fmt.Sprintf("{Type: %d, Value: %x}", t.Type, t.Value)
}

func (t *TunnelEncapSubTLVUnknown) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  EncapSubTLVType `json:"type"`
		Value []byte          `json:"value"`
	}{
		Type:  t.Type,
		Value: t.Value,
	})
}

func NewTunnelEncapSubTLVUnknown(typ EncapSubTLVType, value []byte) *TunnelEncapSubTLVUnknown {
	return &TunnelEncapSubTLVUnknown{
		TunnelEncapSubTLV: TunnelEncapSubTLV{
			Type: typ,
		},
		Value: value,
	}
}

type TunnelEncapSubTLVEncapsulation struct {
	TunnelEncapSubTLV
	Key    uint32 // this represent both SessionID for L2TPv3 case and GRE-key for GRE case (RFC5512 4.)
	Cookie []byte
}

func (t *TunnelEncapSubTLVEncapsulation) DecodeFromBytes(data []byte) error {
	value, err := t.TunnelEncapSubTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	if t.Length < 4 {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "Not all TunnelEncapSubTLVEncapsulation bytes available")
	}
	t.Key = binary.BigEndian.Uint32(value[0:4])
	t.Cookie = value[4:]
	return nil
}

func (t *TunnelEncapSubTLVEncapsulation) Serialize() ([]byte, error) {
	buf := make([]byte, 4, 4+len(t.Cookie))
	binary.BigEndian.PutUint32(buf, t.Key)
	buf = append(buf, t.Cookie...)
	return t.TunnelEncapSubTLV.Serialize(buf)
}

func (t *TunnelEncapSubTLVEncapsulation) String() string {
	return fmt.Sprintf("{Key: %d, Cookie: %x}", t.Key, t.Cookie)
}

func (t *TunnelEncapSubTLVEncapsulation) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type   EncapSubTLVType `json:"type"`
		Key    uint32          `json:"key"`
		Cookie []byte          `json:"cookie"`
	}{
		Type:   t.Type,
		Key:    t.Key,
		Cookie: t.Cookie,
	})
}

func NewTunnelEncapSubTLVEncapsulation(key uint32, cookie []byte) *TunnelEncapSubTLVEncapsulation {
	return &TunnelEncapSubTLVEncapsulation{
		TunnelEncapSubTLV: TunnelEncapSubTLV{
			Type: ENCAP_SUBTLV_TYPE_ENCAPSULATION,
		},
		Key:    key,
		Cookie: cookie,
	}
}

type TunnelEncapSubTLVProtocol struct {
	TunnelEncapSubTLV
	Protocol uint16
}

func (t *TunnelEncapSubTLVProtocol) DecodeFromBytes(data []byte) error {
	value, err := t.TunnelEncapSubTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	if t.Length < 2 {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "Not all TunnelEncapSubTLVProtocol bytes available")
	}
	t.Protocol = binary.BigEndian.Uint16(value[0:2])
	return nil
}

func (t *TunnelEncapSubTLVProtocol) Serialize() ([]byte, error) {
	var buf [2]byte
	binary.BigEndian.PutUint16(buf[:2], t.Protocol)
	return t.TunnelEncapSubTLV.Serialize(buf[:])
}

func (t *TunnelEncapSubTLVProtocol) String() string {
	return fmt.Sprintf("{Protocol: %d}", t.Protocol)
}

func (t *TunnelEncapSubTLVProtocol) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type     EncapSubTLVType `json:"type"`
		Protocol uint16          `json:"protocol"`
	}{
		Type:     t.Type,
		Protocol: t.Protocol,
	})
}

func NewTunnelEncapSubTLVProtocol(protocol uint16) *TunnelEncapSubTLVProtocol {
	return &TunnelEncapSubTLVProtocol{
		TunnelEncapSubTLV: TunnelEncapSubTLV{
			Type: ENCAP_SUBTLV_TYPE_PROTOCOL,
		},
		Protocol: protocol,
	}
}

type TunnelEncapSubTLVColor struct {
	TunnelEncapSubTLV
	Color uint32
}

func (t *TunnelEncapSubTLVColor) DecodeFromBytes(data []byte) error {
	value, err := t.TunnelEncapSubTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	if t.Length != 8 {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "Invalid TunnelEncapSubTLVColor length")
	}
	t.Color = binary.BigEndian.Uint32(value[4:8])
	return nil
}

func (t *TunnelEncapSubTLVColor) Serialize() ([]byte, error) {
	var buf [8]byte
	buf[0] = byte(EC_TYPE_TRANSITIVE_OPAQUE)
	buf[1] = byte(EC_SUBTYPE_COLOR)
	binary.BigEndian.PutUint32(buf[4:8], t.Color)
	return t.TunnelEncapSubTLV.Serialize(buf[:])
}

func (t *TunnelEncapSubTLVColor) String() string {
	return fmt.Sprintf("{Color: %d}", t.Color)
}

func (t *TunnelEncapSubTLVColor) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  EncapSubTLVType `json:"type"`
		Color uint32          `json:"color"`
	}{
		Type:  t.Type,
		Color: t.Color,
	})
}

func NewTunnelEncapSubTLVColor(color uint32) *TunnelEncapSubTLVColor {
	return &TunnelEncapSubTLVColor{
		TunnelEncapSubTLV: TunnelEncapSubTLV{
			Type: ENCAP_SUBTLV_TYPE_COLOR,
		},
		Color: color,
	}
}

type TunnelEncapSubTLVEgressEndpoint struct {
	TunnelEncapSubTLV
	Address net.IP
}

// Tunnel Egress Endpoint Sub-TLV subfield positions
const (
	EGRESS_ENDPOINT_RESERVED_POS = 0
	EGRESS_ENDPOINT_FAMILY_POS   = 4
	EGRESS_ENDPOINT_ADDRESS_POS  = 6
)

func (t *TunnelEncapSubTLVEgressEndpoint) DecodeFromBytes(data []byte) error {
	value, err := t.TunnelEncapSubTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	if t.Length < EGRESS_ENDPOINT_ADDRESS_POS {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "Not all TunnelEncapSubTLVEgressEndpoint bytes available")
	}
	addressFamily := binary.BigEndian.Uint16(value[EGRESS_ENDPOINT_FAMILY_POS : EGRESS_ENDPOINT_FAMILY_POS+2])

	var addressLen uint16
	switch addressFamily {
	case 0:
		addressLen = 0
	case AFI_IP:
		addressLen = net.IPv4len
	case AFI_IP6:
		addressLen = net.IPv6len
	default:
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "Unsupported address family in TunnelEncapSubTLVEgressEndpoint")
	}
	if t.Length != EGRESS_ENDPOINT_ADDRESS_POS+addressLen {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "Not all TunnelEncapSubTLVEgressEndpoint address bytes available")
	}
	t.Address = nil
	if addressFamily != 0 {
		t.Address = net.IP(value[EGRESS_ENDPOINT_ADDRESS_POS : EGRESS_ENDPOINT_ADDRESS_POS+addressLen])
	}

	return nil
}

func (t *TunnelEncapSubTLVEgressEndpoint) Serialize() ([]byte, error) {
	var length uint32 = EGRESS_ENDPOINT_ADDRESS_POS
	var family uint16
	var ip net.IP
	if t.Address == nil {
		family = 0
	} else if t.Address.To4() != nil {
		length += net.IPv4len
		family = AFI_IP
		ip = t.Address.To4()
	} else {
		length += net.IPv6len
		family = AFI_IP6
		ip = t.Address.To16()
	}
	buf := make([]byte, length)
	binary.BigEndian.PutUint32(buf, 0)
	binary.BigEndian.PutUint16(buf[EGRESS_ENDPOINT_FAMILY_POS:], family)
	if family != 0 {
		copy(buf[EGRESS_ENDPOINT_ADDRESS_POS:], ip)
	}
	return t.TunnelEncapSubTLV.Serialize(buf)
}

func (t *TunnelEncapSubTLVEgressEndpoint) String() string {
	address := ""
	if t.Address != nil {
		address = t.Address.String()
	}
	return fmt.Sprintf("{EgressEndpoint: %s}", address)
}

func (t *TunnelEncapSubTLVEgressEndpoint) MarshalJSON() ([]byte, error) {
	address := ""
	if t.Address != nil {
		address = t.Address.String()
	}

	return json.Marshal(struct {
		Type    EncapSubTLVType `json:"type"`
		Address string          `json:"address"`
	}{
		Type:    t.Type,
		Address: address,
	})
}

func NewTunnelEncapSubTLVEgressEndpoint(address string) *TunnelEncapSubTLVEgressEndpoint {
	var ip net.IP = nil
	if address != "" {
		ip = net.ParseIP(address)
	}
	return &TunnelEncapSubTLVEgressEndpoint{
		TunnelEncapSubTLV: TunnelEncapSubTLV{
			Type: ENCAP_SUBTLV_TYPE_EGRESS_ENDPOINT,
		},
		Address: ip,
	}
}

type TunnelEncapSubTLVUDPDestPort struct {
	TunnelEncapSubTLV
	UDPDestPort uint16
}

func (t *TunnelEncapSubTLVUDPDestPort) DecodeFromBytes(data []byte) error {
	value, err := t.TunnelEncapSubTLV.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	if t.Length < 2 {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "Not all TunnelEncapSubTLVUDPDestPort bytes available")
	}
	t.UDPDestPort = binary.BigEndian.Uint16(value[0:2])
	return nil
}

func (t *TunnelEncapSubTLVUDPDestPort) Serialize() ([]byte, error) {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, t.UDPDestPort)
	return t.TunnelEncapSubTLV.Serialize(buf)
}

func (t *TunnelEncapSubTLVUDPDestPort) String() string {
	return fmt.Sprintf("{UDPDestPort: %d}", t.UDPDestPort)
}

func (t *TunnelEncapSubTLVUDPDestPort) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type        EncapSubTLVType `json:"type"`
		UDPDestPort uint16          `json:"port"`
	}{
		Type:        t.Type,
		UDPDestPort: t.UDPDestPort,
	})
}

func NewTunnelEncapSubTLVUDPDestPort(port uint16) *TunnelEncapSubTLVUDPDestPort {
	return &TunnelEncapSubTLVUDPDestPort{
		TunnelEncapSubTLV: TunnelEncapSubTLV{
			Type: ENCAP_SUBTLV_TYPE_UDP_DEST_PORT,
		},
		UDPDestPort: port,
	}
}

type TunnelEncapTLV struct {
	Type   TunnelType
	Length uint16
	Value  []TunnelEncapSubTLVInterface
}

func (t *TunnelEncapTLV) Len() int {
	var l int
	for _, v := range t.Value {
		l += v.Len()
	}
	return 4 + l // Type(2) + Length(2) + Value(variable)
}

func (t *TunnelEncapTLV) DecodeFromBytes(data []byte) error {
	t.Type = TunnelType(binary.BigEndian.Uint16(data[0:2]))
	t.Length = binary.BigEndian.Uint16(data[2:4])
	data = data[4:]
	if len(data) < int(t.Length) {
		return NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "Not all TunnelEncapTLV bytes available")
	}
	value := data[:t.Length]
	for len(value) > 2 {
		subType := EncapSubTLVType(value[0])
		var subTlv TunnelEncapSubTLVInterface
		switch subType {
		case ENCAP_SUBTLV_TYPE_ENCAPSULATION:
			subTlv = &TunnelEncapSubTLVEncapsulation{}
		case ENCAP_SUBTLV_TYPE_PROTOCOL:
			subTlv = &TunnelEncapSubTLVProtocol{}
		case ENCAP_SUBTLV_TYPE_COLOR:
			subTlv = &TunnelEncapSubTLVColor{}
		case ENCAP_SUBTLV_TYPE_UDP_DEST_PORT:
			subTlv = &TunnelEncapSubTLVUDPDestPort{}
		case ENCAP_SUBTLV_TYPE_EGRESS_ENDPOINT:
			subTlv = &TunnelEncapSubTLVEgressEndpoint{}
		case ENCAP_SUBTLV_TYPE_SRPREFERENCE:
			subTlv = &TunnelEncapSubTLVSRPreference{}
		case ENCAP_SUBTLV_TYPE_SRBINDING_SID:
			subTlv = &TunnelEncapSubTLVSRBSID{}
		case ENCAP_SUBTLV_TYPE_SRSEGMENT_LIST:
			subTlv = &TunnelEncapSubTLVSRSegmentList{}
		case ENCAP_SUBTLV_TYPE_SRENLP:
			subTlv = &TunnelEncapSubTLVSRENLP{}
		case ENCAP_SUBTLV_TYPE_SRPRIORITY:
			subTlv = &TunnelEncapSubTLVSRPriority{}
		case ENCAP_SUBTLV_TYPE_SRCANDIDATE_PATH_NAME:
			subTlv = &TunnelEncapSubTLVSRCandidatePathName{}
		default:
			subTlv = &TunnelEncapSubTLVUnknown{
				TunnelEncapSubTLV: TunnelEncapSubTLV{
					Type: subType,
				},
			}
		}
		err := subTlv.DecodeFromBytes(value)
		if err != nil {
			return err
		}
		t.Value = append(t.Value, subTlv)
		value = value[subTlv.Len():]
	}
	return nil
}

func (p *TunnelEncapTLV) Serialize() ([]byte, error) {
	buf := make([]byte, 4)
	for _, t := range p.Value {
		tBuf, err := t.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, tBuf...)
	}
	binary.BigEndian.PutUint16(buf, uint16(p.Type))
	binary.BigEndian.PutUint16(buf[2:], uint16(len(buf)-4))
	return buf, nil
}

func (p *TunnelEncapTLV) String() string {
	tlvList := make([]string, len(p.Value))
	for i, v := range p.Value {
		tlvList[i] = v.String()
	}
	return fmt.Sprintf("{%s: %s}", p.Type, strings.Join(tlvList, ", "))
}

func (p *TunnelEncapTLV) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  TunnelType                   `json:"type"`
		Value []TunnelEncapSubTLVInterface `json:"value"`
	}{
		Type:  p.Type,
		Value: p.Value,
	})
}

func NewTunnelEncapTLV(typ TunnelType, value []TunnelEncapSubTLVInterface) *TunnelEncapTLV {
	return &TunnelEncapTLV{
		Type:  typ,
		Value: value,
	}
}

type PathAttributeTunnelEncap struct {
	PathAttribute
	Value []*TunnelEncapTLV
}

func (p *PathAttributeTunnelEncap) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	value, err := p.PathAttribute.DecodeFromBytes(data, options...)
	if err != nil {
		return err
	}
	for len(value) > 4 {
		tlv := &TunnelEncapTLV{}
		err = tlv.DecodeFromBytes(value)
		if err != nil {
			return err
		}
		p.Value = append(p.Value, tlv)
		value = value[4+tlv.Length:]
	}
	return nil
}

func (p *PathAttributeTunnelEncap) Serialize(options ...*MarshallingOption) ([]byte, error) {
	buf := make([]byte, 0)
	for _, t := range p.Value {
		bbuf, err := t.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, bbuf...)
	}
	return p.PathAttribute.Serialize(buf, options...)
}

func (p *PathAttributeTunnelEncap) String() string {
	tlvList := make([]string, len(p.Value))
	for i, v := range p.Value {
		tlvList[i] = v.String()
	}
	return fmt.Sprintf("{TunnelEncap: %s}", strings.Join(tlvList, ", "))
}

func (p *PathAttributeTunnelEncap) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  BGPAttrType       `json:"type"`
		Value []*TunnelEncapTLV `json:"value"`
	}{
		Type:  p.Type,
		Value: p.Value,
	})
}

func NewPathAttributeTunnelEncap(value []*TunnelEncapTLV) *PathAttributeTunnelEncap {
	var l int
	for _, v := range value {
		l += v.Len()
	}
	t := BGP_ATTR_TYPE_TUNNEL_ENCAP
	return &PathAttributeTunnelEncap{
		PathAttribute: PathAttribute{
			Flags:  getPathAttrFlags(t, l),
			Type:   t,
			Length: uint16(l),
		},
		Value: value,
	}
}

type PmsiTunnelIDInterface interface {
	Len() int
	Serialize() ([]byte, error)
	String() string
}

type DefaultPmsiTunnelID struct {
	Value []byte
}

func (i *DefaultPmsiTunnelID) Len() int {
	return len(i.Value)
}

func (i *DefaultPmsiTunnelID) Serialize() ([]byte, error) {
	return i.Value, nil
}

func (i *DefaultPmsiTunnelID) String() string {
	return string(i.Value)
}

func NewDefaultPmsiTunnelID(value []byte) *DefaultPmsiTunnelID {
	return &DefaultPmsiTunnelID{
		Value: value,
	}
}

type IngressReplTunnelID struct {
	Value net.IP
}

func (i *IngressReplTunnelID) Len() int {
	return len(i.Value)
}

func (i *IngressReplTunnelID) Serialize() ([]byte, error) {
	if i.Value.To4() != nil {
		return []byte(i.Value.To4()), nil
	}
	return []byte(i.Value), nil
}

func (i *IngressReplTunnelID) String() string {
	return i.Value.String()
}

func NewIngressReplTunnelID(value string) *IngressReplTunnelID {
	ip := net.ParseIP(value)
	if ip == nil {
		return nil
	}
	return &IngressReplTunnelID{
		Value: ip,
	}
}

type PathAttributePmsiTunnel struct {
	PathAttribute
	IsLeafInfoRequired bool
	TunnelType         PmsiTunnelType
	Label              uint32
	TunnelID           PmsiTunnelIDInterface
}

func (p *PathAttributePmsiTunnel) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	value, err := p.PathAttribute.DecodeFromBytes(data, options...)
	if err != nil {
		return err
	}
	if p.Length < 5 {
		eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
		eSubCode := uint8(BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST)
		return NewMessageError(eCode, eSubCode, nil, "PMSI Tunnel length is incorrect")
	}

	if (value[0] & 0x01) > 0 {
		p.IsLeafInfoRequired = true
	}
	p.TunnelType = PmsiTunnelType(value[1])
	if p.Label, err = labelDecode(value[2:5]); err != nil {
		return err
	}

	switch p.TunnelType {
	case PMSI_TUNNEL_TYPE_INGRESS_REPL:
		p.TunnelID = &IngressReplTunnelID{net.IP(value[5:])}
	default:
		p.TunnelID = &DefaultPmsiTunnelID{value[5:]}
	}
	return nil
}

func (p *PathAttributePmsiTunnel) Serialize(options ...*MarshallingOption) ([]byte, error) {
	buf := make([]byte, 2)
	if p.IsLeafInfoRequired {
		buf[0] = 0x01
	}
	buf[1] = byte(p.TunnelType)
	tbuf, err := labelSerialize(p.Label)
	if err != nil {
		return nil, err
	}
	buf = append(buf, tbuf...)
	tbuf, err = p.TunnelID.Serialize()
	if err != nil {
		return nil, err
	}
	buf = append(buf, tbuf...)
	return p.PathAttribute.Serialize(buf, options...)
}

func (p *PathAttributePmsiTunnel) String() string {
	buf := bytes.NewBuffer(make([]byte, 0, 32))
	buf.WriteString(fmt.Sprintf("{Pmsi: type: %s,", p.TunnelType))
	if p.IsLeafInfoRequired {
		buf.WriteString(" leaf-info-required,")
	}
	buf.WriteString(fmt.Sprintf(" label: %d, tunnel-id: %s}", p.Label, p.TunnelID))
	return buf.String()
}

func (p *PathAttributePmsiTunnel) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type               BGPAttrType `json:"type"`
		IsLeafInfoRequired bool        `json:"is-leaf-info-required"`
		TunnelType         uint8       `json:"tunnel-type"`
		Label              uint32      `json:"label"`
		TunnelID           string      `json:"tunnel-id"`
	}{
		Type:               p.Type,
		IsLeafInfoRequired: p.IsLeafInfoRequired,
		TunnelType:         uint8(p.TunnelType),
		Label:              p.Label,
		TunnelID:           p.TunnelID.String(),
	})
}

func NewPathAttributePmsiTunnel(typ PmsiTunnelType, isLeafInfoRequired bool, label uint32, id PmsiTunnelIDInterface) *PathAttributePmsiTunnel {
	if id == nil {
		return nil
	}
	// Flags(1) + TunnelType(1) + Label(3) + TunnelID(variable)
	l := 5 + id.Len()
	t := BGP_ATTR_TYPE_PMSI_TUNNEL
	return &PathAttributePmsiTunnel{
		PathAttribute: PathAttribute{
			Flags:  getPathAttrFlags(t, l),
			Type:   t,
			Length: uint16(l),
		},
		IsLeafInfoRequired: isLeafInfoRequired,
		TunnelType:         typ,
		Label:              label,
		TunnelID:           id,
	}
}

func ParsePmsiTunnel(args []string) (*PathAttributePmsiTunnel, error) {
	// Format:
	// "<type>" ["leaf-info-required"] "<label>" "<tunnel-id>"
	if len(args) < 3 {
		return nil, fmt.Errorf("invalid pmsi tunnel arguments: %s", args)
	}

	var tunnelType PmsiTunnelType
	var isLeafInfoRequired bool
	switch args[0] {
	case "ingress-repl":
		tunnelType = PMSI_TUNNEL_TYPE_INGRESS_REPL
	default:
		typ, err := strconv.ParseUint(args[0], 10, 8)
		if err != nil {
			return nil, fmt.Errorf("invalid pmsi tunnel type: %s", args[0])
		}
		tunnelType = PmsiTunnelType(typ)
	}

	indx := 1
	if args[indx] == "leaf-info-required" {
		isLeafInfoRequired = true
		indx++
	}

	label, err := strconv.ParseUint(args[indx], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid pmsi tunnel label: %s", args[indx])
	}
	indx++

	var id PmsiTunnelIDInterface
	switch tunnelType {
	case PMSI_TUNNEL_TYPE_INGRESS_REPL:
		ip := net.ParseIP(args[indx])
		if ip == nil {
			return nil, fmt.Errorf("invalid pmsi tunnel identifier: %s", args[indx])
		}
		id = &IngressReplTunnelID{Value: ip}
	default:
		id = &DefaultPmsiTunnelID{Value: []byte(args[indx])}
	}

	return NewPathAttributePmsiTunnel(tunnelType, isLeafInfoRequired, uint32(label), id), nil
}

type PathAttributeIP6ExtendedCommunities struct {
	PathAttribute
	Value []ExtendedCommunityInterface
}

func ParseIP6Extended(data []byte) (ExtendedCommunityInterface, error) {
	if len(data) < 8 {
		return nil, NewMessageError(BGP_ERROR_UPDATE_MESSAGE_ERROR, BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST, nil, "not all extended community bytes are available")
	}
	attrType := ExtendedCommunityAttrType(data[0])
	subtype := ExtendedCommunityAttrSubType(data[1])
	transitive := false
	switch attrType {
	case EC_TYPE_TRANSITIVE_IP6_SPECIFIC:
		transitive = true
		fallthrough
	case EC_TYPE_NON_TRANSITIVE_IP6_SPECIFIC:
		ipv6 := net.IP(data[2:18]).String()
		localAdmin := binary.BigEndian.Uint16(data[18:20])
		return NewIPv6AddressSpecificExtended(subtype, ipv6, localAdmin, transitive), nil
	case EC_TYPE_GENERIC_TRANSITIVE_EXPERIMENTAL:
		return parseIP6FlowSpecExtended(data)
	default:
		return &UnknownExtended{
			Type:  ExtendedCommunityAttrType(data[0]),
			Value: data[1:8],
		}, nil
	}
}

func (p *PathAttributeIP6ExtendedCommunities) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	value, err := p.PathAttribute.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	if p.Length%20 != 0 {
		eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
		eSubCode := uint8(BGP_ERROR_SUB_ATTRIBUTE_LENGTH_ERROR)
		return NewMessageError(eCode, eSubCode, nil, "extendedcommunities length isn't correct")
	}
	for len(value) >= 20 {
		e, err := ParseIP6Extended(value)
		if err != nil {
			return err
		}
		p.Value = append(p.Value, e)
		value = value[20:]
	}
	return nil
}

func (p *PathAttributeIP6ExtendedCommunities) Serialize(options ...*MarshallingOption) ([]byte, error) {
	buf := make([]byte, 0)
	for _, p := range p.Value {
		ebuf, err := p.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, ebuf...)
	}
	return p.PathAttribute.Serialize(buf, options...)
}

func (p *PathAttributeIP6ExtendedCommunities) String() string {
	buf := make([]string, len(p.Value))
	for i, v := range p.Value {
		buf[i] = fmt.Sprintf("[%s]", v.String())
	}
	return fmt.Sprintf("{Extcomms: %s}", strings.Join(buf, ","))
}

func (p *PathAttributeIP6ExtendedCommunities) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  BGPAttrType                  `json:"type"`
		Value []ExtendedCommunityInterface `json:"value"`
	}{
		Type:  p.GetType(),
		Value: p.Value,
	})
}

func NewPathAttributeIP6ExtendedCommunities(value []ExtendedCommunityInterface) *PathAttributeIP6ExtendedCommunities {
	l := len(value) * 20
	t := BGP_ATTR_TYPE_IP6_EXTENDED_COMMUNITIES
	return &PathAttributeIP6ExtendedCommunities{
		PathAttribute: PathAttribute{
			Flags:  getPathAttrFlags(t, l),
			Type:   t,
			Length: uint16(l),
		},
		Value: value,
	}
}

type AigpTLVType uint8

const (
	AIGP_TLV_UNKNOWN AigpTLVType = iota
	AIGP_TLV_IGP_METRIC
)

type AigpTLVInterface interface {
	Serialize() ([]byte, error)
	String() string
	MarshalJSON() ([]byte, error)
	Type() AigpTLVType
	Len() int
}

type AigpTLVDefault struct {
	typ   AigpTLVType
	Value []byte
}

func (t *AigpTLVDefault) Serialize() ([]byte, error) {
	buf := make([]byte, 3+len(t.Value))
	buf[0] = uint8(t.Type())
	binary.BigEndian.PutUint16(buf[1:], uint16(3+len(t.Value)))
	copy(buf[3:], t.Value)
	return buf, nil
}

func (t *AigpTLVDefault) String() string {
	return fmt.Sprintf("{Type: %d, Value: %v}", t.Type(), t.Value)
}

func (t *AigpTLVDefault) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  AigpTLVType `json:"type"`
		Value []byte      `json:"value"`
	}{
		Type:  t.Type(),
		Value: t.Value,
	})
}

func (t *AigpTLVDefault) Type() AigpTLVType {
	return t.typ
}

func (t *AigpTLVDefault) Len() int {
	return 3 + len(t.Value) // Type(1) + Length(2) + Value(variable)
}

func NewAigpTLVDefault(typ AigpTLVType, value []byte) *AigpTLVDefault {
	return &AigpTLVDefault{
		typ:   typ,
		Value: value,
	}
}

type AigpTLVIgpMetric struct {
	Metric uint64
}

func (t *AigpTLVIgpMetric) Serialize() ([]byte, error) {
	buf := make([]byte, 11)
	buf[0] = uint8(AIGP_TLV_IGP_METRIC)
	binary.BigEndian.PutUint16(buf[1:], uint16(11))
	binary.BigEndian.PutUint64(buf[3:], t.Metric)
	return buf, nil
}

func (t *AigpTLVIgpMetric) String() string {
	return fmt.Sprintf("{Metric: %d}", t.Metric)
}

func (t *AigpTLVIgpMetric) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type   AigpTLVType `json:"type"`
		Metric uint64      `json:"metric"`
	}{
		Type:   AIGP_TLV_IGP_METRIC,
		Metric: t.Metric,
	})
}

func NewAigpTLVIgpMetric(metric uint64) *AigpTLVIgpMetric {
	return &AigpTLVIgpMetric{
		Metric: metric,
	}
}

func (t *AigpTLVIgpMetric) Type() AigpTLVType {
	return AIGP_TLV_IGP_METRIC
}

func (t *AigpTLVIgpMetric) Len() int {
	return 11
}

type PathAttributeAigp struct {
	PathAttribute
	Values []AigpTLVInterface
}

func (p *PathAttributeAigp) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	value, err := p.PathAttribute.DecodeFromBytes(data, options...)
	if err != nil {
		return err
	}
	for len(value) > 3 {
		typ := value[0]
		length := binary.BigEndian.Uint16(value[1:3])
		if length <= 3 {
			return NewMessageError(BGP_ERROR_MESSAGE_HEADER_ERROR, BGP_ERROR_SUB_BAD_MESSAGE_LENGTH, nil, "Malformed BGP message")
		}
		if len(value) < int(length) {
			break
		}
		v := value[3:length]
		switch AigpTLVType(typ) {
		case AIGP_TLV_IGP_METRIC:
			if len(v) < 8 {
				break
			}
			metric := binary.BigEndian.Uint64(v)
			p.Values = append(p.Values, NewAigpTLVIgpMetric(metric))
		default:
			p.Values = append(p.Values, NewAigpTLVDefault(AigpTLVType(typ), v))
		}
		value = value[length:]
	}
	if len(value) != 0 {
		eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
		eSubCode := uint8(BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST)
		return NewMessageError(eCode, eSubCode, nil, "Aigp length is incorrect")
	}
	return nil
}

func (p *PathAttributeAigp) Serialize(options ...*MarshallingOption) ([]byte, error) {
	buf := make([]byte, 0)
	for _, t := range p.Values {
		bbuf, err := t.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, bbuf...)
	}
	return p.PathAttribute.Serialize(buf, options...)
}

func (p *PathAttributeAigp) String() string {
	buf := bytes.NewBuffer(make([]byte, 0, 32))
	buf.WriteString("{Aigp: [")
	for _, v := range p.Values {
		buf.WriteString(v.String())
	}
	buf.WriteString("]}")
	return buf.String()
}

func (p *PathAttributeAigp) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  BGPAttrType        `json:"type"`
		Value []AigpTLVInterface `json:"value"`
	}{
		Type:  p.GetType(),
		Value: p.Values,
	})
}

func NewPathAttributeAigp(values []AigpTLVInterface) *PathAttributeAigp {
	var l int
	for _, v := range values {
		l += v.Len()
	}
	t := BGP_ATTR_TYPE_AIGP
	return &PathAttributeAigp{
		PathAttribute: PathAttribute{
			Flags:  getPathAttrFlags(t, l),
			Type:   t,
			Length: uint16(l),
		},
		Values: values,
	}
}

type LargeCommunity struct {
	ASN        uint32
	LocalData1 uint32
	LocalData2 uint32
}

func (c *LargeCommunity) Serialize() ([]byte, error) {
	buf := make([]byte, 12)
	binary.BigEndian.PutUint32(buf, c.ASN)
	binary.BigEndian.PutUint32(buf[4:], c.LocalData1)
	binary.BigEndian.PutUint32(buf[8:], c.LocalData2)
	return buf, nil
}

func (c *LargeCommunity) String() string {
	return fmt.Sprintf("%d:%d:%d", c.ASN, c.LocalData1, c.LocalData2)
}

func (c *LargeCommunity) Eq(rhs *LargeCommunity) bool {
	return c.ASN == rhs.ASN && c.LocalData1 == rhs.LocalData1 && c.LocalData2 == rhs.LocalData2
}

func NewLargeCommunity(asn, data1, data2 uint32) *LargeCommunity {
	return &LargeCommunity{
		ASN:        asn,
		LocalData1: data1,
		LocalData2: data2,
	}
}

func ParseLargeCommunity(value string) (*LargeCommunity, error) {
	elems := strings.Split(value, ":")
	if len(elems) != 3 {
		return nil, errors.New("invalid large community format")
	}
	v := make([]uint32, 0, 3)
	for _, elem := range elems {
		e, err := strconv.ParseUint(elem, 10, 32)
		if err != nil {
			return nil, errors.New("invalid large community format")
		}
		v = append(v, uint32(e))
	}
	return NewLargeCommunity(v[0], v[1], v[2]), nil
}

type PathAttributeLargeCommunities struct {
	PathAttribute
	Values []*LargeCommunity
}

func (p *PathAttributeLargeCommunities) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	value, err := p.PathAttribute.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	if p.Length%12 != 0 {
		eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
		eSubCode := uint8(BGP_ERROR_SUB_ATTRIBUTE_LENGTH_ERROR)
		return NewMessageError(eCode, eSubCode, nil, "large communities length isn't correct")
	}
	p.Values = make([]*LargeCommunity, 0, p.Length/12)
	for len(value) >= 12 {
		asn := binary.BigEndian.Uint32(value[:4])
		data1 := binary.BigEndian.Uint32(value[4:8])
		data2 := binary.BigEndian.Uint32(value[8:12])
		p.Values = append(p.Values, NewLargeCommunity(asn, data1, data2))
		value = value[12:]
	}
	return nil
}

func (p *PathAttributeLargeCommunities) Serialize(options ...*MarshallingOption) ([]byte, error) {
	buf := make([]byte, 0, len(p.Values)*12)
	for _, t := range p.Values {
		bbuf, err := t.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, bbuf...)
	}
	return p.PathAttribute.Serialize(buf, options...)
}

func (p *PathAttributeLargeCommunities) String() string {
	buf := bytes.NewBuffer(make([]byte, 0, 32))
	buf.WriteString("{LargeCommunity: [ ")
	ss := []string{}
	for _, v := range p.Values {
		ss = append(ss, v.String())
	}
	buf.WriteString(strings.Join(ss, ", "))
	buf.WriteString("]}")
	return buf.String()
}

func (p *PathAttributeLargeCommunities) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Type  BGPAttrType       `json:"type"`
		Value []*LargeCommunity `json:"value"`
	}{
		Type:  p.GetType(),
		Value: p.Values,
	})
}

func NewPathAttributeLargeCommunities(values []*LargeCommunity) *PathAttributeLargeCommunities {
	l := len(values) * 12
	t := BGP_ATTR_TYPE_LARGE_COMMUNITY
	return &PathAttributeLargeCommunities{
		PathAttribute: PathAttribute{
			Flags:  getPathAttrFlags(t, l),
			Type:   t,
			Length: uint16(l),
		},
		Values: values,
	}
}

type PathAttributeUnknown struct {
	PathAttribute
	Value []byte
}

func (p *PathAttributeUnknown) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	value, err := p.PathAttribute.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	p.Value = value
	return nil
}

func (p *PathAttributeUnknown) Serialize(options ...*MarshallingOption) ([]byte, error) {
	return p.PathAttribute.Serialize(p.Value, options...)
}

func (p *PathAttributeUnknown) String() string {
	return fmt.Sprintf("{Flags: %s, Type: %s, Value: %v}", p.Flags, p.Type, p.Value)
}

func (p *PathAttributeUnknown) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Flags BGPAttrFlag `json:"flags"`
		Type  BGPAttrType `json:"type"`
		Value []byte      `json:"value"`
	}{
		Flags: p.GetFlags(),
		Type:  p.GetType(),
		Value: p.Value,
	})
}

func NewPathAttributeUnknown(flags BGPAttrFlag, typ BGPAttrType, value []byte) *PathAttributeUnknown {
	l := len(value)
	if l > 255 {
		flags |= BGP_ATTR_FLAG_EXTENDED_LENGTH
	}
	return &PathAttributeUnknown{
		PathAttribute: PathAttribute{
			Flags:  flags,
			Type:   typ,
			Length: uint16(l),
		},
		Value: value,
	}
}

// BGPUpdateAttributes defines a map with a key as bgp attribute type
// and value as bool. Value set to true indicates that the attribute specified by the key
// exists in the bgp update.
type BGPUpdateAttributes struct {
	Attribute map[BGPAttrType]bool
}

func GetBGPUpdateAttributes(data []byte) map[BGPAttrType]bool {
	m := make(map[BGPAttrType]bool)
	for p := 0; p < len(data); {
		flag := data[p]
		p++
		if p < len(data) {
			t := data[p]
			m[BGPAttrType(t)] = true
		} else {
			break
		}
		p++
		var l uint16
		// Checking for Extened
		if flag&0x10 == 0x10 {
			if p+2 <= len(data) {
				l = binary.BigEndian.Uint16(data[p : p+2])
			} else {
				break
			}
			p += 2
		} else {
			if p < len(data) {
				l = uint16(data[p])
				p++
			} else {
				break
			}
		}
		p += int(l)
	}
	return m
}

func GetBGPUpdateAttributesFromMsg(msg *BGPUpdate) map[BGPAttrType]bool {
	m := make(map[BGPAttrType]bool)
	for _, p := range msg.PathAttributes {
		m[p.GetType()] = true
	}

	return m
}

func GetPathAttribute(data []byte) (PathAttributeInterface, error) {
	if len(data) < 2 {
		eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
		eSubCode := uint8(BGP_ERROR_SUB_ATTRIBUTE_LENGTH_ERROR)
		return nil, NewMessageError(eCode, eSubCode, data, "attribute type length is short")
	}
	switch BGPAttrType(data[1]) {
	case BGP_ATTR_TYPE_ORIGIN:
		return &PathAttributeOrigin{}, nil
	case BGP_ATTR_TYPE_AS_PATH:
		return &PathAttributeAsPath{}, nil
	case BGP_ATTR_TYPE_NEXT_HOP:
		return &PathAttributeNextHop{}, nil
	case BGP_ATTR_TYPE_MULTI_EXIT_DISC:
		return &PathAttributeMultiExitDisc{}, nil
	case BGP_ATTR_TYPE_LOCAL_PREF:
		return &PathAttributeLocalPref{}, nil
	case BGP_ATTR_TYPE_ATOMIC_AGGREGATE:
		return &PathAttributeAtomicAggregate{}, nil
	case BGP_ATTR_TYPE_AGGREGATOR:
		return &PathAttributeAggregator{}, nil
	case BGP_ATTR_TYPE_COMMUNITIES:
		return &PathAttributeCommunities{}, nil
	case BGP_ATTR_TYPE_ORIGINATOR_ID:
		return &PathAttributeOriginatorId{}, nil
	case BGP_ATTR_TYPE_CLUSTER_LIST:
		return &PathAttributeClusterList{}, nil
	case BGP_ATTR_TYPE_MP_REACH_NLRI:
		return &PathAttributeMpReachNLRI{}, nil
	case BGP_ATTR_TYPE_MP_UNREACH_NLRI:
		return &PathAttributeMpUnreachNLRI{}, nil
	case BGP_ATTR_TYPE_EXTENDED_COMMUNITIES:
		return &PathAttributeExtendedCommunities{}, nil
	case BGP_ATTR_TYPE_AS4_PATH:
		return &PathAttributeAs4Path{}, nil
	case BGP_ATTR_TYPE_AS4_AGGREGATOR:
		return &PathAttributeAs4Aggregator{}, nil
	case BGP_ATTR_TYPE_TUNNEL_ENCAP:
		return &PathAttributeTunnelEncap{}, nil
	case BGP_ATTR_TYPE_PMSI_TUNNEL:
		return &PathAttributePmsiTunnel{}, nil
	case BGP_ATTR_TYPE_IP6_EXTENDED_COMMUNITIES:
		return &PathAttributeIP6ExtendedCommunities{}, nil
	case BGP_ATTR_TYPE_AIGP:
		return &PathAttributeAigp{}, nil
	case BGP_ATTR_TYPE_LARGE_COMMUNITY:
		return &PathAttributeLargeCommunities{}, nil
	case BGP_ATTR_TYPE_LS:
		return &PathAttributeLs{}, nil
	case BGP_ATTR_TYPE_PREFIX_SID:
		return &PathAttributePrefixSID{}, nil
	}
	return &PathAttributeUnknown{}, nil
}

type BGPUpdate struct {
	WithdrawnRoutesLen    uint16
	WithdrawnRoutes       []*IPAddrPrefix
	TotalPathAttributeLen uint16
	PathAttributes        []PathAttributeInterface
	NLRI                  []*IPAddrPrefix
}

func (msg *BGPUpdate) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	var strongestError error

	// cache error codes
	eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
	eSubCode := uint8(BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST)

	// check withdrawn route length
	if len(data) < 2 {
		return NewMessageError(eCode, eSubCode, nil, "message length isn't enough for withdrawn route length")
	}

	msg.WithdrawnRoutesLen = binary.BigEndian.Uint16(data[0:2])
	data = data[2:]

	// check withdrawn route
	if len(data) < int(msg.WithdrawnRoutesLen) {
		return NewMessageError(eCode, eSubCode, nil, "withdrawn route length exceeds message length")
	}

	addpathLen := 0
	if IsAddPathEnabled(true, RF_IPv4_UC, options) {
		addpathLen = 4
	}

	msg.WithdrawnRoutes = make([]*IPAddrPrefix, 0, msg.WithdrawnRoutesLen)
	for routelen := msg.WithdrawnRoutesLen; routelen > 0; {
		w := &IPAddrPrefix{}
		err := w.DecodeFromBytes(data, options...)
		if err != nil {
			return err
		}
		routelen -= uint16(w.Len(options...) + addpathLen)
		if len(data) < w.Len(options...)+addpathLen {
			return NewMessageError(eCode, eSubCode, nil, "Withdrawn route length is short")
		}
		data = data[w.Len(options...)+addpathLen:]
		msg.WithdrawnRoutes = append(msg.WithdrawnRoutes, w)
	}

	// check path total attribute length
	if len(data) < 2 {
		return NewMessageError(eCode, eSubCode, nil, "message length isn't enough for path total attribute length")
	}

	msg.TotalPathAttributeLen = binary.BigEndian.Uint16(data[0:2])
	data = data[2:]

	// check path attribute
	if len(data) < int(msg.TotalPathAttributeLen) {
		return NewMessageError(eCode, eSubCode, nil, "path total attribute length exceeds message length")
	}
	attributes := GetBGPUpdateAttributes(data)
	o := MarshallingOption{
		Attributes: attributes,
	}
	options = append(options, &o)

	msg.PathAttributes = []PathAttributeInterface{}
	for pathlen := msg.TotalPathAttributeLen; pathlen > 0; {
		var e error
		if pathlen < 3 {
			e = NewMessageErrorWithErrorHandling(
				eCode, BGP_ERROR_SUB_ATTRIBUTE_LENGTH_ERROR, data, ERROR_HANDLING_TREAT_AS_WITHDRAW, nil, "insufficient data to decode")
			if e.(*MessageError).Stronger(strongestError) {
				strongestError = e
			}
			data = data[pathlen:]
			break
		}
		p, err := GetPathAttribute(data)
		if err != nil {
			return err
		}
		err = p.DecodeFromBytes(data, options...)
		if err != nil {
			e = err.(*MessageError)
			if e.(*MessageError).SubTypeCode == BGP_ERROR_SUB_ATTRIBUTE_FLAGS_ERROR {
				e.(*MessageError).ErrorHandling = ERROR_HANDLING_TREAT_AS_WITHDRAW
			} else {
				e.(*MessageError).ErrorHandling = getErrorHandlingFromPathAttribute(p.GetType())
				e.(*MessageError).ErrorAttribute = &p
			}
			if e.(*MessageError).Stronger(strongestError) {
				strongestError = e
			}
		}
		pathlen -= uint16(p.Len(options...))
		if len(data) < p.Len(options...) {
			e = NewMessageErrorWithErrorHandling(
				eCode, BGP_ERROR_SUB_ATTRIBUTE_LENGTH_ERROR, data, ERROR_HANDLING_TREAT_AS_WITHDRAW, nil, "attribute length is short")
			if e.(*MessageError).Stronger(strongestError) {
				strongestError = e
			}
			return strongestError
		}
		data = data[p.Len(options...):]
		if e == nil || e.(*MessageError).ErrorHandling != ERROR_HANDLING_ATTRIBUTE_DISCARD {
			msg.PathAttributes = append(msg.PathAttributes, p)
		}
	}

	msg.NLRI = make([]*IPAddrPrefix, 0)
	for restlen := len(data); restlen > 0; {
		n := &IPAddrPrefix{}
		err := n.DecodeFromBytes(data, options...)
		if err != nil {
			return err
		}
		restlen -= n.Len(options...) + addpathLen
		if len(data) < n.Len(options...)+addpathLen {
			return NewMessageError(eCode, BGP_ERROR_SUB_INVALID_NETWORK_FIELD, nil, "NLRI length is short")
		}
		if n.Len(options...) > 32 {
			return NewMessageError(eCode, BGP_ERROR_SUB_INVALID_NETWORK_FIELD, nil, "NLRI length is too long")
		}
		data = data[n.Len(options...)+addpathLen:]
		msg.NLRI = append(msg.NLRI, n)
	}

	return strongestError
}

func (msg *BGPUpdate) Serialize(options ...*MarshallingOption) ([]byte, error) {
	wbuf := make([]byte, 2)
	for _, w := range msg.WithdrawnRoutes {
		onewbuf, err := w.Serialize(options...)
		if err != nil {
			return nil, err
		}
		wbuf = append(wbuf, onewbuf...)
	}
	msg.WithdrawnRoutesLen = uint16(len(wbuf) - 2)
	binary.BigEndian.PutUint16(wbuf, msg.WithdrawnRoutesLen)

	attributes := GetBGPUpdateAttributesFromMsg(msg)
	o := MarshallingOption{
		Attributes: attributes,
	}
	options = append(options, &o)
	pbuf := make([]byte, 2)
	for _, p := range msg.PathAttributes {
		onepbuf, err := p.Serialize(options...)
		if err != nil {
			return nil, err
		}
		pbuf = append(pbuf, onepbuf...)
	}
	msg.TotalPathAttributeLen = uint16(len(pbuf) - 2)
	binary.BigEndian.PutUint16(pbuf, msg.TotalPathAttributeLen)

	buf := append(wbuf, pbuf...)
	for _, n := range msg.NLRI {
		nbuf, err := n.Serialize(options...)
		if err != nil {
			return nil, err
		}
		buf = append(buf, nbuf...)
	}

	return buf, nil
}

func (msg *BGPUpdate) IsEndOfRib() (bool, RouteFamily) {
	if len(msg.WithdrawnRoutes) == 0 && len(msg.NLRI) == 0 {
		if len(msg.PathAttributes) == 0 {
			return true, RF_IPv4_UC
		} else if len(msg.PathAttributes) == 1 && msg.PathAttributes[0].GetType() == BGP_ATTR_TYPE_MP_UNREACH_NLRI {
			unreach := msg.PathAttributes[0].(*PathAttributeMpUnreachNLRI)
			if len(unreach.Value) == 0 {
				return true, AfiSafiToRouteFamily(unreach.AFI, unreach.SAFI)
			}
		}
	}
	return false, RouteFamily(0)
}

func TreatAsWithdraw(msg *BGPUpdate) *BGPUpdate {
	withdraw := &BGPUpdate{
		WithdrawnRoutesLen:    0,
		WithdrawnRoutes:       []*IPAddrPrefix{},
		TotalPathAttributeLen: 0,
		PathAttributes:        make([]PathAttributeInterface, 0, len(msg.PathAttributes)),
		NLRI:                  []*IPAddrPrefix{},
	}
	withdraw.WithdrawnRoutes = append(msg.WithdrawnRoutes, msg.NLRI...)
	var unreach []AddrPrefixInterface

	for _, p := range msg.PathAttributes {
		switch nlri := p.(type) {
		case *PathAttributeMpReachNLRI:
			unreach = append(unreach, nlri.Value...)
		case *PathAttributeMpUnreachNLRI:
			unreach = append(unreach, nlri.Value...)
		}
	}
	if len(unreach) != 0 {
		withdraw.PathAttributes = append(withdraw.PathAttributes, NewPathAttributeMpUnreachNLRI(unreach))
	}
	return withdraw
}

func NewBGPUpdateMessage(withdrawnRoutes []*IPAddrPrefix, pathattrs []PathAttributeInterface, nlri []*IPAddrPrefix) *BGPMessage {
	return &BGPMessage{
		Header: BGPHeader{Type: BGP_MSG_UPDATE},
		Body:   &BGPUpdate{0, withdrawnRoutes, 0, pathattrs, nlri},
	}
}

func NewEndOfRib(family RouteFamily) *BGPMessage {
	if family == RF_IPv4_UC {
		return NewBGPUpdateMessage(nil, nil, nil)
	} else {
		afi, safi := RouteFamilyToAfiSafi(family)
		t := BGP_ATTR_TYPE_MP_UNREACH_NLRI
		unreach := &PathAttributeMpUnreachNLRI{
			PathAttribute: PathAttribute{
				Flags: PathAttrFlags[t],
				Type:  t,
			},
			AFI:  afi,
			SAFI: safi,
		}
		return NewBGPUpdateMessage(nil, []PathAttributeInterface{unreach}, nil)
	}
}

type BGPNotification struct {
	ErrorCode    uint8
	ErrorSubcode uint8
	Data         []byte
}

func (msg *BGPNotification) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	if len(data) < 2 {
		return NewMessageError(BGP_ERROR_MESSAGE_HEADER_ERROR, BGP_ERROR_SUB_BAD_MESSAGE_LENGTH, nil, "Not all Notification bytes available")
	}
	msg.ErrorCode = data[0]
	msg.ErrorSubcode = data[1]
	if len(data) > 2 {
		msg.Data = data[2:]
	}
	return nil
}

func (msg *BGPNotification) Serialize(options ...*MarshallingOption) ([]byte, error) {
	buf := make([]byte, 2, 2+len(msg.Data))
	buf[0] = msg.ErrorCode
	buf[1] = msg.ErrorSubcode
	buf = append(buf, msg.Data...)
	return buf, nil
}

func NewBGPNotificationMessage(errcode uint8, errsubcode uint8, data []byte) *BGPMessage {
	return &BGPMessage{
		Header: BGPHeader{Type: BGP_MSG_NOTIFICATION},
		Body:   &BGPNotification{errcode, errsubcode, data},
	}
}

type BGPKeepAlive struct {
}

func (msg *BGPKeepAlive) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	return nil
}

func (msg *BGPKeepAlive) Serialize(options ...*MarshallingOption) ([]byte, error) {
	return nil, nil
}

func NewBGPKeepAliveMessage() *BGPMessage {
	return &BGPMessage{
		Header: BGPHeader{Len: BGP_HEADER_LENGTH, Type: BGP_MSG_KEEPALIVE},
		Body:   &BGPKeepAlive{},
	}
}

type BGPRouteRefresh struct {
	AFI         uint16
	Demarcation uint8
	SAFI        uint8
}

func (msg *BGPRouteRefresh) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	if len(data) < 4 {
		return NewMessageError(BGP_ERROR_ROUTE_REFRESH_MESSAGE_ERROR, BGP_ERROR_SUB_INVALID_MESSAGE_LENGTH, nil, "Not all RouteRefresh bytes available")
	}
	msg.AFI = binary.BigEndian.Uint16(data[0:2])
	msg.Demarcation = data[2]
	msg.SAFI = data[3]
	return nil
}

func (msg *BGPRouteRefresh) Serialize(options ...*MarshallingOption) ([]byte, error) {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint16(buf[0:2], msg.AFI)
	buf[2] = msg.Demarcation
	buf[3] = msg.SAFI
	return buf, nil
}

func NewBGPRouteRefreshMessage(afi uint16, demarcation uint8, safi uint8) *BGPMessage {
	return &BGPMessage{
		Header: BGPHeader{Type: BGP_MSG_ROUTE_REFRESH},
		Body:   &BGPRouteRefresh{afi, demarcation, safi},
	}
}

type BGPBody interface {
	DecodeFromBytes([]byte, ...*MarshallingOption) error
	Serialize(...*MarshallingOption) ([]byte, error)
}

const (
	BGP_HEADER_LENGTH      = 19
	BGP_MAX_MESSAGE_LENGTH = 4096
)

type BGPHeader struct {
	Marker []byte
	Len    uint16
	Type   uint8
}

func (msg *BGPHeader) DecodeFromBytes(data []byte, options ...*MarshallingOption) error {
	// minimum BGP message length
	if uint16(len(data)) < BGP_HEADER_LENGTH {
		return NewMessageError(BGP_ERROR_MESSAGE_HEADER_ERROR, BGP_ERROR_SUB_BAD_MESSAGE_LENGTH, nil, "not all BGP message header")
	}

	msg.Len = binary.BigEndian.Uint16(data[16:18])
	if int(msg.Len) < BGP_HEADER_LENGTH {
		return NewMessageError(BGP_ERROR_MESSAGE_HEADER_ERROR, BGP_ERROR_SUB_BAD_MESSAGE_LENGTH, nil, "unknown message type")
	}

	msg.Type = data[18]
	return nil
}

func (msg *BGPHeader) Serialize(options ...*MarshallingOption) ([]byte, error) {
	buf := make([]byte, BGP_HEADER_LENGTH)
	for i := range buf[:16] {
		buf[i] = 0xff
	}
	binary.BigEndian.PutUint16(buf[16:18], msg.Len)
	buf[18] = msg.Type
	return buf, nil
}

type BGPMessage struct {
	Header BGPHeader
	Body   BGPBody
}

func parseBody(h *BGPHeader, data []byte, options ...*MarshallingOption) (*BGPMessage, error) {
	if len(data) < int(h.Len)-BGP_HEADER_LENGTH {
		return nil, NewMessageError(BGP_ERROR_MESSAGE_HEADER_ERROR, BGP_ERROR_SUB_BAD_MESSAGE_LENGTH, nil, "Not all BGP message bytes available")
	}
	msg := &BGPMessage{Header: *h}

	switch msg.Header.Type {
	case BGP_MSG_OPEN:
		msg.Body = &BGPOpen{}
	case BGP_MSG_UPDATE:
		msg.Body = &BGPUpdate{}
	case BGP_MSG_NOTIFICATION:
		msg.Body = &BGPNotification{}
	case BGP_MSG_KEEPALIVE:
		msg.Body = &BGPKeepAlive{}
	case BGP_MSG_ROUTE_REFRESH:
		msg.Body = &BGPRouteRefresh{}
	default:
		return nil, NewMessageError(BGP_ERROR_MESSAGE_HEADER_ERROR, BGP_ERROR_SUB_BAD_MESSAGE_TYPE, nil, "unknown message type")
	}
	err := msg.Body.DecodeFromBytes(data, options...)
	return msg, err
}

func ParseBGPMessage(data []byte, options ...*MarshallingOption) (*BGPMessage, error) {
	h := &BGPHeader{}
	err := h.DecodeFromBytes(data, options...)
	if err != nil {
		return nil, err
	}

	if int(h.Len) > len(data) {
		return nil, NewMessageError(BGP_ERROR_MESSAGE_HEADER_ERROR, BGP_ERROR_SUB_BAD_MESSAGE_LENGTH, nil, "unknown message type")
	}

	return parseBody(h, data[BGP_HEADER_LENGTH:h.Len], options...)
}

func ParseBGPBody(h *BGPHeader, data []byte, options ...*MarshallingOption) (*BGPMessage, error) {
	return parseBody(h, data, options...)
}

func (msg *BGPMessage) Serialize(options ...*MarshallingOption) ([]byte, error) {
	b, err := msg.Body.Serialize(options...)
	if err != nil {
		return nil, err
	}
	if msg.Header.Len == 0 {
		if BGP_HEADER_LENGTH+len(b) > BGP_MAX_MESSAGE_LENGTH {
			return nil, NewMessageError(0, 0, nil, fmt.Sprintf("too long message length %d", BGP_HEADER_LENGTH+len(b)))
		}
		msg.Header.Len = BGP_HEADER_LENGTH + uint16(len(b))
	}
	h, err := msg.Header.Serialize(options...)
	if err != nil {
		return nil, err
	}
	return append(h, b...), nil
}

type ErrorHandling int

const (
	ERROR_HANDLING_NONE ErrorHandling = iota
	ERROR_HANDLING_ATTRIBUTE_DISCARD
	ERROR_HANDLING_TREAT_AS_WITHDRAW
	ERROR_HANDLING_AFISAFI_DISABLE
	ERROR_HANDLING_SESSION_RESET
)

func getErrorHandlingFromPathAttribute(t BGPAttrType) ErrorHandling {
	switch t {
	case BGP_ATTR_TYPE_ORIGIN:
		return ERROR_HANDLING_TREAT_AS_WITHDRAW
	case BGP_ATTR_TYPE_AS_PATH:
		return ERROR_HANDLING_TREAT_AS_WITHDRAW
	case BGP_ATTR_TYPE_AS4_PATH:
		return ERROR_HANDLING_TREAT_AS_WITHDRAW
	case BGP_ATTR_TYPE_NEXT_HOP:
		return ERROR_HANDLING_TREAT_AS_WITHDRAW
	case BGP_ATTR_TYPE_MULTI_EXIT_DISC:
		return ERROR_HANDLING_TREAT_AS_WITHDRAW
	case BGP_ATTR_TYPE_LOCAL_PREF:
		return ERROR_HANDLING_TREAT_AS_WITHDRAW
	case BGP_ATTR_TYPE_ATOMIC_AGGREGATE:
		return ERROR_HANDLING_ATTRIBUTE_DISCARD
	case BGP_ATTR_TYPE_AGGREGATOR:
		return ERROR_HANDLING_ATTRIBUTE_DISCARD
	case BGP_ATTR_TYPE_AS4_AGGREGATOR:
		return ERROR_HANDLING_TREAT_AS_WITHDRAW
	case BGP_ATTR_TYPE_COMMUNITIES:
		return ERROR_HANDLING_TREAT_AS_WITHDRAW
	case BGP_ATTR_TYPE_ORIGINATOR_ID:
		return ERROR_HANDLING_TREAT_AS_WITHDRAW
	case BGP_ATTR_TYPE_CLUSTER_LIST:
		return ERROR_HANDLING_TREAT_AS_WITHDRAW
	case BGP_ATTR_TYPE_MP_REACH_NLRI:
		return ERROR_HANDLING_AFISAFI_DISABLE
	case BGP_ATTR_TYPE_MP_UNREACH_NLRI:
		return ERROR_HANDLING_AFISAFI_DISABLE
	case BGP_ATTR_TYPE_EXTENDED_COMMUNITIES:
		return ERROR_HANDLING_TREAT_AS_WITHDRAW
	case BGP_ATTR_TYPE_IP6_EXTENDED_COMMUNITIES:
		return ERROR_HANDLING_TREAT_AS_WITHDRAW
	case BGP_ATTR_TYPE_PMSI_TUNNEL:
		return ERROR_HANDLING_TREAT_AS_WITHDRAW
	case BGP_ATTR_TYPE_LARGE_COMMUNITY:
		return ERROR_HANDLING_TREAT_AS_WITHDRAW
	case BGP_ATTR_TYPE_TUNNEL_ENCAP:
		return ERROR_HANDLING_ATTRIBUTE_DISCARD
	case BGP_ATTR_TYPE_AIGP:
		return ERROR_HANDLING_ATTRIBUTE_DISCARD
	default:
		return ERROR_HANDLING_ATTRIBUTE_DISCARD
	}
}

type MessageError struct {
	TypeCode       uint8
	SubTypeCode    uint8
	Data           []byte
	Message        string
	ErrorHandling  ErrorHandling
	ErrorAttribute *PathAttributeInterface
}

func NewMessageError(typeCode, subTypeCode uint8, data []byte, msg string) error {
	return &MessageError{
		TypeCode:       typeCode,
		SubTypeCode:    subTypeCode,
		Data:           data,
		ErrorHandling:  ERROR_HANDLING_SESSION_RESET,
		ErrorAttribute: nil,
		Message:        msg,
	}
}

func NewMessageErrorWithErrorHandling(typeCode, subTypeCode uint8, data []byte, errorHandling ErrorHandling, errorAttribute *PathAttributeInterface, msg string) error {
	return &MessageError{
		TypeCode:       typeCode,
		SubTypeCode:    subTypeCode,
		Data:           data,
		ErrorHandling:  errorHandling,
		ErrorAttribute: errorAttribute,
		Message:        msg,
	}
}

func (e *MessageError) Error() string {
	return e.Message
}

func (e *MessageError) Stronger(err error) bool {
	if err == nil {
		return true
	}
	if msgErr, ok := err.(*MessageError); ok {
		return e.ErrorHandling > msgErr.ErrorHandling
	}
	return false
}

func (e *TwoOctetAsSpecificExtended) Flat() map[string]string {
	if e.SubType == EC_SUBTYPE_ROUTE_TARGET {
		return map[string]string{"routeTarget": e.String()}
	}
	return map[string]string{}
}

func (e *ColorExtended) Flat() map[string]string {
	return map[string]string{}
}

func (e *EncapExtended) Flat() map[string]string {
	return map[string]string{"encaspulation": e.TunnelType.String()}
}

func (e *DefaultGatewayExtended) Flat() map[string]string {
	return map[string]string{}
}

func (e *ValidationExtended) Flat() map[string]string {
	return map[string]string{}
}

func (e *LinkBandwidthExtended) Flat() map[string]string {
	return map[string]string{}
}

func (e *OpaqueExtended) Flat() map[string]string {
	return map[string]string{}
}

func (e *IPv4AddressSpecificExtended) Flat() map[string]string {
	return map[string]string{}
}

func (e *IPv6AddressSpecificExtended) Flat() map[string]string {
	return map[string]string{}
}

func (e *FourOctetAsSpecificExtended) Flat() map[string]string {
	return map[string]string{}
}

func (e *ESILabelExtended) Flat() map[string]string {
	return map[string]string{}
}

func (e *ESImportRouteTarget) Flat() map[string]string {
	return map[string]string{}
}

func (e *MacMobilityExtended) Flat() map[string]string {
	return map[string]string{}
}

func (e *RouterMacExtended) Flat() map[string]string {
	return map[string]string{}
}

func (e *TrafficRateExtended) Flat() map[string]string {
	return map[string]string{}
}

func (e *TrafficRemarkExtended) Flat() map[string]string {
	return map[string]string{}
}

func (e *RedirectIPv4AddressSpecificExtended) Flat() map[string]string {
	return map[string]string{}
}

func (e *RedirectIPv6AddressSpecificExtended) Flat() map[string]string {
	return map[string]string{}
}

func (e *RedirectFourOctetAsSpecificExtended) Flat() map[string]string {
	return map[string]string{}
}

func (e *UnknownExtended) Flat() map[string]string {
	return map[string]string{}
}

func (e *TrafficActionExtended) Flat() map[string]string {
	return map[string]string{}
}

func (p *PathAttributeExtendedCommunities) Flat() map[string]string {
	flat := map[string]string{}
	for _, ec := range p.Value {
		FlatUpdate(flat, ec.Flat())
	}
	return flat
}

func (p *PathAttribute) Flat() map[string]string {
	return map[string]string{}
}

func (l *LabeledVPNIPAddrPrefix) Flat() map[string]string {
	prefixLen := l.IPAddrPrefixDefault.Length - uint8(8*(l.Labels.Len()+l.RD.Len()))
	return map[string]string{
		"Prefix":    l.IPAddrPrefixDefault.Prefix.String(),
		"PrefixLen": fmt.Sprintf("%d", prefixLen),
		"NLRI":      l.String(),
		"Label":     l.Labels.String(),
	}
}

func (p *IPAddrPrefixDefault) Flat() map[string]string {
	l := strings.Split(p.String(), "/")
	if len(l) == 2 {
		return map[string]string{
			"Prefix":    l[0],
			"PrefixLen": l[1],
		}
	}
	return map[string]string{}
}

func (l *EVPNNLRI) Flat() map[string]string {
	return map[string]string{}
}
func (l *RouteTargetMembershipNLRI) Flat() map[string]string {
	return map[string]string{}
}
func (l *FlowSpecIPv4Unicast) Flat() map[string]string {
	return map[string]string{}
}
func (l *FlowSpecIPv4VPN) Flat() map[string]string {
	return map[string]string{}
}
func (l *FlowSpecIPv6Unicast) Flat() map[string]string {
	return map[string]string{}
}
func (l *FlowSpecIPv6VPN) Flat() map[string]string {
	return map[string]string{}
}
func (l *FlowSpecL2VPN) Flat() map[string]string {
	return map[string]string{}
}
func (l *OpaqueNLRI) Flat() map[string]string {
	return map[string]string{}
}

// Update a Flat representation by adding elements of the second
// one. If two elements use same keys, values are separated with
// ';'. In this case, it returns an error but the update has been
// realized.
func FlatUpdate(f1, f2 map[string]string) error {
	conflict := false
	for k2, v2 := range f2 {
		if v1, ok := f1[k2]; ok {
			f1[k2] = v1 + ";" + v2
			conflict = true
		} else {
			f1[k2] = v2
		}
	}
	if conflict {
		return errors.New("keys conflict")
	} else {
		return nil
	}
}
