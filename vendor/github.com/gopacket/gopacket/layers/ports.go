// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"fmt"
	"strconv"

	"github.com/gopacket/gopacket"
)

// TCPPort is a port in a TCP layer.
type TCPPort uint16

// UDPPort is a port in a UDP layer.
type UDPPort uint16

// RUDPPort is a port in a RUDP layer.
type RUDPPort uint8

// SCTPPort is a port in a SCTP layer.
type SCTPPort uint16

// UDPLitePort is a port in a UDPLite layer.
type UDPLitePort uint16

// RUDPPortNames contains the string names for all RUDP ports.
var RUDPPortNames = map[RUDPPort]string{}

// UDPLitePortNames contains the string names for all UDPLite ports.
var UDPLitePortNames = map[UDPLitePort]string{}

// {TCP,UDP,SCTP}PortNames can be found in iana_ports.go

// String returns the port as "number(name)" if there's a well-known port name,
// or just "number" if there isn't.  Well-known names are stored in
// TCPPortNames.
func (a TCPPort) String() string {
	if name, ok := TCPPortNames(a); ok {
		return fmt.Sprintf("%d(%s)", a, name)
	}
	return strconv.Itoa(int(a))
}

// LayerType returns a LayerType that would be able to decode the
// application payload. It uses some well-known ports such as 53 for
// DNS.
//
// Returns gopacket.LayerTypePayload for unknown/unsupported port numbers.
func (a TCPPort) LayerType() gopacket.LayerType {
	if tcpPortLayerTypeOverride.has(uint16(a)) {
		return tcpPortLayerType[a]
	}
	switch a {
	case 53:
		return LayerTypeDNS
	case 443: // https
		return LayerTypeTLS
	case 502: // modbustcp
		return LayerTypeModbusTCP
	case 636: // ldaps
		return LayerTypeTLS
	case 989: // ftps-data
		return LayerTypeTLS
	case 990: // ftps
		return LayerTypeTLS
	case 992: // telnets
		return LayerTypeTLS
	case 993: // imaps
		return LayerTypeTLS
	case 994: // ircs
		return LayerTypeTLS
	case 995: // pop3s
		return LayerTypeTLS
	case 5061: // ips
		return LayerTypeTLS
	}
	return gopacket.LayerTypePayload
}

var tcpPortLayerTypeOverride bitfield

var tcpPortLayerType = map[TCPPort]gopacket.LayerType{}

// RegisterTCPPortLayerType creates a new mapping between a TCPPort
// and an underlaying LayerType.
func RegisterTCPPortLayerType(port TCPPort, layerType gopacket.LayerType) {
	tcpPortLayerTypeOverride.set(uint16(port))
	tcpPortLayerType[port] = layerType
}

// String returns the port as "number(name)" if there's a well-known port name,
// or just "number" if there isn't.  Well-known names are stored in
// UDPPortNames.
func (a UDPPort) String() string {
	if name, ok := UDPPortNames(a); ok {
		return fmt.Sprintf("%d(%s)", a, name)
	}
	return strconv.Itoa(int(a))
}

// LayerType returns a LayerType that would be able to decode the
// application payload. It uses some well-known ports such as 53 for
// DNS.
//
// Returns gopacket.LayerTypePayload for unknown/unsupported port numbers.
func (a UDPPort) LayerType() gopacket.LayerType {
	if udpPortLayerTypeOverride.has(uint16(a)) {
		return udpPortLayerType[a]
	}
	switch a {
	case 53:
		return LayerTypeDNS
	case 67:
		return LayerTypeDHCPv4
	case 68:
		return LayerTypeDHCPv4
	case 123:
		return LayerTypeNTP
	case 546:
		return LayerTypeDHCPv6
	case 547:
		return LayerTypeDHCPv6
	case 623:
		return LayerTypeRMCP
	case 1812:
		return LayerTypeRADIUS
	case 2152:
		return LayerTypeGTPv1U
	case 3784:
		return LayerTypeBFD
	case 4789:
		return LayerTypeVXLAN
	case 5060:
		return LayerTypeSIP
	case 6081:
		return LayerTypeGeneve
	case 6343:
		return LayerTypeSFlow
	}
	return gopacket.LayerTypePayload
}

var udpPortLayerTypeOverride bitfield

var udpPortLayerType = map[UDPPort]gopacket.LayerType{}

// RegisterUDPPortLayerType creates a new mapping between a UDPPort
// and an underlaying LayerType.
func RegisterUDPPortLayerType(port UDPPort, layerType gopacket.LayerType) {
	udpPortLayerTypeOverride.set(uint16(port))
	udpPortLayerType[port] = layerType
}

// String returns the port as "number(name)" if there's a well-known port name,
// or just "number" if there isn't.  Well-known names are stored in
// RUDPPortNames.
func (a RUDPPort) String() string {
	if name, ok := RUDPPortNames[a]; ok {
		return fmt.Sprintf("%d(%s)", a, name)
	}
	return strconv.Itoa(int(a))
}

// String returns the port as "number(name)" if there's a well-known port name,
// or just "number" if there isn't.  Well-known names are stored in
// SCTPPortNames.
func (a SCTPPort) String() string {
	if name, ok := SCTPPortNames(a); ok {
		return fmt.Sprintf("%d(%s)", a, name)
	}
	return strconv.Itoa(int(a))
}

// String returns the port as "number(name)" if there's a well-known port name,
// or just "number" if there isn't.  Well-known names are stored in
// UDPLitePortNames.
func (a UDPLitePort) String() string {
	if name, ok := UDPLitePortNames[a]; ok {
		return fmt.Sprintf("%d(%s)", a, name)
	}
	return strconv.Itoa(int(a))
}
