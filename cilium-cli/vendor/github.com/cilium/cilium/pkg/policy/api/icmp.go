// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"encoding/json"
	"fmt"

	"k8s.io/apimachinery/pkg/util/intstr"
)

const (
	IPv4Family = "IPv4"
	IPv6Family = "IPv6"
)

var icmpIpv4TypeNameToCode = map[string]string{
	"EchoReply":              "0",
	"DestinationUnreachable": "3",
	"Redirect":               "5",
	"Echo":                   "8",
	"EchoRequest":            "8",
	"RouterAdvertisement":    "9",
	"RouterSelection":        "10",
	"TimeExceeded":           "11",
	"ParameterProblem":       "12",
	"Timestamp":              "13",
	"TimestampReply":         "14",
	"Photuris":               "40",
	"ExtendedEchoRequest":    "42",
	"ExtendedEchoReply":      "43",
}

var icmpIpv6TypeNameToCode = map[string]string{
	"DestinationUnreachable":                 "1",
	"PacketTooBig":                           "2",
	"TimeExceeded":                           "3",
	"ParameterProblem":                       "4",
	"EchoRequest":                            "128",
	"EchoReply":                              "129",
	"MulticastListenerQuery":                 "130",
	"MulticastListenerReport":                "131",
	"MulticastListenerDone":                  "132",
	"RouterSolicitation":                     "133",
	"RouterAdvertisement":                    "134",
	"NeighborSolicitation":                   "135",
	"NeighborAdvertisement":                  "136",
	"RedirectMessage":                        "137",
	"RouterRenumbering":                      "138",
	"ICMPNodeInformationQuery":               "139",
	"ICMPNodeInformationResponse":            "140",
	"InverseNeighborDiscoverySolicitation":   "141",
	"InverseNeighborDiscoveryAdvertisement":  "142",
	"HomeAgentAddressDiscoveryRequest":       "144",
	"HomeAgentAddressDiscoveryReply":         "145",
	"MobilePrefixSolicitation":               "146",
	"MobilePrefixAdvertisement":              "147",
	"DuplicateAddressRequestCodeSuffix":      "157",
	"DuplicateAddressConfirmationCodeSuffix": "158",
	"ExtendedEchoRequest":                    "160",
	"ExtendedEchoReply":                      "161",
}

type ICMPRules []ICMPRule

// ICMPRule is a list of ICMP fields.
type ICMPRule struct {
	// Fields is a list of ICMP fields.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxItems=40
	Fields []ICMPField `json:"fields,omitempty"`
}

// ICMPField is a ICMP field.
//
// +deepequal-gen=true
// +deepequal-gen:private-method=true
type ICMPField struct {
	// Family is a IP address version.
	// Currently, we support `IPv4` and `IPv6`.
	// `IPv4` is set as default.
	//
	// +kubebuilder:default=IPv4
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Enum=IPv4;IPv6
	Family string `json:"family,omitempty"`

	// Type is a ICMP-type.
	// It should be an 8bit code (0-255), or it's CamelCase name (for example, "EchoReply").
	// Allowed ICMP types are:
	//     Ipv4: EchoReply | DestinationUnreachable | Redirect | Echo | EchoRequest |
	//		     RouterAdvertisement | RouterSelection | TimeExceeded | ParameterProblem |
	//			 Timestamp | TimestampReply | Photuris | ExtendedEcho Request | ExtendedEcho Reply
	//     Ipv6: DestinationUnreachable | PacketTooBig | TimeExceeded | ParameterProblem |
	//			 EchoRequest | EchoReply | MulticastListenerQuery| MulticastListenerReport |
	// 			 MulticastListenerDone | RouterSolicitation | RouterAdvertisement | NeighborSolicitation |
	// 			 NeighborAdvertisement | RedirectMessage | RouterRenumbering | ICMPNodeInformationQuery |
	// 			 ICMPNodeInformationResponse | InverseNeighborDiscoverySolicitation | InverseNeighborDiscoveryAdvertisement |
	// 			 HomeAgentAddressDiscoveryRequest | HomeAgentAddressDiscoveryReply | MobilePrefixSolicitation |
	// 			 MobilePrefixAdvertisement | DuplicateAddressRequestCodeSuffix | DuplicateAddressConfirmationCodeSuffix |
	// 			 ExtendedEchoRequest | ExtendedEchoReply
	//
	// +deepequal-gen=false
	// +kubebuilder:validation:XIntOrString
	// +kubebuilder:validation:Pattern="^([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]|EchoReply|DestinationUnreachable|Redirect|Echo|RouterAdvertisement|RouterSelection|TimeExceeded|ParameterProblem|Timestamp|TimestampReply|Photuris|ExtendedEchoRequest|ExtendedEcho Reply|PacketTooBig|ParameterProblem|EchoRequest|MulticastListenerQuery|MulticastListenerReport|MulticastListenerDone|RouterSolicitation|RouterAdvertisement|NeighborSolicitation|NeighborAdvertisement|RedirectMessage|RouterRenumbering|ICMPNodeInformationQuery|ICMPNodeInformationResponse|InverseNeighborDiscoverySolicitation|InverseNeighborDiscoveryAdvertisement|HomeAgentAddressDiscoveryRequest|HomeAgentAddressDiscoveryReply|MobilePrefixSolicitation|MobilePrefixAdvertisement|DuplicateAddressRequestCodeSuffix|DuplicateAddressConfirmationCodeSuffix)$"
	Type *intstr.IntOrString `json:"type"`
}

func (i *ICMPField) DeepEqual(o *ICMPField) bool {
	if i == nil {
		return o == nil
	}

	if i.Type.String() != o.Type.String() {
		return false
	}

	return i.deepEqual(o)
}

// UnmarshalJSON unmarshals the ICMPField from the byte array and check if the Type matches with IP version.
func (i *ICMPField) UnmarshalJSON(value []byte) error {
	var t struct {
		Family string              `json:"family,omitempty"`
		Type   *intstr.IntOrString `json:"type"`
	}

	if err := json.Unmarshal(value, &t); err != nil {
		return err
	}

	// If i.Type is ICMP type name, the value should be checked if it belongs to the map for the given family.
	if t.Type.String() != "0" && t.Type.IntValue() == 0 {
		name := t.Type.String()
		var nameToCode map[string]string
		switch t.Family {
		case IPv6Family:
			nameToCode = icmpIpv6TypeNameToCode
		default:
			nameToCode = icmpIpv4TypeNameToCode
		}

		if _, ok := nameToCode[name]; !ok {
			return fmt.Errorf("ICMP type %s not found in %s", name, t.Family)
		}
	}

	i.Family = t.Family
	i.Type = t.Type

	return nil
}

// Iterate iterates over all elements of ICMPRules.
func (ir ICMPRules) Iterate(f func(pr Ports) error) error {
	for i := range ir {
		if err := f(&ir[i]); err != nil {
			return err
		}
	}
	return nil
}

// Len returns the length of the elements of ICMPRules.
func (ir ICMPRules) Len() int {
	return len(ir)
}

// GetPortProtocols generates PortProtocol slice from ICMPRule and returns it.
func (ir ICMPRule) GetPortProtocols() []PortProtocol {
	var pps []PortProtocol
	for _, t := range ir.Fields {
		pp := t.PortProtocol()
		pps = append(pps, *pp)
	}
	return pps
}

// GetPortRule generates PortRule from ICMPRule and returns it.
func (ir ICMPRule) GetPortRule() *PortRule {
	var pps []PortProtocol
	for _, t := range ir.Fields {
		pp := t.PortProtocol()
		pps = append(pps, *pp)
	}
	pr := PortRule{
		Ports: pps,
	}
	return &pr
}

// PortProtocol translates ICMPType to PortProtocol.
func (i ICMPField) PortProtocol() *PortProtocol {
	var proto L4Proto
	var nameToCode map[string]string

	switch i.Family {
	case IPv6Family:
		proto = ProtoICMPv6
		nameToCode = icmpIpv6TypeNameToCode

	default:
		proto = ProtoICMP
		nameToCode = icmpIpv4TypeNameToCode
	}

	port := i.Type.String()
	if name, ok := nameToCode[port]; ok {
		port = name
	}

	pr := PortProtocol{
		Port:     port,
		Protocol: proto,
	}
	return &pr
}
