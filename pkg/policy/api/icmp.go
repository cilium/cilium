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
	"Echo Reply":              "0",
	"Destination Unreachable": "3",
	"Redirect":                "5",
	"Echo":                    "8",
	"Echo Request":            "8",
	"Router Advertisement":    "9",
	"Router Selection":        "10",
	"Time Exceeded":           "11",
	"Parameter Problem":       "12",
	"Timestamp":               "13",
	"Timestamp Reply":         "14",
	"Photuris":                "40",
	"Extended Echo Request":   "42",
	"Extended Echo Reply":     "43",
}

var icmpIpv6TypeNameToCode = map[string]string{
	"Destination Unreachable":                    "1",
	"Packet Too Big":                             "2",
	"Time Exceeded":                              "3",
	"Parameter Problem":                          "4",
	"Echo Request":                               "128",
	"Echo Reply":                                 "129",
	"Multicast Listener Query":                   "130",
	"Multicast Listener Report":                  "131",
	"Multicast Listener Done":                    "132",
	"Router Solicitation":                        "133",
	"Router Advertisement":                       "134",
	"Neighbor Solicitation":                      "135",
	"Neighbor Advertisement":                     "136",
	"Redirect Message":                           "137",
	"Router Renumbering":                         "138",
	"ICMP Node Information Query":                "139",
	"ICMP Node Information Response":             "140",
	"Inverse Neighbor Discovery Solicitation":    "141",
	"Inverse Neighbor Discovery Advertisement":   "142",
	"Home Agent Address Discovery Request":       "144",
	"Home Agent Address Discovery Reply":         "145",
	"Mobile Prefix Solicitation":                 "146",
	"Mobile Prefix Advertisement":                "147",
	"Duplicate Address Request Code Suffix":      "157",
	"Duplicate Address Confirmation Code Suffix": "158",
	"Extended Echo Request":                      "160",
	"Extended Echo Reply":                        "161",
}

type ICMPRules []ICMPRule

// ICMPRule is a list of ICMP fields.
type ICMPRule struct {
	// Fields is a list of ICMP fields.
	//
	// +kubebuilder:validation:Optional
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
	// It should be an 8bit code (0-255), or it's name (for example, "Echo Reply").
	// Allowed ICMP types are:
	//     Ipv4: Echo Reply | Destination Unreachable | Redirect | Echo | Echo Request |
	//		     Router Advertisement |Router Selection |Time Exceeded |Parameter Problem |
	//			 Timestamp | Timestamp Reply | Photuris | Extended Echo Request | Extended Echo Reply
	//     Ipv6: Destination Unreachable | Packet Too Big | Time Exceeded | Parameter Problem |
	//			 Echo Request | Echo Reply | Multicast Listener Query| Multicast Listener Report |
	// 			 Multicast Listener Done | Router Solicitation | Router Advertisement | Neighbor Solicitation |
	// 			 Neighbor Advertisement | Redirect Message | Router Renumbering | ICMP Node Information Query |
	// 			 ICMP Node Information Response | Inverse Neighbor Discovery Solicitation | Inverse Neighbor Discovery Advertisement |
	// 			 Home Agent Address Discovery Request | Home Agent Address Discovery Reply | Mobile Prefix Solicitation |
	// 			 Mobile Prefix Advertisement | Duplicate Address Request Code Suffix | Duplicate Address Confirmation Code Suffix |
	// 			 Extended Echo Request | Extended Echo Reply
	//
	// +deepequal-gen=false
	// +kubebuilder:validation:XIntOrString
	// +kubebuilder:validation:Pattern="^([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]|Echo Reply|Destination Unreachable|Redirect|Echo|Router Advertisement|Router Selection|Time Exceeded|Parameter Problem|Timestamp|Timestamp Reply|Photuris|Extended Echo Request|Extended Echo Reply|Packet Too Big|Parameter Problem|Echo Request|Multicast Listener Query|Multicast Listener Report|Multicast Listener Done|Router Solicitation|Router Advertisement|Neighbor Solicitation|Neighbor Advertisement|Redirect Message|Router Renumbering|ICMP Node Information Query|ICMP Node Information Response|Inverse Neighbor Discovery Solicitation|Inverse Neighbor Discovery Advertisement|Home Agent Address Discovery Request|Home Agent Address Discovery Reply|Mobile Prefix Solicitation|Mobile Prefix Advertisement|Duplicate Address Request Code Suffix|Duplicate Address Confirmation Code Suffix)$"
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
