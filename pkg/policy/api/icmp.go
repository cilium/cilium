// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import "strconv"

const (
	IPv4Family = "IPv4"
	IPv6Family = "IPv6"
)

type ICMPRules []ICMPRule

// ICMPRule is a list of ICMP fields.
type ICMPRule struct {
	// Fields is a list of ICMP fields.
	//
	// +kubebuilder:validation:Optional
	Fields []ICMPField `json:"fields,omitempty"`
}

// ICMPField is a ICMP field.
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
	// It should be 0-255 (8bit).
	//
	// +kubebuilder:validation:Maximum=255
	// +kubebuilder:validation:Minimum=0
	Type uint8 `json:"type"`
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

	typeStr := strconv.Itoa(int(i.Type))
	if i.Family == IPv6Family {
		proto = ProtoICMPv6
	} else {
		proto = ProtoICMP
	}

	pr := PortProtocol{
		Port:     typeStr,
		Protocol: proto,
	}
	return &pr
}
