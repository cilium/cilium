// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ir

import (
	"net"

	"github.com/cilium/cilium/api/v1/flow"
)

// IP tracks flow source/destination IP information.
type IP struct {
	SourceXlated string         `json:"sourceXlated,omitempty"`
	Source       net.IP         `json:"source,omitempty"`
	Destination  net.IP         `json:"destination,omitempty"`
	IPVersion    flow.IPVersion `json:"ipVersion,omitempty"`
	Encrypted    bool           `json:"encrypted,omitempty"`
}

// IsEmpty returns true if the struct has no data.
func (i IP) IsEmpty() bool {
	return i.IPVersion == flow.IPVersion_IP_NOT_USED && i.Source == nil && i.Destination == nil && i.SourceXlated == ""
}

func (i IP) merge(i1 IP) IP {
	if i1.Source != nil {
		i.Source = i1.Source
	}
	if i1.Destination != nil {
		i.Destination = i1.Destination
	}
	if i1.SourceXlated != "" {
		i.SourceXlated = i1.SourceXlated
	}
	if i.Encrypted != i1.Encrypted {
		i.Encrypted = i1.Encrypted
	}
	if i1.IPVersion != flow.IPVersion_IP_NOT_USED {
		i.IPVersion = i1.IPVersion
	}

	return i
}

func (ip IP) toProto() *flow.IP {
	if ip.IsEmpty() {
		return nil
	}

	var sip string
	if ip.Source != nil {
		sip = ip.Source.String()
	}
	var dip string
	if ip.Destination != nil {
		dip = ip.Destination.String()
	}

	return &flow.IP{
		Source:       sip,
		Destination:  dip,
		IpVersion:    ip.IPVersion,
		SourceXlated: ip.SourceXlated,
		Encrypted:    ip.Encrypted,
	}
}

func protoToIP(i *flow.IP) IP {
	if i == nil {
		return IP{}
	}

	return IP{
		Source:       net.ParseIP(i.Source),
		Destination:  net.ParseIP(i.Destination),
		IPVersion:    i.IpVersion,
		SourceXlated: i.SourceXlated,
		Encrypted:    i.Encrypted,
	}
}
