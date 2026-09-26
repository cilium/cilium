// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ir

import (
	"github.com/cilium/cilium/api/v1/flow"
)

// IP tracks flow source/destination IP information.
type IP struct {
	SourceXlated string         `json:"sourceXlated,omitempty"`
	Source       string         `json:"source,omitempty"`
	Destination  string         `json:"destination,omitempty"`
	IPVersion    flow.IPVersion `json:"ipVersion,omitempty"`
	Encrypted    bool           `json:"encrypted,omitempty"`
}

// IsEmpty returns true if the struct has no data.
// NOTE: Leaving encrypted field unchecked since if no other fields are set the IP should be deemed empty.
func (i IP) IsEmpty() bool {
	return i.SourceXlated == "" &&
		i.Source == "" &&
		i.Destination == "" &&
		i.IPVersion == flow.IPVersion_IP_NOT_USED
}

// ipTestMerge merges ips types.
// NOTE: This is only used for testing!
func ipTestMerge(i1, i2 IP) IP {
	if i2.Source != "" {
		i1.Source = i2.Source
	}
	if i2.Destination != "" {
		i1.Destination = i2.Destination
	}
	if i2.SourceXlated != "" {
		i1.SourceXlated = i2.SourceXlated
	}
	if i2.Encrypted != i1.Encrypted {
		i1.Encrypted = i2.Encrypted
	}
	if i2.IPVersion != flow.IPVersion_IP_NOT_USED {
		i1.IPVersion = i2.IPVersion
	}

	return i1
}

func (ip IP) toProto() *flow.IP {
	if ip.IsEmpty() {
		return nil
	}

	return &flow.IP{
		Source:       ip.Source,
		Destination:  ip.Destination,
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
		Source:       i.Source,
		Destination:  i.Destination,
		IPVersion:    i.IpVersion,
		SourceXlated: i.SourceXlated,
		Encrypted:    i.Encrypted,
	}
}
