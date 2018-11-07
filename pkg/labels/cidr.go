// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package labels

import (
	"fmt"
	"net"
	"strings"
)

// maskedIPToLabelString is the base method for serializing an IP + prefix into
// a string that can be used for creating Labels and EndpointSelector objects.
//
// For IPv6 addresses, it converts ":" into "-" as EndpointSelectors don't
// support colons inside the name section of a label.
func maskedIPToLabelString(ip *net.IP, prefix int) string {
	ipStr := ip.String()
	ipNoColons := strings.Replace(ipStr, ":", "-", -1)

	// EndpointSelector keys can't start or end with a "-", so insert a
	// zero at the start or end if it would otherwise have a "-" at that
	// position.
	preZero := ""
	postZero := ""
	if ipNoColons[0] == '-' {
		preZero = "0"
	}
	if ipNoColons[len(ipNoColons)-1] == '-' {
		postZero = "0"
	}
	return fmt.Sprintf("%s:%s%s%s/%d", LabelSourceCIDR, preZero,
		ipNoColons, postZero, prefix)
}

// IPNetToLabel turns a CIDR into a Label object which can be used to create
// EndpointSelector objects.
func IPNetToLabel(cidr *net.IPNet) Label {
	ones, _ := cidr.Mask.Size()
	lblStr := maskedIPToLabelString(&cidr.IP, ones)
	return ParseLabel(lblStr)
}

// IPStringToLabel parses a string and returns it as a CIDR label.
//
// If "IP" is not a valid IP address or CIDR Prefix, returns an error.
func IPStringToLabel(IP string) (Label, error) {
	_, parsedPrefix, err := net.ParseCIDR(IP)
	if err != nil {
		parsedIP := net.ParseIP(IP)
		if parsedIP == nil {
			return Label{}, fmt.Errorf("Not an IP address or CIDR: %s", IP)
		}
		bits := net.IPv6len * 8
		if parsedIP.To4() != nil {
			bits = net.IPv4len * 8
		}
		parsedPrefix = &net.IPNet{IP: parsedIP, Mask: net.CIDRMask(bits, bits)}
	}

	return IPNetToLabel(parsedPrefix), nil
}

// MaskedIPNetToLabelString masks the prefix/bits of the specified 'cidr' then
// turns the resulting CIDR into a label string for use elsewhere.
func MaskedIPNetToLabelString(cidr *net.IPNet, prefix, bits int) string {
	mask := net.CIDRMask(prefix, bits)
	maskedIP := cidr.IP.Mask(mask)
	return maskedIPToLabelString(&maskedIP, prefix)
}
