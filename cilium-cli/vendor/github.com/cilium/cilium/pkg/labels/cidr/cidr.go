// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cidr

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/cilium/cilium/pkg/labels"
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
	var str strings.Builder
	str.Grow(
		len(labels.LabelSourceCIDR) +
			len(preZero) +
			len(ipNoColons) +
			len(postZero) +
			2 /*len of prefix*/ +
			2, /* ':' '/' */
	)
	str.WriteString(labels.LabelSourceCIDR)
	str.WriteRune(':')
	str.WriteString(preZero)
	str.WriteString(ipNoColons)
	str.WriteString(postZero)
	str.WriteRune('/')
	str.WriteString(strconv.Itoa(prefix))
	return str.String()
}

// ipNetToLabel turns a CIDR into a Label object which can be used to create
// EndpointSelector objects.
func ipNetToLabel(cidr *net.IPNet) labels.Label {
	ones, _ := cidr.Mask.Size()
	lblStr := maskedIPToLabelString(&cidr.IP, ones)
	return labels.ParseLabel(lblStr)
}

// IPStringToLabel parses a string and returns it as a CIDR label.
//
// If "IP" is not a valid IP address or CIDR Prefix, returns an error.
func IPStringToLabel(IP string) (labels.Label, error) {
	_, parsedPrefix, err := net.ParseCIDR(IP)
	if err != nil {
		parsedIP := net.ParseIP(IP)
		if parsedIP == nil {
			return labels.Label{}, fmt.Errorf("Not an IP address or CIDR: %s", IP)
		}
		bits := net.IPv6len * 8
		if parsedIP.To4() != nil {
			bits = net.IPv4len * 8
		}
		parsedPrefix = &net.IPNet{IP: parsedIP, Mask: net.CIDRMask(bits, bits)}
	}

	return ipNetToLabel(parsedPrefix), nil
}

// maskedIPNetToLabelString masks the prefix/bits of the specified 'cidr' then
// turns the resulting CIDR into a label string for use elsewhere.
func maskedIPNetToLabelString(cidr *net.IPNet, prefix, bits int) string {
	mask := net.CIDRMask(prefix, bits)
	maskedIP := cidr.IP.Mask(mask)
	return maskedIPToLabelString(&maskedIP, prefix)
}

// GetCIDRLabels turns a CIDR into a set of labels representing the cidr itself
// and all broader CIDRS which include the specified CIDR in them. For example:
// CIDR: 10.0.0.0/8 =>
//     "cidr:10.0.0.0/8", "cidr:10.0.0.0/7", "cidr:8.0.0.0/6",
//     "cidr:8.0.0.0/5", "cidr:0.0.0.0/4, "cidr:0.0.0.0/3",
//     "cidr:0.0.0.0/2",  "cidr:0.0.0.0/1",  "cidr:0.0.0.0/0"
//
// The identity reserved:world is always added as it includes any CIDR.
func GetCIDRLabels(cidr *net.IPNet) labels.Labels {
	ones, bits := cidr.Mask.Size()
	result := make([]string, 0, ones+1)

	// If ones is zero, then it's the default CIDR prefix /0 which should
	// just be regarded as reserved:world. In all other cases, we need
	// to generate the set of prefixes starting from the /0 up to the
	// specified prefix length.
	if ones > 0 {
		for i := 0; i <= ones; i++ {
			label := maskedIPNetToLabelString(cidr, i, bits)
			result = append(result, label)
		}
	}

	result = append(result, labels.LabelSourceReserved+":"+labels.IDNameWorld)

	return labels.NewLabelsFromModel(result)
}
