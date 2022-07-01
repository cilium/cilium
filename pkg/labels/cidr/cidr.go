// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cidr

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/cilium/cilium/pkg/labels"
)

// maskedIPToLabelString is the base method for serializing an IP + prefix into
// a string that can be used for creating Labels and EndpointSelector objects.
//
// For IPv6 addresses, it converts ":" into "-" as EndpointSelectors don't
// support colons inside the name section of a label.
func maskedIPToLabelString(ip netip.Addr, prefix int) string {
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

// IPStringToLabel parses a string and returns it as a CIDR label.
//
// If ip is not a valid IP address or CIDR Prefix, returns an error.
func IPStringToLabel(ip string) (labels.Label, error) {
	var lblString string
	// factored out of netip.ParsePrefix to avoid allocating an empty netip.Prefix in case it's
	// an IP and not a CIDR.
	i := strings.LastIndexByte(ip, '/')
	if i < 0 {
		parsedIP, err := netip.ParseAddr(ip)
		if err != nil {
			return labels.Label{}, fmt.Errorf("%q is not an IP address: %w", ip, err)
		}
		lblString = maskedIPToLabelString(parsedIP, parsedIP.BitLen())
	} else {
		parsedPrefix, err := netip.ParsePrefix(ip)
		if err != nil {
			return labels.Label{}, fmt.Errorf("%q is not a CIDR: %w", ip, err)
		}
		lblString = maskedIPToLabelString(parsedPrefix.Masked().Addr(), parsedPrefix.Bits())
	}
	return labels.ParseLabel(lblString), nil
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
	ones, _ := cidr.Mask.Size()
	result := make([]string, 0, ones+1)

	// If ones is zero, then it's the default CIDR prefix /0 which should
	// just be regarded as reserved:world. In all other cases, we need
	// to generate the set of prefixes starting from the /0 up to the
	// specified prefix length.
	if ones > 0 {
		ip, _ := netip.AddrFromSlice(cidr.IP)
		for i := 0; i <= ones; i++ {
			prefix := netip.PrefixFrom(ip, i)
			label := maskedIPToLabelString(prefix.Masked().Addr(), i)
			result = append(result, label)
		}
	}

	result = append(result, labels.LabelSourceReserved+":"+labels.IDNameWorld)

	return labels.NewLabelsFromModel(result)
}
