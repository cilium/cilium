// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package labels

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/cilium/cilium/pkg/option"
)

var (
	worldLabelNonDualStack = Label{Source: LabelSourceReserved, Key: IDNameWorld}
	worldLabelV4           = Label{Source: LabelSourceReserved, Key: IDNameWorldIPv4}
	worldLabelV6           = Label{Source: LabelSourceReserved, Key: IDNameWorldIPv6}
)

// maskedIPToLabelString is the base method for serializing an IP + prefix into
// a string that can be used for creating Labels and EndpointSelector objects.
//
// For IPv6 addresses, it converts ":" into "-" as EndpointSelectors don't
// support colons inside the name section of a label.
func MaskedIPToLabelString(ipStr string, prefix int) string {
	var str strings.Builder
	str.Grow(
		1 /* preZero */ +
			len(ipStr) +
			1 /* postZero */ +
			2 /*len of prefix*/ +
			1, /* '/' */
	)

	if strings.ContainsRune(ipStr, ':') {
		for i := range len(ipStr) {
			if ipStr[i] == ':' {
				// EndpointSelector keys can't start or end with a "-", so insert a
				// zero at the start or end if it would otherwise have a "-" at that
				// position.
				if i == 0 {
					str.WriteByte('0')
					str.WriteByte('-')
					continue
				}
				if i == len(ipStr)-1 {
					str.WriteByte('-')
					str.WriteByte('0')
					continue
				}
				str.WriteByte('-')
			} else {
				str.WriteByte(ipStr[i])
			}
		}
	} else {
		str.WriteString(ipStr)
	}
	str.WriteRune('/')
	str.WriteString(strconv.Itoa(prefix))
	return str.String()
}

// maskedIPToLabelString is the base method for serializing an IP + prefix into
// a string that can be used for creating Labels and EndpointSelector objects.
//
// For IPv6 addresses, it converts ":" into "-" as EndpointSelectors don't
// support colons inside the name section of a label.
func maskedIPToLabel(ipStr string, prefix int) Label {
	return Label{Key: MaskedIPToLabelString(ipStr, prefix), Source: LabelSourceCIDR}
}

var (
	ErrLabelNotCIDR = errors.New("Label is not a CIDR label")
)

// CIDRLabelToIPString reverses IPStringToLabel for testing purposes, mainly.
func (l Label) ToCIDRString() (string, error) {
	if l.cidr == nil || l.Source != LabelSourceCIDR || l.Value != "" {
		return "", ErrLabelNotCIDR
	}
	return l.cidr.String(), nil
}

// IPStringToLabel parses a string and returns it as a CIDR label.
//
// If ip is not a valid IP address or CIDR Prefix, returns an error.
func IPStringToLabel(ip string) (Label, error) {
	// factored out of netip.ParsePrefix to avoid allocating an empty netip.Prefix in case it's
	// an IP and not a CIDR.
	i := strings.LastIndexByte(ip, '/')
	if i < 0 {
		parsedIP, err := netip.ParseAddr(ip)
		if err != nil {
			return Label{}, fmt.Errorf("%q is not an IP address: %w", ip, err)
		}
		return maskedIPToLabel(ip, parsedIP.BitLen()), nil
	} else {
		parsedPrefix, err := netip.ParsePrefix(ip)
		if err != nil {
			return Label{}, fmt.Errorf("%q is not a CIDR: %w", ip, err)
		}
		return maskedIPToLabel(parsedPrefix.Masked().Addr().String(), parsedPrefix.Bits()), nil
	}
}

func GetCIDRLabel(prefix netip.Prefix) Label {
	l := maskedIPToLabel(prefix.Masked().Addr().String(), prefix.Bits())
	l.cidr = &prefix
	return l
}

// GetCIDRLabels turns a CIDR in to a specially formatted label, and returns
// a Labels including the CIDR-specific label and the appropriate world label.
// e.g. "10.0.0.0/8" => ["cidr:10.0.0.0/8", "reserved:world-ipv4"]
//
// IPv6 requires some special treatment, since ":" is special in the label selector
// grammar. For example, "::/0" becomes "cidr:0--0/0",
func GetCIDRLabels(prefix netip.Prefix) Labels {
	lbls := make(Labels, 2)
	if prefix.Bits() > 0 {
		l := GetCIDRLabel(prefix)
		lbls[l.Key] = l
	}
	lbls.AddWorldLabel(prefix.Addr())

	return lbls
}

func (lbls Labels) AddWorldLabel(addr netip.Addr) {
	switch {
	case !option.Config.IsDualStack():
		lbls[worldLabelNonDualStack.Key] = worldLabelNonDualStack
	case addr.Is4():
		lbls[worldLabelV4.Key] = worldLabelV4
	default:
		lbls[worldLabelV6.Key] = worldLabelV6
	}
}

func LabelToPrefix(key string) (netip.Prefix, error) {
	prefixStr := strings.ReplaceAll(key, "-", ":")
	pfx, err := netip.ParsePrefix(prefixStr)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("failed to parse label prefix %s: %w", key, err)
	}
	return pfx, nil
}
