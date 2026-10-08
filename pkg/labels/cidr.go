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
	// Exported to access from tests in other packages
	WorldLabel   = Label{Source: LabelSourceReserved, Key: IDNameWorld}
	WorldLabelV4 = Label{Source: LabelSourceReserved, Key: IDNameWorldIPv4}
	WorldLabelV6 = Label{Source: LabelSourceReserved, Key: IDNameWorldIPv6}
)

// getCIDRLabel returns a Label representation of the given prefix. Should not be called for zero
// length prefixes, that need to be represented with a world label.
//
// For IPv6 addresses, it converts ":" into "-" as EndpointSelectors don't
// support colons inside the name section of a label.
func getCIDRLabel(prefix netip.Prefix) Label {
	ipv6 := prefix.Addr().Is6()
	ipStr := prefix.Masked().Addr().String()
	prefixLen := prefix.Bits()

	var str strings.Builder
	str.Grow(
		1 /* preZero */ +
			len(ipStr) +
			1 /* postZero */ +
			2 /*len of prefix*/ +
			1, /* '/' */
	)

	// Only scan bytes individually if needed (for an IPv6 address)
	if ipv6 {
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
	str.WriteString(strconv.Itoa(prefixLen))

	return Label{
		Key:    str.String(),
		Source: LabelSourceCIDR,
		cidr:   &prefix,
	}
}

// IPStringToLabel parses a string and returns it as a single CIDR label.
// World label is not added, but a zero-length prefix is represented as
// the appropriate world label.
// Single-label representation must only be used for selectors, identities always need the world
// label as well.
// If ip is not a valid IP address or CIDR Prefix, returns an error.
func IPStringToLabel(ip string) (Label, error) {
	var prefix netip.Prefix
	// factored out of netip.ParsePrefix to avoid allocating an empty netip.Prefix in case it's
	// an IP and not a CIDR.
	i := strings.LastIndexByte(ip, '/')
	if i < 0 {
		parsedIP, err := netip.ParseAddr(ip)
		if err != nil {
			return Label{}, fmt.Errorf("%q is not an IP address: %w", ip, err)
		}
		prefix, err = parsedIP.Prefix(parsedIP.BitLen())
		if err != nil {
			return Label{}, fmt.Errorf("%q cannot get prefix: %w", ip, err)
		}
	} else {
		var err error
		prefix, err = netip.ParsePrefix(ip)
		if err != nil {
			return Label{}, fmt.Errorf("%q is not a CIDR: %w", ip, err)
		}
	}

	if prefix.Bits() > 0 {
		return getCIDRLabel(prefix), nil
	}
	return getWorldLabel(prefix.Addr()), nil
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

// GetCIDRLabels turns a CIDR in to a specially formatted label, and returns
// a Labels including the CIDR-specific label and the appropriate world label.
// e.g. "10.0.0.0/8" => ["cidr:10.0.0.0/8", "reserved:world-ipv4"]
// For a zero-length prefix only the world label is returned, e.g.,
// "0.0.0.0/0" => ["reserved:world-ipv4"]
//
// Returned Labels should be used for defining CIDR identities. For CIDR selectors IPStringToLabel
// should be used instead.
//
// IPv6 requires some special treatment, since ":" is special in the label selector
// grammar. For example, "::1/128" becomes "cidr:0--1/128" ("::/0" becomes ["reserved:world-ipv6"]).
func GetCIDRLabels(prefix netip.Prefix) Labels {
	lbls := make(Labels, 2)
	if prefix.Bits() > 0 {
		l := getCIDRLabel(prefix)
		lbls[l.Key] = l
	}
	lbls.AddWorldLabel(prefix.Addr())

	return lbls
}

// GetCIDRLabelArray is similar to GetCIDRLabels, but returns the result as an LabelArray,
// preserving order of the returned labels.
//
// Returned Labels should be used for defining CIDR identities. For CIDR selectors IPStringToLabel
// should be used instead.
func GetCIDRLabelArray(prefix netip.Prefix) LabelArray {
	lbls := make(LabelArray, 0, 2)
	if prefix.Bits() > 0 {
		lbls = append(lbls, getCIDRLabel(prefix))
	}
	lbls = append(lbls, getWorldLabel(prefix.Addr()))
	return lbls
}

func (lbls Labels) AddWorldLabel(addr netip.Addr) {
	lbl := getWorldLabel(addr)
	lbls[lbl.Key] = lbl
}

// getWorldLabel returns the appropriate world label for the given address depending on the address
// family (IPv4 or IPv6) and configuration (whether IPv4, IPv6, or both are enabled).
// - if only one address family is enabled, then the "world" label is used for that family
// - otherwise the "world-ipv4" used for IPv4 addresses, and "world-ipv6" for IPv6 addresses.
//
// A label is returned for IP address even if the address family is disabled. In production this
// will not match anything (e.g., "world-ipv6" in IPv4-only deployment will not be populated into
// identities, so a selector with that label will never match anything), but allows a label selector
// to be created for each (wildcard) CIDR in the policy without erroring out. Alternatively we could
// consider validating the address family of a policy CIDR is enabled at runtime.
func getWorldLabel(addr netip.Addr) Label {
	switch {
	case addr.Is4() && option.Config.EnableIPv6:
		// IPv6 is enabled, so this is either dualstack, or singlestack with IPv4 disabled.
		// In both cases we have to use the qualified world label for IPv4
		return WorldLabelV4
	case addr.Is6() && option.Config.EnableIPv4:
		// IPv4 is enabled, so this is either dualstack, or singlestack with IPv6 disabled.
		// In both cases we have to use the qualified world label for IPv6
		return WorldLabelV6
	}
	// single-stack with an enabled family
	return WorldLabel
}

func keyToPrefix(key string) (netip.Prefix, error) {
	prefixStr := strings.ReplaceAll(key, "-", ":")
	pfx, err := netip.ParsePrefix(prefixStr)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("failed to parse label prefix %s: %w", key, err)
	}
	return pfx, nil
}
