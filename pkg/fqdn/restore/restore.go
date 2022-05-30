// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// The restore package provides data structures important to restoring
// DNS proxy rules. This package serves as a central source for these
// structures.
// Note that these are marshaled as JSON and any changes need to be compatible
// across an upgrade!
package restore

import (
	"bytes"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
)

// DNSRules contains IP-based DNS rules for a set of ports (e.g., 53)
type DNSRules map[uint16]IPRules

// IPRules is an unsorted collection of IPrules
type IPRules []IPRule

// IPRule stores the allowed destination IPs for a DNS names matching a regex
type IPRule struct {
	Re  RuleRegex
	IPs map[RuleIPOrCIDR]struct{} // IPs, nil set is wildcard and allows all IPs!
}

// RuleIPOrCIDR is one allowed destination IP or CIDR
// It marshals to/from text in a way that is compatible with net.IP and CIDRs
type RuleIPOrCIDR netip.Prefix

func ParseRuleIPOrCIDR(s string) (ip RuleIPOrCIDR, err error) {
	err = ip.UnmarshalText([]byte(s))
	return
}

func MustParseRuleIPOrCIDR(s string) (ip RuleIPOrCIDR) {
	if err := ip.UnmarshalText([]byte(s)); err != nil {
		panic(fmt.Errorf("bad input '%s': %s", s, err))
	}
	return
}

func (ip RuleIPOrCIDR) ContainsAddr(addr RuleIPOrCIDR) bool {
	return addr.IsAddr() && netip.Prefix(ip).Contains(netip.Prefix(addr).Addr())
}

func (ip RuleIPOrCIDR) IsAddr() bool {
	return netip.Prefix(ip).Bits() == -1
}

func (ip RuleIPOrCIDR) String() string {
	if ip.IsAddr() {
		return netip.Prefix(ip).Addr().String()
	} else {
		return netip.Prefix(ip).String()
	}
}

func (ip RuleIPOrCIDR) ToSingleCIDR() RuleIPOrCIDR {
	addr := netip.Prefix(ip).Addr()
	return RuleIPOrCIDR(netip.PrefixFrom(addr, addr.BitLen()))
}

func (ip RuleIPOrCIDR) MarshalText() ([]byte, error) {
	if ip.IsAddr() {
		return netip.Prefix(ip).Addr().MarshalText()
	} else {
		return netip.Prefix(ip).MarshalText()
	}
}

func (ip *RuleIPOrCIDR) UnmarshalText(b []byte) (err error) {
	if b == nil {
		return fmt.Errorf("cannot unmarshal nil into RuleIPOrCIDR")
	}
	if i := bytes.IndexByte(b, byte('/')); i < 0 {
		var addr netip.Addr
		if err = addr.UnmarshalText(b); err == nil {
			*ip = RuleIPOrCIDR(netip.PrefixFrom(addr, 0xff))
		}
	} else {
		var prefix netip.Prefix
		if err = prefix.UnmarshalText(b); err == nil {
			*ip = RuleIPOrCIDR(prefix)
		}
	}
	return
}

// RuleRegex is a wrapper for *regexp.Regexp so that we can define marshalers for it.
type RuleRegex struct {
	*regexp.Regexp
}

// Sort is only used for testing
// Sorts in place, but returns IPRules for convenience
func (r IPRules) Sort() IPRules {
	sort.SliceStable(r, func(i, j int) bool {
		return r[i].Re.String() < r[j].Re.String()
	})
	return r
}

// Sort is only used for testing
// Sorts in place, but returns DNSRules for convenience
func (r DNSRules) Sort() DNSRules {
	for port, ipRules := range r {
		if len(ipRules) > 0 {
			ipRules = ipRules.Sort()
			r[port] = ipRules
		}
	}
	return r
}

// UnmarshalText unmarshals json into a RuleRegex
// This must have a pointer receiver, otherwise the RuleRegex remains empty.
func (r *RuleRegex) UnmarshalText(b []byte) error {
	regex, err := regexp.Compile(string(b))
	if err != nil {
		return err
	}
	r.Regexp = regex
	return nil
}

// MarshalText marshals RuleRegex as string
func (r RuleRegex) MarshalText() ([]byte, error) {
	if r.Regexp != nil {
		return []byte(r.Regexp.String()), nil
	}
	return nil, nil
}
