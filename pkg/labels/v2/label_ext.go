// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2

import (
	"bytes"
	"fmt"
	"net/netip"
	"strings"
)

//
// Convenience methods for 'Label'
//

const (
	// LabelSourceUnspec is a label with unspecified source
	LabelSourceUnspec = "unspec"

	// LabelSourceAny is a label that matches any source
	LabelSourceAny = "any"

	// LabelSourceAnyKeyPrefix is prefix of a "any" label
	LabelSourceAnyKeyPrefix = LabelSourceAny + "."

	// LabelSourceK8s is a label imported from Kubernetes
	LabelSourceK8s = "k8s"

	// LabelSourceK8sKeyPrefix is prefix of a Kubernetes label
	LabelSourceK8sKeyPrefix = LabelSourceK8s + "."

	// LabelSourceContainer is a label imported from the container runtime
	LabelSourceContainer = "container"

	// LabelSourceCNI is a label imported from the CNI plugin
	LabelSourceCNI = "cni"

	// LabelSourceReserved is the label source for reserved types.
	LabelSourceReserved = "reserved"

	// LabelSourceCIDR is the label source for generated CIDRs.
	LabelSourceCIDR = "cidr"

	// LabelSourceCIDRGroup is the label source used for labels from CIDRGroups
	LabelSourceCIDRGroup = "cidrgroup"

	// LabelSourceNode is the label source for remote-nodes.
	LabelSourceNode = "node"

	// LabelSourceFQDN is the label source for IPs resolved by fqdn lookups
	LabelSourceFQDN = "fqdn"

	// LabelSourceReservedKeyPrefix is the prefix of a reserved label
	LabelSourceReservedKeyPrefix = LabelSourceReserved + "."

	// LabelSourceDirectory is the label source for policies read from files
	LabelSourceDirectory = "directory"
)

// EqualIgnoringAnySource returns true if source (ignoring 'any'), Key and Value are equal and false otherwise.
func (l Label) EqualIgnoringAnySource(b Label) bool {
	if !l.IsAnySource() && l.Source() != b.Source() {
		return false
	}
	return l.Equal(b)
}

func (l Label) DeepEqual(other *Label) bool {
	return l.Equal(*other)
}

func (l Label) CIDR() *netip.Prefix {
	return l.rep().cidr
}

// Has returns true label L contains target.
// target may be "looser" w.r.t source or cidr, i.e.
// "k8s:foo=bar".Has("any:foo=bar") is true
// "any:foo=bar".Has("k8s:foo=bar") is false
// "cidr:10.0.0.1/32".Has("cidr:10.0.0.0/24") is true
func (l Label) Has(target Label) bool {
	return l.HasKey(target) && l.Value() == target.Value()
}

// HasKey returns true if l has target's key.
// target may be "looser" w.r.t source or cidr, i.e.
// "k8s:foo=bar".HasKey("any:foo") is true
// "any:foo=bar".HasKey("k8s:foo") is false
// "cidr:10.0.0.1/32".HasKey("cidr:10.0.0.0/24") is true
// "cidr:10.0.0.0/24".HasKey("cidr:10.0.0.1/32") is false
func (l Label) HasKey(target Label) bool {
	if !target.IsAnySource() && l.Source() != target.Source() {
		return false
	}

	// Do cidr-aware matching if both sources are "cidr".
	if target.Source() == LabelSourceCIDR && l.Source() == LabelSourceCIDR {
		tc := target.CIDR()
		if tc == nil {
			v, err := LabelToPrefix(target.Key())
			if err != nil {
				tc = &v
			}
		}
		lc := l.CIDR()
		if lc == nil {
			v, err := LabelToPrefix(l.Key())
			if err != nil {
				lc = &v
			}
		}
		if tc != nil && lc != nil && tc.Bits() <= lc.Bits() && tc.Contains(lc.Addr()) {
			return true
		}
	}

	return l.Key() == target.Key()
}

// IsValid returns true if Key != "".
func (l Label) IsValid() bool {
	return l.Key() != ""
}

// IsAnySource return if the label was set with source "any".
func (l Label) IsAnySource() bool {
	return l.Source() == LabelSourceAny
}

// IsReservedSource return if the label was set with source "Reserved".
func (l Label) IsReservedSource() bool {
	return l.Source() == LabelSourceReserved
}

const PathDelimiter = "."

// GetExtendedKey returns the key of a label with the source encoded.
func (l Label) GetExtendedKey() string {
	return l.Source() + PathDelimiter + l.Key()
}

func LabelToPrefix(key string) (netip.Prefix, error) {
	prefixStr := strings.Replace(key, "-", ":", -1)
	pfx, err := netip.ParsePrefix(prefixStr)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("failed to parse label prefix %s: %w", key, err)
	}
	return pfx, nil
}

// FormatForKVStore returns the label as a formatted string, ending in
// a semicolon
//
// DO NOT BREAK THE FORMAT OF THIS. THE RETURNED STRING IS USED AS
// PART OF THE KEY IN THE KEY-VALUE STORE.
//
// Non-pointer receiver allows this to be called on a value in a map.
func (l Label) FormatForKVStore() []byte {
	// We don't care if the values already have a '='.
	//
	// We absolutely care that the final character is a semi-colon.
	// Identity allocation in the kvstore depends on this (see
	// kvstore.prefixMatchesKey())
	b := make([]byte, 0, len(l.Source())+len(l.Key())+len(l.Value())+3)
	buf := bytes.NewBuffer(b)
	l.FormatForKVStoreInto(buf)
	return buf.Bytes()
}

// FormatForKVStoreInto writes the label as a formatted string, ending in
// a semicolon into buf.
//
// DO NOT BREAK THE FORMAT OF THIS. THE RETURNED STRING IS USED AS
// PART OF THE KEY IN THE KEY-VALUE STORE.
//
// Non-pointer receiver allows this to be called on a value in a map.
func (l Label) FormatForKVStoreInto(buf *bytes.Buffer) {
	buf.WriteString(l.Source())
	buf.WriteRune(':')
	buf.WriteString(l.Key())
	buf.WriteRune('=')
	buf.WriteString(l.Value())
	buf.WriteRune(';')
}
