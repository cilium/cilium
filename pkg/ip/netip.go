// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ip

import "net/netip"

// Addr wraps netip.Addr so it can be used as a field in Kubernetes API
// types. Embedding (rather than a defined type) inherits MarshalText /
// UnmarshalText. encoding/json falls back to those when no MarshalJSON /
// UnmarshalJSON is defined, preserving the textual wire format. The
// hand-written DeepCopyInto / DeepCopy / DeepEqual methods are required
// because deepcopy-gen and deepequal-gen cannot synthesize them for an
// external type with unexported pointer fields.
//
// Unlike Prefix, Addr carries no Format marker: the API server's CRD format
// registry only has `ipv4` and `ipv6` but no combined `ip` format, so we
// can't have format-based validation for a field that can be of either IP
// family.
//
// +k8s:deepcopy-gen=false
// +deepequal-gen=false
// +kubebuilder:validation:Type=string
type Addr struct {
	netip.Addr
}

// AddrFrom wraps a netip.Addr.
func AddrFrom(a netip.Addr) Addr { return Addr{Addr: a} }

// DeepCopyInto is a manual copy: netip.Addr's hidden zone pointer references
// interned, immutable data, so a value copy is safe.
func (in *Addr) DeepCopyInto(out *Addr) { *out = *in }

func (in *Addr) DeepCopy() *Addr {
	if in == nil {
		return nil
	}
	out := new(Addr)
	in.DeepCopyInto(out)
	return out
}

func (in *Addr) DeepEqual(other *Addr) bool {
	if in == nil || other == nil {
		return in == other
	}
	return in.Addr == other.Addr
}

// Addr deliberately does not define IsZero: netip.Addr's only invalid state
// is its zero value, so encoding/json's reflect-based zero check for the
// `omitzero` tag option produces the same result. See Prefix.IsZero for the
// case where an explicit method is required.

// Prefix wraps netip.Prefix, same rationale as Addr.
//
// +k8s:deepcopy-gen=false
// +deepequal-gen=false
// +kubebuilder:validation:Type=string
// +kubebuilder:validation:Format=cidr
type Prefix struct {
	netip.Prefix
}

// PrefixFrom wraps a netip.Prefix.
func PrefixFrom(p netip.Prefix) Prefix { return Prefix{Prefix: p} }

func (in *Prefix) DeepCopyInto(out *Prefix) { *out = *in }

func (in *Prefix) DeepCopy() *Prefix {
	if in == nil {
		return nil
	}
	out := new(Prefix)
	in.DeepCopyInto(out)
	return out
}

func (in *Prefix) DeepEqual(other *Prefix) bool {
	if in == nil || other == nil {
		return in == other
	}
	return in.Prefix == other.Prefix
}

// IsZero reports whether p is unset or invalid, for encoding/json's `omitzero`
// tag option. A Prefix built from a valid Addr with an out-of-range bit count
// (e.g. PrefixFrom(addr, -1)) is non-zero by reflect's definition but invalid
// by IsValid(), and would otherwise be emitted as `""`.
func (p Prefix) IsZero() bool { return !p.Prefix.IsValid() }
