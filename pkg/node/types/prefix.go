// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"

	"github.com/cilium/cilium/pkg/ip"
)

// Prefix is a transitional wrapper used for the Node kvstore CIDR fields that
// were previously *cidr.CIDR. It embeds ip.Prefix (the canonical netip.Prefix
// wrapper this migration converges on) so it inherits String/IsValid and the
// generated-code DeepCopy/DeepEqual pattern, while overriding JSON marshaling
// to preserve backward compatibility on the wire.
//
// See issue https://github.com/cilium/cilium/issues/46924 for the full context
// and motivation behind this type and why it is needed.
//
// +k8s:deepcopy-gen=false
// +deepequal-gen=false
type Prefix struct {
	ip.Prefix
}

// PrefixFrom wraps a netip.Prefix, canonicalizing it to its masked network
// address so the emitted legacy object matches what net.ParseCIDR produced.
func PrefixFrom(p netip.Prefix) Prefix {
	return Prefix{ip.PrefixFrom(p.Masked())}
}

// legacyCIDR is a frozen copy of the on-wire shape that *cidr.CIDR produced
// (which embeds *net.IPNet, promoting these two fields in this order). We are
// intentionally not directly using pkg/cidr.CIDR: this wire contract must stay
// stable and independent of pkg/cidr. This will allow us to fully deprecate and
// remove pkg/cidr.CIDR as soon as it is no longer used, while this legacyCIDR will
// have to remain at least until the 1.23 release (see timeline on the #46924 issue)
type legacyCIDR struct {
	IP   net.IP
	Mask net.IPMask
}

// MarshalJSON emits the legacy net.IPNet object form for backward compatibility.
func (p Prefix) MarshalJSON() ([]byte, error) {
	if !p.IsValid() {
		return []byte("null"), nil // matches a nil *cidr.CIDR
	}
	masked := p.Masked()
	addr := masked.Addr()

	// TODO(1.22): replace the return statement below with:
	//     return json.Marshal(p.String())
	return json.Marshal(legacyCIDR{
		IP:   addr.AsSlice(),
		Mask: net.CIDRMask(masked.Bits(), addr.BitLen()),
	})
}

// UnmarshalJSON accepts both the legacy object form and the target string form,
// as well as JSON null (a previously-unset *cidr.CIDR).
func (p *Prefix) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*p = Prefix{}
		return nil
	}

	// Target string form: "10.244.1.0/24".
	if len(data) > 0 && data[0] == '"' {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		parsed, err := netip.ParsePrefix(s)
		if err != nil {
			return err
		}
		*p = PrefixFrom(parsed)
		return nil
	}

	// Legacy object form: {"IP":"...","Mask":"...."}.
	var legacy legacyCIDR
	if err := json.Unmarshal(data, &legacy); err != nil {
		return err
	}
	addr, ok := netip.AddrFromSlice(legacy.IP)
	if !ok {
		return fmt.Errorf("invalid IP in node CIDR: %v", legacy.IP)
	}
	ones, bits := legacy.Mask.Size()
	if bits == 0 { // canonical CIDR masks always report 32 or 128 bits
		return fmt.Errorf("non-canonical mask in node CIDR: %v", legacy.Mask)
	}
	parsed := netip.PrefixFrom(addr.Unmap(), ones)
	if !parsed.IsValid() {
		return fmt.Errorf("invalid node CIDR: %v/%d", legacy.IP, ones)
	}
	*p = PrefixFrom(parsed)
	return nil
}

// DeepCopyInto is a hand-written copy: netip.Addr's hidden zone pointer
// references interned, immutable data, so a value copy is safe. It is declared
// here (rather than inherited from ip.Prefix) so deepcopy-gen'd callers, which
// emit in.Field.DeepCopyInto(&out.Field), type-check against *Prefix.
func (p *Prefix) DeepCopyInto(out *Prefix) { *out = *p }

func (p *Prefix) DeepCopy() *Prefix {
	if p == nil {
		return nil
	}
	out := new(Prefix)
	p.DeepCopyInto(out)
	return out
}

func (p *Prefix) DeepEqual(other *Prefix) bool {
	if p == nil || other == nil {
		return p == other
	}
	return p.Prefix == other.Prefix
}
