package netutil

import (
	"fmt"
)

// AddrFamily is the type for IANA address family numbers.
type AddrFamily uint16

// An incomplete list of IANA address family numbers.
//
// See https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml.
const (
	AddrFamilyNone AddrFamily = 0
	AddrFamilyIPv4 AddrFamily = 1
	AddrFamilyIPv6 AddrFamily = 2
)

// type check
var _ fmt.Stringer = AddrFamilyNone

// String implements the [fmt.Stringer] interface for AddrFamily.
func (f AddrFamily) String() (s string) {
	switch f {
	case AddrFamilyNone:
		return "none"
	case AddrFamilyIPv4:
		return "ipv4"
	case AddrFamilyIPv6:
		return "ipv6"
	default:
		return fmt.Sprintf("!bad_addr_fam_%d", f)
	}
}

// Constants to avoid a dependency on github.com/miekg/dns.
//
// See https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4.
const (
	dnsTypeA    uint16 = 1
	dnsTypeAAAA uint16 = 28
)

// AddrFamilyFromRRType returns an AddrFamily appropriate for the DNS resource
// record type rr.  That is, [AddrFamilyIPv4] for DNS type A (1),
// [AddrFamilyIPv6] for DNS type AAAA (28), and [AddrFamilyNone] otherwise.
func AddrFamilyFromRRType(rr uint16) (fam AddrFamily) {
	switch rr {
	case dnsTypeA:
		return AddrFamilyIPv4
	case dnsTypeAAAA:
		return AddrFamilyIPv6
	default:
		return AddrFamilyNone
	}
}
