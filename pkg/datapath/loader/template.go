// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"fmt"
	"math"
	"net/netip"

	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/mac"
)

const (
	templateSecurityID          = identity.ReservedIdentityWorld
	templateLxcID               = uint16(65535)
	templatePolicyVerdictFilter = uint32(0xffff)
	templateIfIndex             = math.MaxUint32
	templateEndpointNetNsCookie = math.MaxUint64
)

var (
	templateIPv4 = [4]byte{192, 0, 2, 3}
	templateIPv6 = [16]byte{0x20, 0x01, 0xdb, 0x8, 0x0b, 0xad, 0xca, 0xfe, 0x60, 0x0d, 0xbe, 0xe2, 0x0b, 0xad, 0xca, 0xfe}

	templateMAC = mac.MAC([]byte{0x02, 0x00, 0x60, 0x0D, 0xF0, 0x0D})
)

// templateCfg wraps a real configuration from an endpoint to pass through its
// configuration of conditional branches in the datapath, but to mock out dummy
// values for static data.
//
// Note that the static data dummy values must be non-zero in every 32-bit
// section of the data to ensure that during compilation, the compiler reserves
// space in the .data section of the ELF for the value of the data, rather than
// generating a reference to the .bss section (which is what it will typically
// do if a static integer is initialized to zero).
//
// Ideally we also statically configure the values used in the template in such
// a way that if ever someone managed to inadvertently attach the template
// program directly to a device, that there are no unintended consequences such
// as allowing traffic to leak out with routable addresses.
type templateCfg struct {
	// CompileTimeConfiguration passes through directly to the underlying
	// endpoint configuration, while the rest of the EndpointConfiguration
	// interface is implemented directly here through receiver functions.
	datapath.CompileTimeConfiguration
}

// GetID returns a uint64, but in practice on the datapath side it is
// guaranteed to be 16-bit; it is used to generate map names, so we need to
// ensure that the template generates map names that are as long as the longest
// possible name, which would be guaranteed with a 5-digit output.
//
// In practice, attempts to load an endpoint with the ID 65535 will fail which
// means that the calling code must approprately substitute the ID in the ELF
// prior to load, or it will fail with a relatively obvious error.
func (t *templateCfg) GetID() uint64 {
	return uint64(templateLxcID)
}

// StringID returns the string form of the ID returned by GetID().
func (t *templateCfg) StringID() string {
	return fmt.Sprintf("%d", t.GetID())
}

// GetIdentity treats the template program as part of the world, so if there's
// ever some weird bug that causes the template value here to be used, it will
// be in the least privileged security context.
func (t *templateCfg) GetIdentity() identity.NumericIdentity {
	return templateSecurityID
}

// GetEndpointNetNsCookie returns a invalid (zero) network namespace cookie.
func (t *templateCfg) GetEndpointNetNsCookie() uint64 {
	return templateEndpointNetNsCookie
}

// GetNodeMAC returns a well-known dummy MAC address which may be later
// substituted in the ELF.
func (t *templateCfg) GetNodeMAC() mac.MAC {
	return templateMAC
}

func (t *templateCfg) GetIfIndex() int {
	return templateIfIndex
}

// IPv4Address always returns an IP in the documentation prefix (RFC5737) as
// a nonsense address that should typically not be routable.
func (t *templateCfg) IPv4Address() netip.Addr {
	return netip.AddrFrom4(templateIPv4)
}

// IPv6Address returns an IP in the documentation prefix (RFC3849) to ensure
// that each 32-bit segment of the address is non-zero as per the requirements
// described in the structure definition. This can't be guaranteed while using
// a more appropriate prefix such as the discard prefix (RFC6666).
func (t *templateCfg) IPv6Address() netip.Addr {
	return netip.AddrFrom16(templateIPv6)
}

// GetPolicyVerdictLogFilter returns an uint32 filter to ensure
// that the filter is non-zero as per the requirements
// described in the structure definition.
func (t *templateCfg) GetPolicyVerdictLogFilter() uint32 {
	return templatePolicyVerdictFilter
}

func (*templateCfg) GetFibTableID() uint32 {
	return 0
}

func (*templateCfg) GetPropertyValue(key string) any {
	return nil
}

func (*templateCfg) RequireARPPassthrough() bool {
	return false
}

// wrap takes an endpoint configuration and optional stats tracker and wraps
// it inside a templateCfg which hides static data from callers that wish to
// generate header files based on the configuration, substituting it for
// template data.
func wrap(cfg datapath.CompileTimeConfiguration) *templateCfg {
	return &templateCfg{
		CompileTimeConfiguration: cfg,
	}
}
