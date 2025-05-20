package ndp

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"time"
	"unicode"

	"golang.org/x/net/idna"
)

// Infinity indicates that a prefix is valid for an infinite amount of time,
// unless a new, finite, value is received in a subsequent router advertisement.
const Infinity = time.Duration(0xffffffff) * time.Second

const (
	// Length of a link-layer address for Ethernet networks.
	ethAddrLen = 6

	// The assumed NDP option length (in units of 8 bytes) for fixed length options.
	llaOptLen = 1
	piOptLen  = 4
	mtuOptLen = 1

	// Type values for each type of valid Option.
	optSourceLLA         = 1
	optTargetLLA         = 2
	optPrefixInformation = 3
	optMTU               = 5
	optNonce             = 14
	optRouteInformation  = 24
	optRDNSS             = 25
	optRAFlagsExtension  = 26
	optDNSSL             = 31
	optCaptivePortal     = 37
	optPREF64            = 38
)

// A Direction specifies the direction of a LinkLayerAddress Option as a source
// or target.
type Direction int

// Possible Direction values.
const (
	Source Direction = optSourceLLA
	Target Direction = optTargetLLA
)

// An Option is a Neighbor Discovery Protocol option.
type Option interface {
	// Code specifies the NDP option code for an Option.
	Code() uint8

	// "Code" as a method name isn't actually accurate because NDP options
	// also refer to that field as "Type", but we want to avoid confusion
	// with Message implementations which already use Type.

	// Called when dealing with a Message's Options.
	marshal() ([]byte, error)
	unmarshal(b []byte) error
}

var _ Option = &LinkLayerAddress{}

// A LinkLayerAddress is a Source or Target Link-Layer Address option, as
// described in RFC 4861, Section 4.6.1.
type LinkLayerAddress struct {
	Direction Direction
	Addr      net.HardwareAddr
}

// TODO(mdlayher): deal with non-ethernet links and variable option length?

// Code implements Option.
func (lla *LinkLayerAddress) Code() byte { return byte(lla.Direction) }

func (lla *LinkLayerAddress) marshal() ([]byte, error) {
	if d := lla.Direction; d != Source && d != Target {
		return nil, fmt.Errorf("ndp: invalid link-layer address direction: %d", d)
	}

	if len(lla.Addr) != ethAddrLen {
		return nil, fmt.Errorf("ndp: invalid link-layer address: %q", lla.Addr)
	}

	raw := &RawOption{
		Type:   lla.Code(),
		Length: llaOptLen,
		Value:  lla.Addr,
	}

	return raw.marshal()
}

func (lla *LinkLayerAddress) unmarshal(b []byte) error {
	raw := new(RawOption)
	if err := raw.unmarshal(b); err != nil {
		return err
	}

	d := Direction(raw.Type)
	if d != Source && d != Target {
		return fmt.Errorf("ndp: invalid link-layer address direction: %d", d)
	}

	if l := raw.Length; l != llaOptLen {
		return fmt.Errorf("ndp: unexpected link-layer address option length: %d", l)
	}

	*lla = LinkLayerAddress{
		Direction: d,
		Addr:      net.HardwareAddr(raw.Value),
	}

	return nil
}

var _ Option = new(MTU)

// An MTU is an MTU option, as described in RFC 4861, Section 4.6.1.
type MTU struct {
	MTU uint32
}

// NewMTU creates an MTU Option from an MTU value.
func NewMTU(mtu uint32) *MTU {
	return &MTU{MTU: mtu}
}

// Code implements Option.
func (*MTU) Code() byte { return optMTU }

func (m *MTU) marshal() ([]byte, error) {
	raw := &RawOption{
		Type:   m.Code(),
		Length: mtuOptLen,
		// 2 reserved bytes, 4 for MTU.
		Value: make([]byte, 6),
	}

	binary.BigEndian.PutUint32(raw.Value[2:6], uint32(m.MTU))

	return raw.marshal()
}

func (m *MTU) unmarshal(b []byte) error {
	raw := new(RawOption)
	if err := raw.unmarshal(b); err != nil {
		return err
	}

	*m = MTU{MTU: binary.BigEndian.Uint32(raw.Value[2:6])}

	return nil
}

var _ Option = &PrefixInformation{}

// A PrefixInformation is a a Prefix Information option, as described in RFC 4861, Section 4.6.1.
type PrefixInformation struct {
	PrefixLength                   uint8
	OnLink                         bool
	AutonomousAddressConfiguration bool
	ValidLifetime                  time.Duration
	PreferredLifetime              time.Duration
	Prefix                         netip.Addr
}

// Code implements Option.
func (*PrefixInformation) Code() byte { return optPrefixInformation }

func (pi *PrefixInformation) marshal() ([]byte, error) {
	// Per the RFC:
	// "The bits in the prefix after the prefix length are reserved and MUST
	// be initialized to zero by the sender and ignored by the receiver."
	//
	// Therefore, any prefix, when masked with its specified length, should be
	// identical to the prefix itself for it to be valid.
	p := netip.PrefixFrom(pi.Prefix, int(pi.PrefixLength))
	if masked := p.Masked(); pi.Prefix != masked.Addr() {
		return nil, fmt.Errorf("ndp: invalid prefix information: %s/%d",
			pi.Prefix, pi.PrefixLength)
	}

	raw := &RawOption{
		Type:   pi.Code(),
		Length: piOptLen,
		// 30 bytes for PrefixInformation body.
		Value: make([]byte, 30),
	}

	raw.Value[0] = pi.PrefixLength

	if pi.OnLink {
		raw.Value[1] |= (1 << 7)
	}
	if pi.AutonomousAddressConfiguration {
		raw.Value[1] |= (1 << 6)
	}

	valid := pi.ValidLifetime.Seconds()
	binary.BigEndian.PutUint32(raw.Value[2:6], uint32(valid))

	pref := pi.PreferredLifetime.Seconds()
	binary.BigEndian.PutUint32(raw.Value[6:10], uint32(pref))

	// 4 bytes reserved.

	copy(raw.Value[14:30], pi.Prefix.AsSlice())

	return raw.marshal()
}

func (pi *PrefixInformation) unmarshal(b []byte) error {
	raw := new(RawOption)
	if err := raw.unmarshal(b); err != nil {
		return err
	}

	// Guard against incorrect option length.
	if raw.Length != piOptLen {
		return io.ErrUnexpectedEOF
	}

	var (
		oFlag = (raw.Value[1] & 0x80) != 0
		aFlag = (raw.Value[1] & 0x40) != 0

		valid     = time.Duration(binary.BigEndian.Uint32(raw.Value[2:6])) * time.Second
		preferred = time.Duration(binary.BigEndian.Uint32(raw.Value[6:10])) * time.Second
	)

	// Skip to address.
	addr := raw.Value[14:30]
	ip, ok := netip.AddrFromSlice(addr)
	if !ok {
		panicf("ndp: invalid IPv6 address slice: %v", addr)
	}
	if err := checkIPv6(ip); err != nil {
		return err
	}

	// Per the RFC, bits in prefix past prefix length are ignored by the
	// receiver.
	pl := raw.Value[0]
	p := netip.PrefixFrom(ip, int(pl)).Masked()

	*pi = PrefixInformation{
		PrefixLength:                   pl,
		OnLink:                         oFlag,
		AutonomousAddressConfiguration: aFlag,
		ValidLifetime:                  valid,
		PreferredLifetime:              preferred,
		Prefix:                         p.Addr(),
	}

	return nil
}

var _ Option = &RouteInformation{}

// A RouteInformation is a Route Information option, as described in RFC 4191,
// Section 2.3.
type RouteInformation struct {
	PrefixLength  uint8
	Preference    Preference
	RouteLifetime time.Duration
	Prefix        netip.Addr
}

// Code implements Option.
func (*RouteInformation) Code() byte { return optRouteInformation }

func (ri *RouteInformation) marshal() ([]byte, error) {
	// Per the RFC:
	// "The bits in the prefix after the prefix length are reserved and MUST
	// be initialized to zero by the sender and ignored by the receiver."
	//
	// Therefore, any prefix, when masked with its specified length, should be
	// identical to the prefix itself for it to be valid.
	err := fmt.Errorf("ndp: invalid route information: %s/%d", ri.Prefix, ri.PrefixLength)
	p := netip.PrefixFrom(ri.Prefix, int(ri.PrefixLength))
	if masked := p.Masked(); ri.Prefix != masked.Addr() {
		return nil, err
	}

	// Depending on the length of the prefix, we can add fewer bytes to the
	// option.
	var iplen int
	switch {
	case ri.PrefixLength == 0:
		iplen = 0
	case ri.PrefixLength > 0 && ri.PrefixLength < 65:
		iplen = 1
	case ri.PrefixLength > 64 && ri.PrefixLength < 129:
		iplen = 2
	default:
		// Invalid IPv6 prefix.
		return nil, err
	}

	raw := &RawOption{
		Type:   ri.Code(),
		Length: uint8(iplen) + 1,
		// Prefix length, preference, lifetime, and prefix body as computed by
		// using iplen.
		Value: make([]byte, 1+1+4+(iplen*8)),
	}

	raw.Value[0] = ri.PrefixLength

	// Adjacent bits are reserved.
	if prf := uint8(ri.Preference); prf != 0 {
		raw.Value[1] |= (prf << 3)
	}

	lt := ri.RouteLifetime.Seconds()
	binary.BigEndian.PutUint32(raw.Value[2:6], uint32(lt))

	copy(raw.Value[6:], ri.Prefix.AsSlice())

	return raw.marshal()
}

func (ri *RouteInformation) unmarshal(b []byte) error {
	raw := new(RawOption)
	if err := raw.unmarshal(b); err != nil {
		return err
	}

	// Verify the option's length against prefix length using the rules defined
	// in the RFC.
	l := raw.Value[0]
	rerr := fmt.Errorf("ndp: invalid route information for /%d prefix", l)

	switch {
	case l == 0:
		if raw.Length < 1 || raw.Length > 3 {
			return rerr
		}
	case l > 0 && l < 65:
		// Some devices will use length 3 anyway for a route that fits in /64.
		if raw.Length != 2 && raw.Length != 3 {
			return rerr
		}
	case l > 64 && l < 129:
		if raw.Length != 3 {
			return rerr
		}
	default:
		// Invalid IPv6 prefix.
		return rerr
	}

	// Unpack preference (with adjacent reserved bits) and lifetime values.
	var (
		pref = Preference((raw.Value[1] & 0x18) >> 3)
		lt   = time.Duration(binary.BigEndian.Uint32(raw.Value[2:6])) * time.Second
	)

	if err := checkPreference(pref); err != nil {
		return err
	}

	// Take up to the specified number of IP bytes into the prefix.
	var (
		addr [16]byte
		buf  = raw.Value[6 : 6+(l/8)]
	)

	copy(addr[:], buf)

	*ri = RouteInformation{
		PrefixLength:  l,
		Preference:    pref,
		RouteLifetime: lt,
		Prefix:        netip.AddrFrom16(addr),
	}

	return nil
}

// A RecursiveDNSServer is a Recursive DNS Server option, as described in
// RFC 8106, Section 5.1.
type RecursiveDNSServer struct {
	Lifetime time.Duration
	Servers  []netip.Addr
}

// Code implements Option.
func (*RecursiveDNSServer) Code() byte { return optRDNSS }

// Offsets for the RDNSS option.
const (
	rdnssLifetimeOff = 2
	rdnssServersOff  = 6
)

var (
	errRDNSSNoServers = errors.New("ndp: recursive DNS server option requires at least one server")
	errRDNSSBadServer = errors.New("ndp: recursive DNS server option has malformed IPv6 address")
)

func (r *RecursiveDNSServer) marshal() ([]byte, error) {
	slen := len(r.Servers)
	if slen == 0 {
		return nil, errRDNSSNoServers
	}

	raw := &RawOption{
		Type: r.Code(),
		// Always have one length unit to start, and then each IPv6 address
		// occupies two length units.
		Length: 1 + uint8((slen * 2)),
		// Allocate enough space for all data.
		Value: make([]byte, rdnssServersOff+(slen*net.IPv6len)),
	}

	binary.BigEndian.PutUint32(
		raw.Value[rdnssLifetimeOff:rdnssServersOff],
		uint32(r.Lifetime.Seconds()),
	)

	for i := 0; i < len(r.Servers); i++ {
		// Determine the start and end byte offsets for each address,
		// effectively iterating 16 bytes at a time to insert an address.
		var (
			start = rdnssServersOff + (i * net.IPv6len)
			end   = rdnssServersOff + net.IPv6len + (i * net.IPv6len)
		)

		copy(raw.Value[start:end], r.Servers[i].AsSlice())
	}

	return raw.marshal()
}

func (r *RecursiveDNSServer) unmarshal(b []byte) error {
	raw := new(RawOption)
	if err := raw.unmarshal(b); err != nil {
		return err
	}

	// Skip 2 reserved bytes to get lifetime.
	lt := time.Duration(binary.BigEndian.Uint32(
		raw.Value[rdnssLifetimeOff:rdnssServersOff])) * time.Second

	// Determine the number of DNS servers specified using the method described
	// in the RFC.  Remember, length is specified in units of 8 octets.
	//
	// "That is, the number of addresses is equal to (Length - 1) / 2."
	//
	// Make sure at least one server is present, and that the IPv6 addresses are
	// the expected 16 byte length.
	dividend := (int(raw.Length) - 1)
	if dividend%2 != 0 {
		return errRDNSSBadServer
	}

	count := dividend / 2
	if count == 0 {
		return errRDNSSNoServers
	}

	servers := make([]netip.Addr, 0, count)
	for i := 0; i < count; i++ {
		// Determine the start and end byte offsets for each address,
		// effectively iterating 16 bytes at a time to fetch an address.
		var (
			start = rdnssServersOff + (i * net.IPv6len)
			end   = rdnssServersOff + net.IPv6len + (i * net.IPv6len)
		)

		s, ok := netip.AddrFromSlice(raw.Value[start:end])
		if !ok {
			return errRDNSSBadServer
		}

		servers = append(servers, s)
	}

	*r = RecursiveDNSServer{
		Lifetime: lt,
		Servers:  servers,
	}

	return nil
}

// A DNSSearchList is a DNS search list option, as described in
// RFC 8106, Section 5.2.
type DNSSearchList struct {
	Lifetime    time.Duration
	DomainNames []string
}

// Code implements Option.
func (*DNSSearchList) Code() byte { return optDNSSL }

// Offsets for the RDNSS option.
const (
	dnsslLifetimeOff = 2
	dnsslDomainsOff  = 6
)

var (
	errDNSSLBadDomains = errors.New("ndp: DNS search list option has malformed domain names")
	errDNSSLNoDomains  = errors.New("ndp: DNS search list option requires at least one domain name")
)

func (d *DNSSearchList) marshal() ([]byte, error) {
	if len(d.DomainNames) == 0 {
		return nil, errDNSSLNoDomains
	}

	// Make enough room for reserved bytes and lifetime.
	value := make([]byte, dnsslDomainsOff)

	binary.BigEndian.PutUint32(
		value[dnsslLifetimeOff:dnsslDomainsOff],
		uint32(d.Lifetime.Seconds()),
	)

	// Attach each label component of a domain name with a one byte length prefix
	// and a null terminator between full domain names, using the algorithm from:
	// https://tools.ietf.org/html/rfc1035#section-3.1.
	for _, dn := range d.DomainNames {
		// All unicode names must be converted to punycode.
		dn, err := idna.ToASCII(dn)
		if err != nil {
			return nil, errDNSSLBadDomains
		}

		for _, label := range strings.Split(dn, ".") {
			// Label must be convertable to valid Punycode.
			if !isASCII(label) {
				return nil, errDNSSLBadDomains
			}

			value = append(value, byte(len(label)))
			value = append(value, label...)
		}

		value = append(value, 0)
	}

	// Pad null bytes into value, so that when combined with type and length,
	// the entire buffer length is divisible by 8 bytes for proper NDP option
	// length.
	if r := (len(value) + 2) % 8; r != 0 {
		value = append(value, bytes.Repeat([]byte{0x00}, 8-r)...)
	}

	raw := &RawOption{
		Type: d.Code(),
		// Always have one length unit to start, and then calculate the length
		// needed for value.
		Length: uint8((len(value) + 2) / 8),
		Value:  value,
	}

	return raw.marshal()
}

func (d *DNSSearchList) unmarshal(b []byte) error {
	raw := new(RawOption)
	if err := raw.unmarshal(b); err != nil {
		return err
	}

	// Skip 2 reserved bytes to get lifetime.
	lt := time.Duration(binary.BigEndian.Uint32(
		raw.Value[dnsslLifetimeOff:dnsslDomainsOff])) * time.Second

	// This block implements the domain name space parsing algorithm from:
	// https://tools.ietf.org/html/rfc1035#section-3.1.
	//
	// A domain is comprised of a sequence of labels, which are accumulated and
	// then separated by periods later on.
	var domains []string
	var labels []string
	for i := dnsslDomainsOff; ; {
		if len(raw.Value[i:]) < 2 {
			return errDNSSLBadDomains
		}

		// Parse the length of the upcoming label.
		length := int(raw.Value[i])
		if length >= len(raw.Value[i:])-1 {
			// Length out of range.
			return errDNSSLBadDomains
		}
		if length == 0 {
			// No more labels.
			break
		}
		i++

		// Parse the label string and ensure it is ASCII, and that it doesn't
		// contain invalid characters.
		label := string(raw.Value[i : i+length])
		if !isASCII(label) {
			return errDNSSLBadDomains
		}

		// TODO(mdlayher): much smarter validation.
		if label == "" || strings.Contains(label, ".") || strings.Contains(label, " ") {
			return errDNSSLBadDomains
		}

		// Verify that the Punycode label decodes to something sane.
		label, err := idna.ToUnicode(label)
		if err != nil {
			return errDNSSLBadDomains
		}

		// TODO(mdlayher): much smarter validation.
		if label == "" || hasUnicodeReplacement(label) || strings.Contains(label, ".") || strings.Contains(label, " ") {
			return errDNSSLBadDomains
		}

		labels = append(labels, label)
		i += length

		// If we've reached a null byte, join labels into a domain name and
		// empty the label stack for reuse.
		if raw.Value[i] == 0 {
			i++

			domain, err := idna.ToUnicode(strings.Join(labels, "."))
			if err != nil {
				return errDNSSLBadDomains
			}

			domains = append(domains, domain)
			labels = []string{}

			// Have we reached the end of the value slice?
			if len(raw.Value[i:]) == 0 || (len(raw.Value[i:]) == 1 && raw.Value[i] == 0) {
				// No more non-padding bytes, no more labels.
				break
			}
		}
	}

	// Must have found at least one domain.
	if len(domains) == 0 {
		return errDNSSLNoDomains
	}

	*d = DNSSearchList{
		Lifetime:    lt,
		DomainNames: domains,
	}

	return nil
}

// Unrestricted is the IANA-assigned URI for a network with no captive portal
// restrictions, as specified in RFC 8910, Section 2.
const Unrestricted = "urn:ietf:params:capport:unrestricted"

// A CaptivePortal is a Captive-Portal option, as described in RFC 8910, Section
// 2.3.
type CaptivePortal struct {
	URI string
}

// NewCaptivePortal produces a CaptivePortal Option for the input URI string. As
// a special case, if uri is empty, Unrestricted is used as the CaptivePortal
// OptionURI.
//
// If uri is an IP address literal, an error is returned. Per RFC 8910, uri
// "SHOULD NOT" be an IP address, but there are circumstances where this
// behavior may be useful. In that case, the caller can bypass NewCaptivePortal
// and construct a CaptivePortal Option directly.
func NewCaptivePortal(uri string) (*CaptivePortal, error) {
	if uri == "" {
		return &CaptivePortal{URI: Unrestricted}, nil
	}

	// Try to comply with the max limit for DHCPv4.
	if len(uri) > 255 {
		return nil, errors.New("ndp: captive portal option URI is too long")
	}

	// TODO(mdlayher): a URN is almost a URL, but investigate compliance with
	// https://datatracker.ietf.org/doc/html/rfc8141. In particular there are
	// some tricky rules around case-sensitivity.
	urn, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}

	// "The URI SHOULD NOT contain an IP address literal."
	//
	// Since this is a constructor and there's nothing stopping the user from
	// manually creating this string if they so choose, we'll return an error
	// IP addresses. This includes bare IP addresses or IP addresses with some
	// kind of path appended.
	for _, s := range strings.Split(urn.Path, "/") {
		if ip, err := netip.ParseAddr(s); err == nil {
			return nil, fmt.Errorf("ndp: captive portal option URIs should not contain IP addresses: %s", ip)
		}
	}

	return &CaptivePortal{URI: urn.String()}, nil
}

// Code implements Option.
func (*CaptivePortal) Code() byte { return optCaptivePortal }

func (cp *CaptivePortal) marshal() ([]byte, error) {
	if len(cp.URI) == 0 {
		return nil, errors.New("ndp: captive portal option requires a non-empty URI")
	}

	// Pad up to next unit of 8 bytes including 2 bytes for code, length, and
	// bytes for the URI string. Extra bytes will be null.
	l := len(cp.URI)
	if r := (l + 2) % 8; r != 0 {
		l += 8 - r
	}

	value := make([]byte, l)
	copy(value, []byte(cp.URI))

	raw := &RawOption{
		Type:   cp.Code(),
		Length: (uint8(l) + 2) / 8,
		Value:  value,
	}

	return raw.marshal()
}

func (cp *CaptivePortal) unmarshal(b []byte) error {
	raw := new(RawOption)
	if err := raw.unmarshal(b); err != nil {
		return err
	}

	// Don't allow a null URI.
	if len(raw.Value) == 0 || raw.Value[0] == 0x00 {
		return errors.New("ndp: captive portal URI is null")
	}

	// Find any trailing null bytes and trim them away before setting the URI.
	i := bytes.Index(raw.Value, []byte{0x00})
	if i == -1 {
		i = len(raw.Value)
	}

	// Our constructor does validation of URIs, but we treat the URI as opaque
	// for parsing, since we likely have to interop with other implementations.
	*cp = CaptivePortal{URI: string(raw.Value[:i])}

	return nil
}

// PREF64 is a PREF64 option, as described in RFC 8781, Section 4. The prefix
// must have a prefix length of 96, 64, 56, 40, or 32. The lifetime is used to
// indicate to clients how long the PREF64 prefix is valid for. A lifetime of 0
// indicates the prefix is no longer valid. If unsure, refer to RFC 8781
// Section 4.1 for how to calculate an appropriate lifetime.
type PREF64 struct {
	Lifetime time.Duration
	Prefix   netip.Prefix
}

func (p *PREF64) Code() byte { return optPREF64 }

func (p *PREF64) marshal() ([]byte, error) {
	var plc uint8
	switch p.Prefix.Bits() {
	case 96:
		plc = 0
	case 64:
		plc = 1
	case 56:
		plc = 2
	case 48:
		plc = 3
	case 40:
		plc = 4
	case 32:
		plc = 5
	default:
		return nil, errors.New("ndp: invalid pref64 prefix size")
	}

	scaledLifetime := uint16(math.Round(p.Lifetime.Seconds() / 8))

	// The scaled lifetime must be less than the maximum of 8191.
	if scaledLifetime > 8191 {
		return nil, errors.New("ndp: pref64 scaled lifetime is too large")
	}

	value := []byte{}

	// The scaled lifetime and PLC values live within the same 16-bit field.
	// Here we move the scaled lifetime to the left-most 13 bits and place the
	// PLC at the last 3 bits of the 16-bit field.
	value = binary.BigEndian.AppendUint16(
		value,
		(scaledLifetime<<3&(0xffff^0b111))|uint16(plc&0b111),
	)

	allPrefixBits := p.Prefix.Masked().Addr().As16()
	optionPrefixBits := allPrefixBits[:96/8]
	value = append(value, optionPrefixBits...)

	raw := &RawOption{
		Type:   p.Code(),
		Length: (uint8(len(value)) + 2) / 8,
		Value:  value,
	}

	return raw.marshal()
}

func (p *PREF64) unmarshal(b []byte) error {
	raw := new(RawOption)
	if err := raw.unmarshal(b); err != nil {
		return err
	}

	if raw.Type != optPREF64 {
		return errors.New("ndp: invalid pref64 type")
	}

	if len(raw.Value) != (96/8)+2 {
		return errors.New("ndp: invalid pref64 message length")
	}

	lifetimeAndPlc := binary.BigEndian.Uint16(raw.Value[:2])
	plc := uint8(lifetimeAndPlc & 0b111)

	var prefixSize int
	switch plc {
	case 0:
		prefixSize = 96
	case 1:
		prefixSize = 64
	case 2:
		prefixSize = 56
	case 3:
		prefixSize = 48
	case 4:
		prefixSize = 40
	case 5:
		prefixSize = 32
	default:
		return errors.New("ndp: invalid pref64 prefix length code")
	}

	addr := [16]byte{}
	copy(addr[:], raw.Value[2:])
	prefix, err := netip.AddrFrom16(addr).Prefix(int(prefixSize))
	if err != nil {
		return err
	}

	scaledLifetime := (lifetimeAndPlc & (0xffff ^ 0b111)) >> 3
	lifetime := time.Duration(scaledLifetime) * 8 * time.Second

	*p = PREF64{
		Lifetime: lifetime,
		Prefix:   prefix,
	}

	return nil
}

// A RAFlagsExtension is a Router Advertisement Flags Extension (or Expansion)
// option, as described in RFC 5175, Section 4.
type RAFlagsExtension struct {
	Flags RAFlags
}

// RAFlags is a bitmask of Router Advertisement flags contained within an
// RAFlagsExtension.
type RAFlags []byte

// Code implements Option.
func (*RAFlagsExtension) Code() byte { return optRAFlagsExtension }

func (ra *RAFlagsExtension) marshal() ([]byte, error) {
	// "MUST NOT be added to a Router Advertisement message if no flags in the
	// option are set."
	//
	// TODO(mdlayher): replace with slices.IndexFunc when we raise the minimum
	// Go version.
	var found bool
	for _, b := range ra.Flags {
		if b != 0x00 {
			found = true
			break
		}
	}
	if !found {
		return nil, errors.New("ndp: RA flags extension requires one or more flags to be set")
	}

	// Enforce the option size matches the next unit of 8 bytes including 2
	// bytes for code and length.
	l := len(ra.Flags)
	if r := (l + 2) % 8; r != 0 {
		return nil, errors.New("ndp: RA flags extension length is invalid")
	}

	value := make([]byte, l)
	copy(value, ra.Flags)

	raw := &RawOption{
		Type:   ra.Code(),
		Length: (uint8(l) + 2) / 8,
		Value:  value,
	}

	return raw.marshal()
}

func (ra *RAFlagsExtension) unmarshal(b []byte) error {
	raw := new(RawOption)
	if err := raw.unmarshal(b); err != nil {
		return err
	}

	// Don't allow short bytes.
	if len(raw.Value) < 6 {
		return errors.New("ndp: RA Flags Extension too short")
	}

	// raw already made a copy.
	ra.Flags = raw.Value
	return nil
}

// A Nonce is a Nonce option, as described in RFC 3971, Section 5.3.2.
type Nonce struct {
	b []byte
}

// NewNonce creates a Nonce option with an opaque random value.
func NewNonce() *Nonce {
	// Minimum is 6 bytes, and this is also the only value that the Linux kernel
	// recognizes as of kernel 5.17.
	const n = 6
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panicf("ndp: failed to generate nonce bytes: %v", err)
	}

	return &Nonce{b: b}
}

// Equal reports whether n and x are the same nonce.
func (n *Nonce) Equal(x *Nonce) bool { return subtle.ConstantTimeCompare(n.b, x.b) == 1 }

// Code implements Option.
func (*Nonce) Code() byte { return optNonce }

// String returns the string representation of a Nonce.
func (n *Nonce) String() string { return hex.EncodeToString(n.b) }

func (n *Nonce) marshal() ([]byte, error) {
	if len(n.b) == 0 {
		return nil, errors.New("ndp: nonce option requires a non-empty nonce value")
	}

	// Enforce the nonce size matches the next unit of 8 bytes including 2 bytes
	// for code and length.
	l := len(n.b)
	if r := (l + 2) % 8; r != 0 {
		return nil, errors.New("ndp: nonce size is invalid")
	}

	value := make([]byte, l)
	copy(value, n.b)

	raw := &RawOption{
		Type:   n.Code(),
		Length: (uint8(l) + 2) / 8,
		Value:  value,
	}

	return raw.marshal()
}

func (n *Nonce) unmarshal(b []byte) error {
	raw := new(RawOption)
	if err := raw.unmarshal(b); err != nil {
		return err
	}

	// raw already made a copy.
	n.b = raw.Value
	return nil
}

var _ Option = &RawOption{}

// A RawOption is an Option in its raw and unprocessed format.  Options which
// are not recognized by this package can be represented using a RawOption.
type RawOption struct {
	Type   uint8
	Length uint8
	Value  []byte
}

// Code implements Option.
func (r *RawOption) Code() byte { return r.Type }

func (r *RawOption) marshal() ([]byte, error) {
	// Length specified in units of 8 bytes, and the caller must provide
	// an accurate length.
	l := int(r.Length * 8)
	if 1+1+len(r.Value) != l {
		return nil, io.ErrUnexpectedEOF
	}

	b := make([]byte, r.Length*8)
	b[0] = r.Type
	b[1] = r.Length

	copy(b[2:], r.Value)

	return b, nil
}

func (r *RawOption) unmarshal(b []byte) error {
	if len(b) < 2 {
		return io.ErrUnexpectedEOF
	}

	r.Type = b[0]
	r.Length = b[1]
	// Exclude type and length fields from value's length.
	l := int(r.Length*8) - 2

	// Enforce a valid length value that matches the expected one.
	if lb := len(b[2:]); l != lb {
		return fmt.Errorf("ndp: option value byte length should be %d, but length is %d", l, lb)
	}

	r.Value = make([]byte, l)
	copy(r.Value, b[2:])

	return nil
}

// marshalOptions marshals a slice of Options into a single byte slice.
func marshalOptions(options []Option) ([]byte, error) {
	var b []byte
	for _, o := range options {
		ob, err := o.marshal()
		if err != nil {
			return nil, err
		}

		b = append(b, ob...)
	}

	return b, nil
}

// parseOptions parses a slice of Options from a byte slice.
func parseOptions(b []byte) ([]Option, error) {
	var options []Option
	for i := 0; len(b[i:]) != 0; {
		// Two bytes: option type and option length.
		if len(b[i:]) < 2 {
			return nil, io.ErrUnexpectedEOF
		}

		// Type processed as-is, but length is stored in units of 8 bytes,
		// so expand it to the actual byte length.
		t := b[i]
		l := int(b[i+1]) * 8

		// Verify that we won't advance beyond the end of the byte slice.
		if l > len(b[i:]) {
			return nil, io.ErrUnexpectedEOF
		}

		// Infer the option from its type value and use it for unmarshaling.
		var o Option
		switch t {
		case optSourceLLA, optTargetLLA:
			o = new(LinkLayerAddress)
		case optMTU:
			o = new(MTU)
		case optPrefixInformation:
			o = new(PrefixInformation)
		case optRouteInformation:
			o = new(RouteInformation)
		case optRDNSS:
			o = new(RecursiveDNSServer)
		case optRAFlagsExtension:
			o = new(RAFlagsExtension)
		case optDNSSL:
			o = new(DNSSearchList)
		case optCaptivePortal:
			o = new(CaptivePortal)
		case optPREF64:
			o = new(PREF64)
		case optNonce:
			o = new(Nonce)
		default:
			o = new(RawOption)
		}

		// Unmarshal at the current offset, up to the expected length.
		if err := o.unmarshal(b[i : i+l]); err != nil {
			return nil, err
		}

		// Advance to the next option's type field.
		i += l

		options = append(options, o)
	}

	return options, nil
}

// isASCII verifies that the contents of s are all ASCII characters.
func isASCII(s string) bool {
	for _, c := range s {
		if c > unicode.MaxASCII {
			return false
		}
	}
	return true
}

// hasUnicodeReplacement checks for the Unicode replacment character in s.
func hasUnicodeReplacement(s string) bool {
	for _, c := range s {
		if c == unicode.ReplacementChar {
			return true
		}
	}

	return false
}
