package ndp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
	"unicode"

	"gitlab.com/golang-commonmark/puny"
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
	optRouteInformation  = 24
	optRDNSS             = 25
	optDNSSL             = 31
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
		return nil, fmt.Errorf("ndp: invalid link-layer address: %q", lla.Addr.String())
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

// TODO(mdlayher): decide if this should just be a struct type instead.

// An MTU is an MTU option, as described in RFC 4861, Section 4.6.1.
type MTU uint32

// NewMTU creates an MTU Option from an MTU value.
func NewMTU(mtu uint32) *MTU {
	m := MTU(mtu)
	return &m
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

	binary.BigEndian.PutUint32(raw.Value[2:6], uint32(*m))

	return raw.marshal()
}

func (m *MTU) unmarshal(b []byte) error {
	raw := new(RawOption)
	if err := raw.unmarshal(b); err != nil {
		return err
	}

	*m = MTU(binary.BigEndian.Uint32(raw.Value[2:6]))

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
	Prefix                         net.IP
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
	mask := net.CIDRMask(int(pi.PrefixLength), 128)
	if masked := pi.Prefix.Mask(mask); !pi.Prefix.Equal(masked) {
		return nil, fmt.Errorf("ndp: invalid prefix information: %s/%d", pi.Prefix.String(), pi.PrefixLength)
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

	copy(raw.Value[14:30], pi.Prefix)

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

	// Skip reserved area.
	addr := net.IP(raw.Value[14:30])
	if err := checkIPv6(addr); err != nil {
		return err
	}

	// Per the RFC, bits in prefix past prefix length are ignored by the
	// receiver.
	l := raw.Value[0]
	mask := net.CIDRMask(int(l), 128)
	addr = addr.Mask(mask)

	*pi = PrefixInformation{
		PrefixLength:                   l,
		OnLink:                         oFlag,
		AutonomousAddressConfiguration: aFlag,
		ValidLifetime:                  valid,
		PreferredLifetime:              preferred,
		// raw.Value is already a copy of b, so just point to the address.
		Prefix: addr,
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
	Prefix        net.IP
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
	err := fmt.Errorf("ndp: invalid route information: %s/%d", ri.Prefix.String(), ri.PrefixLength)
	mask := net.CIDRMask(int(ri.PrefixLength), 128)
	if masked := ri.Prefix.Mask(mask); !ri.Prefix.Equal(masked) {
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

	copy(raw.Value[6:], ri.Prefix)

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
	err := fmt.Errorf("ndp: invalid route information for /%d prefix", l)

	switch {
	case l == 0:
		if raw.Length < 1 || raw.Length > 3 {
			return err
		}
	case l > 0 && l < 65:
		// Some devices will use length 3 anyway for a route that fits in /64.
		if raw.Length != 2 && raw.Length != 3 {
			return err
		}
	case l > 64 && l < 129:
		if raw.Length != 3 {
			return err
		}
	default:
		// Invalid IPv6 prefix.
		return err
	}

	// Unpack preference (with adjacent reserved bits) and lifetime values.
	var (
		pref = Preference((raw.Value[1] & 0x18) >> 3)
		lt   = time.Duration(binary.BigEndian.Uint32(raw.Value[2:6])) * time.Second
	)

	if err := checkPreference(pref); err != nil {
		return err
	}

	*ri = RouteInformation{
		PrefixLength:  l,
		Preference:    pref,
		RouteLifetime: lt,
		Prefix:        make(net.IP, net.IPv6len),
	}

	// Copy up to the specified number of IP bytes into the prefix.
	copy(ri.Prefix, raw.Value[6:6+(l/8)])

	return nil
}

// A RecursiveDNSServer is a Recursive DNS Server option, as described in
// RFC 8106, Section 5.1.
type RecursiveDNSServer struct {
	Lifetime time.Duration
	Servers  []net.IP
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

		copy(raw.Value[start:end], r.Servers[i])
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

	servers := make([]net.IP, 0, count)
	for i := 0; i < count; i++ {
		// Determine the start and end byte offsets for each address,
		// effectively iterating 16 bytes at a time to fetch an address.
		var (
			start = rdnssServersOff + (i * net.IPv6len)
			end   = rdnssServersOff + net.IPv6len + (i * net.IPv6len)
		)

		// The RawOption already made a copy of this data, so convert it
		// directly to an IPv6 address with no further copying needed.
		servers = append(servers, net.IP(raw.Value[start:end]))
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
		for _, label := range strings.Split(puny.ToASCII(dn), ".") {
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
		label = puny.ToUnicode(label)

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

			domains = append(domains, puny.ToUnicode(strings.Join(labels, ".")))
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
		case optDNSSL:
			o = new(DNSSearchList)
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
