package ndp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

const (
	// Length of an ICMPv6 header.
	icmpLen = 4

	// Minimum byte length values for each type of valid Message.
	naLen = 20
	nsLen = 20
	raLen = 12
	rsLen = 4
)

// A Message is a Neighbor Discovery Protocol message.
type Message interface {
	// Type specifies the ICMPv6 type for a Message.
	Type() ipv6.ICMPType

	// Called via MarshalMessage and ParseMessage.
	marshal() ([]byte, error)
	unmarshal(b []byte) error
}

func marshalMessage(m Message, psh []byte) ([]byte, error) {
	mb, err := m.marshal()
	if err != nil {
		return nil, err
	}

	im := icmp.Message{
		Type: m.Type(),
		// Always zero.
		Code: 0,
		// Calculated by caller or OS.
		Checksum: 0,
		Body: &icmp.RawBody{
			Data: mb,
		},
	}

	return im.Marshal(psh)
}

// MarshalMessage marshals a Message into its binary form and prepends an
// ICMPv6 message with the correct type.
//
// It is assumed that the operating system or caller will calculate and place
// the ICMPv6 checksum in the result.
func MarshalMessage(m Message) ([]byte, error) {
	// Pseudo-header always nil so checksum is calculated by caller or OS.
	return marshalMessage(m, nil)
}

// MarshalMessageChecksum marshals a Message into its binary form and prepends
// an ICMPv6 message with the correct type.
//
// The source and destination IP addresses are used to compute an IPv6 pseudo
// header for checksum calculation.
func MarshalMessageChecksum(m Message, source, destination net.IP) ([]byte, error) {
	return marshalMessage(m, icmp.IPv6PseudoHeader(source, destination))
}

// errParseMessage is a sentinel which indicates an error from ParseMessage.
var errParseMessage = errors.New("failed to parse message")

// ParseMessage parses a Message from its binary form after determining its
// type from a leading ICMPv6 message.
func ParseMessage(b []byte) (Message, error) {
	if len(b) < icmpLen {
		return nil, fmt.Errorf("ndp: ICMPv6 message too short: %w", errParseMessage)
	}

	// TODO(mdlayher): verify checksum?

	var m Message
	t := ipv6.ICMPType(b[0])
	switch t {
	case ipv6.ICMPTypeNeighborAdvertisement:
		m = new(NeighborAdvertisement)
	case ipv6.ICMPTypeNeighborSolicitation:
		m = new(NeighborSolicitation)
	case ipv6.ICMPTypeRouterAdvertisement:
		m = new(RouterAdvertisement)
	case ipv6.ICMPTypeRouterSolicitation:
		m = new(RouterSolicitation)
	default:
		return nil, fmt.Errorf("ndp: unrecognized ICMPv6 type %d: %w", t, errParseMessage)
	}

	if err := m.unmarshal(b[icmpLen:]); err != nil {
		return nil, fmt.Errorf("ndp: failed to unmarshal %s: %w", t, errParseMessage)
	}

	return m, nil
}

var _ Message = &NeighborAdvertisement{}

// A NeighborAdvertisement is a Neighbor Advertisement message as
// described in RFC 4861, Section 4.4.
type NeighborAdvertisement struct {
	Router        bool
	Solicited     bool
	Override      bool
	TargetAddress net.IP
	Options       []Option
}

// Type implements Message.
func (na *NeighborAdvertisement) Type() ipv6.ICMPType { return ipv6.ICMPTypeNeighborAdvertisement }

func (na *NeighborAdvertisement) marshal() ([]byte, error) {
	if err := checkIPv6(na.TargetAddress); err != nil {
		return nil, err
	}

	b := make([]byte, naLen)

	if na.Router {
		b[0] |= (1 << 7)
	}
	if na.Solicited {
		b[0] |= (1 << 6)
	}
	if na.Override {
		b[0] |= (1 << 5)
	}

	copy(b[4:], na.TargetAddress)

	ob, err := marshalOptions(na.Options)
	if err != nil {
		return nil, err
	}

	b = append(b, ob...)

	return b, nil
}

func (na *NeighborAdvertisement) unmarshal(b []byte) error {
	if len(b) < naLen {
		return io.ErrUnexpectedEOF
	}

	// Skip flags and reserved area.
	addr := b[4:naLen]
	if err := checkIPv6(addr); err != nil {
		return err
	}

	options, err := parseOptions(b[naLen:])
	if err != nil {
		return err
	}

	*na = NeighborAdvertisement{
		Router:    (b[0] & 0x80) != 0,
		Solicited: (b[0] & 0x40) != 0,
		Override:  (b[0] & 0x20) != 0,

		TargetAddress: make(net.IP, net.IPv6len),

		Options: options,
	}

	copy(na.TargetAddress, addr)

	return nil
}

var _ Message = &NeighborSolicitation{}

// A NeighborSolicitation is a Neighbor Solicitation message as
// described in RFC 4861, Section 4.3.
type NeighborSolicitation struct {
	TargetAddress net.IP
	Options       []Option
}

// Type implements Message.
func (ns *NeighborSolicitation) Type() ipv6.ICMPType { return ipv6.ICMPTypeNeighborSolicitation }

func (ns *NeighborSolicitation) marshal() ([]byte, error) {
	if err := checkIPv6(ns.TargetAddress); err != nil {
		return nil, err
	}

	b := make([]byte, nsLen)
	copy(b[4:], ns.TargetAddress)

	ob, err := marshalOptions(ns.Options)
	if err != nil {
		return nil, err
	}

	b = append(b, ob...)

	return b, nil
}

func (ns *NeighborSolicitation) unmarshal(b []byte) error {
	if len(b) < nsLen {
		return io.ErrUnexpectedEOF
	}

	// Skip reserved area.
	addr := b[4:nsLen]
	if err := checkIPv6(addr); err != nil {
		return err
	}

	options, err := parseOptions(b[nsLen:])
	if err != nil {
		return err
	}

	*ns = NeighborSolicitation{
		TargetAddress: make(net.IP, net.IPv6len),

		Options: options,
	}

	copy(ns.TargetAddress, addr)

	return nil
}

var _ Message = &RouterAdvertisement{}

// A RouterAdvertisement is a Router Advertisement message as
// described in RFC 4861, Section 4.1.
type RouterAdvertisement struct {
	CurrentHopLimit           uint8
	ManagedConfiguration      bool
	OtherConfiguration        bool
	MobileIPv6HomeAgent       bool
	RouterSelectionPreference Preference
	NeighborDiscoveryProxy    bool
	RouterLifetime            time.Duration
	ReachableTime             time.Duration
	RetransmitTimer           time.Duration
	Options                   []Option
}

// A Preference is a NDP router selection or route preference value as
// described in RFC 4191, Section 2.1.
type Preference int

// Possible Preference values.
const (
	Medium      Preference = 0
	High        Preference = 1
	prfReserved Preference = 2
	Low         Preference = 3
)

// Type implements Message.
func (ra *RouterAdvertisement) Type() ipv6.ICMPType { return ipv6.ICMPTypeRouterAdvertisement }

func (ra *RouterAdvertisement) marshal() ([]byte, error) {
	if err := checkPreference(ra.RouterSelectionPreference); err != nil {
		return nil, err
	}

	b := make([]byte, raLen)

	b[0] = ra.CurrentHopLimit

	if ra.ManagedConfiguration {
		b[1] |= (1 << 7)
	}
	if ra.OtherConfiguration {
		b[1] |= (1 << 6)
	}
	if ra.MobileIPv6HomeAgent {
		b[1] |= (1 << 5)
	}
	if prf := uint8(ra.RouterSelectionPreference); prf != 0 {
		b[1] |= (prf << 3)
	}
	if ra.NeighborDiscoveryProxy {
		b[1] |= (1 << 2)
	}

	lifetime := ra.RouterLifetime.Seconds()
	binary.BigEndian.PutUint16(b[2:4], uint16(lifetime))

	reach := ra.ReachableTime / time.Millisecond
	binary.BigEndian.PutUint32(b[4:8], uint32(reach))

	retrans := ra.RetransmitTimer / time.Millisecond
	binary.BigEndian.PutUint32(b[8:12], uint32(retrans))

	ob, err := marshalOptions(ra.Options)
	if err != nil {
		return nil, err
	}

	b = append(b, ob...)

	return b, nil
}

func (ra *RouterAdvertisement) unmarshal(b []byte) error {
	if len(b) < raLen {
		return io.ErrUnexpectedEOF
	}

	// Skip message body for options.
	options, err := parseOptions(b[raLen:])
	if err != nil {
		return err
	}

	var (
		mFlag = (b[1] & 0x80) != 0
		oFlag = (b[1] & 0x40) != 0
		hFlag = (b[1] & 0x20) != 0
		prf   = Preference((b[1] & 0x18) >> 3)
		pFlag = (b[1] & 0x04) != 0

		lifetime = time.Duration(binary.BigEndian.Uint16(b[2:4])) * time.Second
		reach    = time.Duration(binary.BigEndian.Uint32(b[4:8])) * time.Millisecond
		retrans  = time.Duration(binary.BigEndian.Uint32(b[8:12])) * time.Millisecond
	)

	// Per RFC 4191, Section 2.2:
	// "If the Reserved (10) value is received, the receiver MUST treat the
	// value as if it were (00)."
	if prf == prfReserved {
		prf = Medium
	}

	*ra = RouterAdvertisement{
		CurrentHopLimit:           b[0],
		ManagedConfiguration:      mFlag,
		OtherConfiguration:        oFlag,
		MobileIPv6HomeAgent:       hFlag,
		RouterSelectionPreference: prf,
		NeighborDiscoveryProxy:    pFlag,
		RouterLifetime:            lifetime,
		ReachableTime:             reach,
		RetransmitTimer:           retrans,
		Options:                   options,
	}

	return nil
}

var _ Message = &RouterSolicitation{}

// A RouterSolicitation is a Router Solicitation message as
// described in RFC 4861, Section 4.1.
type RouterSolicitation struct {
	Options []Option
}

// Type implements Message.
func (rs *RouterSolicitation) Type() ipv6.ICMPType { return ipv6.ICMPTypeRouterSolicitation }

func (rs *RouterSolicitation) marshal() ([]byte, error) {
	// b contains reserved area.
	b := make([]byte, rsLen)

	ob, err := marshalOptions(rs.Options)
	if err != nil {
		return nil, err
	}

	b = append(b, ob...)

	return b, nil
}

func (rs *RouterSolicitation) unmarshal(b []byte) error {
	if len(b) < rsLen {
		return io.ErrUnexpectedEOF
	}

	// Skip reserved area.
	options, err := parseOptions(b[rsLen:])
	if err != nil {
		return err
	}

	*rs = RouterSolicitation{
		Options: options,
	}

	return nil
}

// checkIPv6 verifies that ip is an IPv6 address.
func checkIPv6(ip net.IP) error {
	if ip.To16() == nil || ip.To4() != nil {
		return fmt.Errorf("ndp: invalid IPv6 address: %q", ip.String())
	}

	return nil
}

// checkPreference checks the validity of a Preference value.
func checkPreference(prf Preference) error {
	switch prf {
	case Low, Medium, High:
		return nil
	case prfReserved:
		return errors.New("ndp: cannot use reserved router selection preference value")
	default:
		return fmt.Errorf("ndp: unknown router selection preference value: %d", prf)
	}
}
