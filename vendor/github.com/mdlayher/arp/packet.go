package arp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"

	"github.com/mdlayher/ethernet"
)

var (
	// ErrInvalidHardwareAddr is returned when one or more invalid hardware
	// addresses are passed to NewPacket.
	ErrInvalidHardwareAddr = errors.New("invalid hardware address")

	// ErrInvalidIP is returned when one or more invalid IPv4 addresses are
	// passed to NewPacket.
	ErrInvalidIP = errors.New("invalid IPv4 address")

	// errInvalidARPPacket is returned when an ethernet frame does not
	// indicate that an ARP packet is contained in its payload.
	errInvalidARPPacket = errors.New("invalid ARP packet")
)

//go:generate stringer -output=string.go -type=Operation

// An Operation is an ARP operation, such as request or reply.
type Operation uint16

// Operation constants which indicate an ARP request or reply.
const (
	OperationRequest Operation = 1
	OperationReply   Operation = 2
)

// A Packet is a raw ARP packet, as described in RFC 826.
type Packet struct {
	// HardwareType specifies an IANA-assigned hardware type, as described
	// in RFC 826.
	HardwareType uint16

	// ProtocolType specifies the internetwork protocol for which the ARP
	// request is intended.  Typically, this is the IPv4 EtherType.
	ProtocolType uint16

	// HardwareAddrLength specifies the length of the sender and target
	// hardware addresses included in a Packet.
	HardwareAddrLength uint8

	// IPLength specifies the length of the sender and target IPv4 addresses
	// included in a Packet.
	IPLength uint8

	// Operation specifies the ARP operation being performed, such as request
	// or reply.
	Operation Operation

	// SenderHardwareAddr specifies the hardware address of the sender of this
	// Packet.
	SenderHardwareAddr net.HardwareAddr

	// SenderIP specifies the IPv4 address of the sender of this Packet.
	SenderIP netip.Addr

	// TargetHardwareAddr specifies the hardware address of the target of this
	// Packet.
	TargetHardwareAddr net.HardwareAddr

	// TargetIP specifies the IPv4 address of the target of this Packet.
	TargetIP netip.Addr
}

// NewPacket creates a new Packet from an input Operation and hardware/IPv4
// address values for both a sender and target.
//
// If either hardware address is less than 6 bytes in length, or there is a
// length mismatch between the two, ErrInvalidHardwareAddr is returned.
//
// If either IP address is not an IPv4 address, or there is a length mismatch
// between the two, ErrInvalidIP is returned.
func NewPacket(op Operation, srcHW net.HardwareAddr, srcIP netip.Addr, dstHW net.HardwareAddr, dstIP netip.Addr) (*Packet, error) {
	// Validate hardware addresses for minimum length, and matching length
	if len(srcHW) < 6 {
		return nil, ErrInvalidHardwareAddr
	}
	if len(dstHW) < 6 {
		return nil, ErrInvalidHardwareAddr
	}
	if !bytes.Equal(ethernet.Broadcast, dstHW) && len(srcHW) != len(dstHW) {
		return nil, ErrInvalidHardwareAddr
	}

	// Validate IP addresses to ensure they are IPv4 addresses, and
	// correct length
	var invalidIP netip.Addr
	if !srcIP.IsValid() || !srcIP.Is4() {
		return nil, ErrInvalidIP
	}
	if !dstIP.Is4() || dstIP == invalidIP {
		return nil, ErrInvalidIP
	}

	return &Packet{
		// There is no Go-native way to detect hardware type of a network
		// interface, so default to 1 (ethernet 10Mb) for now
		HardwareType: 1,

		// Default to EtherType for IPv4
		ProtocolType: uint16(ethernet.EtherTypeIPv4),

		// Populate other fields using input data
		HardwareAddrLength: uint8(len(srcHW)),
		IPLength:           uint8(4),
		Operation:          op,
		SenderHardwareAddr: srcHW,
		SenderIP:           srcIP,
		TargetHardwareAddr: dstHW,
		TargetIP:           dstIP,
	}, nil
}

// MarshalBinary allocates a byte slice containing the data from a Packet.
//
// MarshalBinary never returns an error.
func (p *Packet) MarshalBinary() ([]byte, error) {
	// 2 bytes: hardware type
	// 2 bytes: protocol type
	// 1 byte : hardware address length
	// 1 byte : protocol length
	// 2 bytes: operation
	// N bytes: source hardware address
	// N bytes: source protocol address
	// N bytes: target hardware address
	// N bytes: target protocol address

	// Though an IPv4 address should always 4 bytes, go-fuzz
	// very quickly created several crasher scenarios which
	// indicated that these values can lie.
	b := make([]byte, 2+2+1+1+2+(p.IPLength*2)+(p.HardwareAddrLength*2))

	// Marshal fixed length data

	binary.BigEndian.PutUint16(b[0:2], p.HardwareType)
	binary.BigEndian.PutUint16(b[2:4], p.ProtocolType)

	b[4] = p.HardwareAddrLength
	b[5] = p.IPLength

	binary.BigEndian.PutUint16(b[6:8], uint16(p.Operation))

	// Marshal variable length data at correct offset using lengths
	// defined in p

	n := 8
	hal := int(p.HardwareAddrLength)
	pl := int(p.IPLength)

	copy(b[n:n+hal], p.SenderHardwareAddr)
	n += hal

	sender4 := p.SenderIP.As4()
	copy(b[n:n+pl], sender4[:])
	n += pl

	copy(b[n:n+hal], p.TargetHardwareAddr)
	n += hal

	target4 := p.TargetIP.As4()
	copy(b[n:n+pl], target4[:])

	return b, nil
}

// UnmarshalBinary unmarshals a raw byte slice into a Packet.
func (p *Packet) UnmarshalBinary(b []byte) error {
	// Must have enough room to retrieve hardware address and IP lengths
	if len(b) < 8 {
		return io.ErrUnexpectedEOF
	}

	// Retrieve fixed length data

	p.HardwareType = binary.BigEndian.Uint16(b[0:2])
	p.ProtocolType = binary.BigEndian.Uint16(b[2:4])

	p.HardwareAddrLength = b[4]
	p.IPLength = b[5]

	p.Operation = Operation(binary.BigEndian.Uint16(b[6:8]))

	// Unmarshal variable length data at correct offset using lengths
	// defined by ml and il
	//
	// These variables are meant to improve readability of offset calculations
	// for the code below
	n := 8
	ml := int(p.HardwareAddrLength)
	ml2 := ml * 2
	il := int(p.IPLength)
	il2 := il * 2

	// Must have enough room to retrieve both hardware address and IP addresses
	addrl := n + ml2 + il2
	if len(b) < addrl {
		return io.ErrUnexpectedEOF
	}

	// Allocate single byte slice to store address information, which
	// is resliced into fields
	bb := make([]byte, addrl-n)

	// Sender hardware address
	copy(bb[0:ml], b[n:n+ml])
	p.SenderHardwareAddr = bb[0:ml]
	n += ml

	// Sender IP address
	copy(bb[ml:ml+il], b[n:n+il])
	senderIP, ok := netip.AddrFromSlice(bb[ml : ml+il])
	if !ok {
		return errors.New("Invalid Sender IP address")
	}
	p.SenderIP = senderIP
	n += il

	// Target hardware address
	copy(bb[ml+il:ml2+il], b[n:n+ml])
	p.TargetHardwareAddr = bb[ml+il : ml2+il]
	n += ml

	// Target IP address
	copy(bb[ml2+il:ml2+il2], b[n:n+il])
	targetIP, ok := netip.AddrFromSlice(bb[ml2+il : ml2+il2])
	if !ok {
		return errors.New("Invalid Target IP address")
	}
	p.TargetIP = targetIP

	return nil
}

func parsePacket(buf []byte) (*Packet, *ethernet.Frame, error) {
	f := new(ethernet.Frame)
	if err := f.UnmarshalBinary(buf); err != nil {
		return nil, nil, err
	}

	// Ignore frames which do not have ARP EtherType
	if f.EtherType != ethernet.EtherTypeARP {
		return nil, nil, errInvalidARPPacket
	}

	p := new(Packet)
	if err := p.UnmarshalBinary(f.Payload); err != nil {
		return nil, nil, err
	}
	return p, f, nil
}
