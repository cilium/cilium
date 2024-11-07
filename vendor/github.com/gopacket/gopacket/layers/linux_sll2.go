// Copyright 2022 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"

	"github.com/gopacket/gopacket"
)

// The ARPHardwareType contains a Linux ARPHRD_ value for the link-layer device type
type ARPHardwareType uint16

const (
	ARPHardwareTypeEthernet      ARPHardwareType = 1
	ARPHardwareTypeFRAD          ARPHardwareType = 770
	ARPHardwareTypeLoopback      ARPHardwareType = 772
	ARPHardwareTypeIPGRE         ARPHardwareType = 778
	ARPHardwareTypeDot11Radiotap ARPHardwareType = 803
)

func (l ARPHardwareType) String() string {
	switch l {
	case ARPHardwareTypeEthernet:
		return "Ethernet"
	case ARPHardwareTypeFRAD:
		return "Frame Relay Access Device"
	case ARPHardwareTypeLoopback:
		return "Loopback device"
	case ARPHardwareTypeIPGRE:
		return "GRE over IP"
	case ARPHardwareTypeDot11Radiotap:
		return "IEEE 802.11 + radiotap header"
	}

	return fmt.Sprintf("Unknown(%d)", int(l))
}

// The LinuxSLL2PacketType can contain the same values as LinuxSLLPacketType accept it is a uint8 instread of a uint16
type LinuxSLL2PacketType uint8

const (
	LinuxSLL2PacketTypeHost      LinuxSLL2PacketType = 0 // To us
	LinuxSLL2PacketTypeBroadcast LinuxSLL2PacketType = 1 // To all
	LinuxSLL2PacketTypeMulticast LinuxSLL2PacketType = 2 // To group
	LinuxSLL2PacketTypeOtherhost LinuxSLL2PacketType = 3 // To someone else
	LinuxSLL2PacketTypeOutgoing  LinuxSLL2PacketType = 4 // Outgoing of any type
	// These ones are invisible by user level
	LinuxSLL2PacketTypeLoopback  LinuxSLL2PacketType = 5 // MC/BRD frame looped back
	LinuxSLL2PacketTypeFastroute LinuxSLL2PacketType = 6 // Fastrouted frame
)

func (l LinuxSLL2PacketType) String() string {
	switch l {
	case LinuxSLL2PacketTypeHost:
		return "host"
	case LinuxSLL2PacketTypeBroadcast:
		return "broadcast"
	case LinuxSLL2PacketTypeMulticast:
		return "multicast"
	case LinuxSLL2PacketTypeOtherhost:
		return "otherhost"
	case LinuxSLL2PacketTypeOutgoing:
		return "outgoing"
	case LinuxSLL2PacketTypeLoopback:
		return "loopback"
	case LinuxSLL2PacketTypeFastroute:
		return "fastroute"
	}
	return fmt.Sprintf("Unknown(%d)", int(l))
}

const (
	LinuxSLL2EthernetTypeDot3    EthernetType = 0x0001
	LinuxSLL2EthernetTypeUnknown EthernetType = 0x0003
	LinuxSLL2EthernetTypeLLC     EthernetType = 0x0004
	LinuxSLL2EthernetTypeCAN     EthernetType = 0x000C
)

// LinuxSLL2 is the second version of the Linux "cooked" capture encapsulation protocol. It is used to encapsulate
// packets within packet capture files, particularly by libpcap/tcpdump when making a packet capture with -i any
// https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL2.html
type LinuxSLL2 struct {
	BaseLayer
	ProtocolType    EthernetType
	InterfaceIndex  uint32
	ARPHardwareType ARPHardwareType
	PacketType      LinuxSLL2PacketType
	AddrLength      uint8
	Addr            net.HardwareAddr
}

// LayerType returns LayerTypeLinuxSLL.
func (sll *LinuxSLL2) LayerType() gopacket.LayerType { return LayerTypeLinuxSLL2 }

func (sll *LinuxSLL2) CanDecode() gopacket.LayerClass {
	return LayerTypeLinuxSLL2
}

func (sll *LinuxSLL2) LinkFlow() gopacket.Flow {
	return gopacket.NewFlow(EndpointMAC, sll.Addr, nil)
}

func (sll *LinuxSLL2) NextLayerType() gopacket.LayerType {
	switch sll.ARPHardwareType {
	case ARPHardwareTypeFRAD:
		// If the ARPHRD_ type is ARPHRD_FRAD (770), the protocol type field is ignored,
		// and the payload following the LINKTYPE_LINUX_SLL header is a Frame Relay LAPF frame,
		// beginning with a ITU-T Recommendation Q.922 LAPF header starting with the address field,
		// and without an FCS at the end of the frame.
		return gopacket.LayerTypeZero // LAPF layer not yet implemented

	case ARPHardwareTypeDot11Radiotap:
		return LayerTypeRadioTap

	case ARPHardwareTypeIPGRE:
		// Docs: If the ARPHRD_ type is ARPHRD_IPGRE (778), the protocol type field contains a GRE protocol type.
		//
		// It doesn't clearly state if if the next header should be GRE or Ethernet in this case. Will assume ethernet
		// for now
		return LayerTypeEthernet

	default:
		switch sll.ProtocolType {
		case LinuxSLL2EthernetTypeDot3:
			// Docs: if the frame is a Novell 802.3 frame without an 802.2 LLC header
			return gopacket.LayerTypeZero // Novell 802.3 frame layer not yet implemented

		case LinuxSLL2EthernetTypeUnknown:
			// Docs: in some mysterious cases;
			return gopacket.LayerTypeZero // Mysterious cases not implemented

		case LinuxSLL2EthernetTypeLLC:
			return LayerTypeLLC

		case LinuxSLL2EthernetTypeCAN:
			// Docs: if the frame is a CAN bus frame that begins with a header of the form
			return gopacket.LayerTypeZero
		}

		return sll.ProtocolType.LayerType()
	}
}

func (sll *LinuxSLL2) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < 20 {
		return errors.New("Linux SLL2 packet too small")
	}
	sll.ProtocolType = EthernetType(binary.BigEndian.Uint16(data[0:2]))
	sll.InterfaceIndex = binary.BigEndian.Uint32(data[4:8])
	sll.ARPHardwareType = ARPHardwareType(binary.BigEndian.Uint16(data[8:10]))
	sll.PacketType = LinuxSLL2PacketType(data[10])
	sll.AddrLength = data[11]
	sll.Addr = data[12:20]
	sll.Addr = sll.Addr[:sll.AddrLength]
	sll.BaseLayer = BaseLayer{data[:20], data[20:]}

	return nil
}

func decodeLinuxSLL2(data []byte, p gopacket.PacketBuilder) error {
	sll := &LinuxSLL2{}
	if err := sll.DecodeFromBytes(data, p); err != nil {
		return err
	}
	p.AddLayer(sll)
	p.SetLinkLayer(sll)
	return p.NextDecoder(sll.NextLayerType())
}
