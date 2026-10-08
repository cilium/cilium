// EtherNet/IP (ENIP) protocol support for gopacket.
// EtherNet/IP is an industrial Ethernet protocol that encapsulates CIP
// (Common Industrial Protocol) over TCP/IP.
// See: https://www.odva.org/technology-standards/key-technologies/ethernet-ip/

package layers

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/gopacket/gopacket"
)

const (
	enipMinPacketLen           int = 24
	enipMinRegSessionPacketLen int = 4
	enipMinSendRRDataPacketLen int = 36

	// TCPPortENIP is the TCP port used to transport EtherNet/IP packets
	TCPPortENIP uint16 = 44818
	// UDPPortENIP is the UDP port used to transport EtherNet/IP packets
	UDPPortENIP uint16 = 2222
)

var (
	// ErrENIPDataTooSmall is returned if an EtherNet/IP packet is truncated
	ErrENIPDataTooSmall = errors.New("ENIP packet data truncated")
	// ErrENIPUnknownDataFormat is returned if an unknown data format ID is encountered
	ErrENIPUnknownDataFormat = errors.New("ENIP unknown data format ID")
)

// ENIPCommand is an EtherNet/IP command code
type ENIPCommand uint16

// ENIP Command constants
const (
	ENIPCommandNOP               ENIPCommand = 0x0000
	ENIPCommandListServices      ENIPCommand = 0x0004
	ENIPCommandListIdentity      ENIPCommand = 0x0063
	ENIPCommandListInterfaces    ENIPCommand = 0x0064
	ENIPCommandRegisterSession   ENIPCommand = 0x0065
	ENIPCommandUnregisterSession ENIPCommand = 0x0066
	ENIPCommandSendRRData        ENIPCommand = 0x006F
	ENIPCommandSendUnitData      ENIPCommand = 0x0070
	ENIPCommandIndicateStatus    ENIPCommand = 0x0072
	ENIPCommandCancel            ENIPCommand = 0x0073
)

// String returns a human-readable string representation of the ENIP command
func (ec ENIPCommand) String() string {
	switch ec {
	case ENIPCommandNOP:
		return "NOP"
	case ENIPCommandListServices:
		return "ListServices"
	case ENIPCommandListIdentity:
		return "ListIdentity"
	case ENIPCommandListInterfaces:
		return "ListInterfaces"
	case ENIPCommandRegisterSession:
		return "RegisterSession"
	case ENIPCommandUnregisterSession:
		return "UnregisterSession"
	case ENIPCommandSendRRData:
		return "SendRRData"
	case ENIPCommandSendUnitData:
		return "SendUnitData"
	case ENIPCommandIndicateStatus:
		return "IndicateStatus"
	case ENIPCommandCancel:
		return "Cancel"
	default:
		return fmt.Sprintf("Unknown(0x%04X)", uint16(ec))
	}
}

// ENIPStatus represents an EtherNet/IP status code
type ENIPStatus uint32

// ENIP Status constants
const (
	ENIPStatusSuccess              ENIPStatus = 0x0000
	ENIPStatusInvalidCommand       ENIPStatus = 0x0001
	ENIPStatusInsufficientMemory   ENIPStatus = 0x0002
	ENIPStatusIncorrectData        ENIPStatus = 0x0003
	ENIPStatusInvalidSessionHandle ENIPStatus = 0x0064
	ENIPStatusInvalidLength        ENIPStatus = 0x0065
	ENIPStatusUnsupportedProtocol  ENIPStatus = 0x0069
)

// String returns a human-readable string representation of the ENIP status
func (es ENIPStatus) String() string {
	switch es {
	case ENIPStatusSuccess:
		return "Success"
	case ENIPStatusInvalidCommand:
		return "Invalid Command"
	case ENIPStatusInsufficientMemory:
		return "Insufficient Memory"
	case ENIPStatusIncorrectData:
		return "Incorrect Data"
	case ENIPStatusInvalidSessionHandle:
		return "Invalid Session Handle"
	case ENIPStatusInvalidLength:
		return "Invalid Length"
	case ENIPStatusUnsupportedProtocol:
		return "Unsupported Protocol"
	default:
		return fmt.Sprintf("Unknown(0x%08X)", uint32(es))
	}
}

// ENIP implements decoding of EtherNet/IP, a protocol used to transport the
// Common Industrial Protocol over standard OSI networks. EtherNet/IP transports
// over both TCP and UDP.
// See the EtherNet/IP Developer's Guide for more information: https://www.odva.org/Portals/0/Library/Publications_Numbered/PUB00213R0_EtherNetIP_Developers_Guide.pdf
type ENIP struct {
	BaseLayer
	Command         ENIPCommand
	Length          uint16
	SessionHandle   uint32
	Status          uint32
	SenderContext   []byte
	Options         uint32
	CommandSpecific ENIPCommandSpecificData
}

// ENIPCommandSpecificData contains data specific to a command. This may
// include another EtherNet/IP packet embedded within the Data structure.
type ENIPCommandSpecificData struct {
	Cmd  ENIPCommand
	Data []byte
}

func init() {
	RegisterTCPPortLayerType(TCPPort(TCPPortENIP), LayerTypeENIP)
	RegisterUDPPortLayerType(UDPPort(UDPPortENIP), LayerTypeENIP)
}

// DecodeFromBytes parses the contents of `data` as an EtherNet/IP packet.
func (enip *ENIP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < enipMinPacketLen {
		df.SetTruncated()
		return ErrENIPDataTooSmall
	}
	enip.Command = ENIPCommand(binary.LittleEndian.Uint16(data[0:2]))
	enip.Length = binary.LittleEndian.Uint16(data[2:4])
	enip.SessionHandle = binary.LittleEndian.Uint32(data[4:8])
	enip.Status = binary.LittleEndian.Uint32(data[8:12])
	enip.SenderContext = data[12:20]
	enip.Options = binary.LittleEndian.Uint32(data[20:24])
	return enip.getPayload(data, df)
}

func (enip *ENIP) getPayload(data []byte, df gopacket.DecodeFeedback) (err error) {
	enip.CommandSpecific.Cmd = enip.Command
	switch enip.Command {
	case ENIPCommandRegisterSession: // Register session command
		if len(data) < 28 { // 24 byte header + 4 byte protocol version/options
			df.SetTruncated()
			err = ErrENIPDataTooSmall
			return
		}
		enip.CommandSpecific.Data = data[24:28]
		enip.Contents = data[0:28]
		enip.Payload = data[28:]
	case ENIPCommandSendUnitData, ENIPCommandSendRRData:
		if len(data) < enipMinSendRRDataPacketLen {
			df.SetTruncated()
			return ErrENIPDataTooSmall
		}
		// Grab the item count
		itemCount := int(binary.LittleEndian.Uint16(data[30:32]))
		csdEnd := 32
		for i := 0; i < itemCount; i++ {
			if csdEnd+4 > len(data) {
				df.SetTruncated()
				return ErrENIPDataTooSmall
			}
			dataFormatID := binary.LittleEndian.Uint16(data[csdEnd:])
			itemLen, err := getDataFormatIDLen(dataFormatID, data[csdEnd+2:])
			if err != nil {
				return err
			}
			csdEnd += itemLen
		}
		if len(data) < csdEnd {
			df.SetTruncated()
			return ErrENIPDataTooSmall
		}
		enip.CommandSpecific.Data = data[24:csdEnd]
		enip.Contents = data[0:csdEnd]
		enip.Payload = data[csdEnd:]
	default:
		enip.CommandSpecific.Data = data[24:]
		enip.Contents = data
		enip.Payload = []byte{}
	}
	return
}

func getDataFormatIDLen(id uint16, data []byte) (int, error) {
	switch id {
	case 0x0000:
		return 4, nil // ID (2 bytes) + length field (2 bytes)
	case 0x000C:
		return 8, nil // Sockaddr info
	case 0x00A1:
		if len(data) < 2 {
			return 0, ErrENIPDataTooSmall
		}
		length := int(binary.LittleEndian.Uint16(data))
		totalLen := 4 + length
		// Ensure the claimed item length fits in the remaining buffer (data includes the 2-byte length field)
		if totalLen < 0 || length < 0 || 2+length > len(data) {
			return 0, ErrENIPDataTooSmall
		}
		return totalLen, nil // Connected data item
	case 0x00B1:
		return 6, nil // Connected address item
	case 0x00B2:
		return 4, nil // Sequenced address item
	case 0x0100:
		return 4, nil // List services response
	case 0x8000:
		return 4, nil // CIP identity
	case 0x8001:
		return 2, nil // CIP security
	case 0x8002:
		return 2, nil // EtherNet/IP capability
	default:
		return 0, ErrENIPUnknownDataFormat
	}
}

// LayerType returns LayerTypeENIP
func (enip *ENIP) LayerType() gopacket.LayerType { return LayerTypeENIP }

// CanDecode returns LayerTypeENIP
func (enip *ENIP) CanDecode() gopacket.LayerClass { return LayerTypeENIP }

// NextLayerType returns either LayerTypePayload or the next layer type
// derived from the command specific data
func (enip *ENIP) NextLayerType() (nl gopacket.LayerType) {
	switch enip.Command {
	case ENIPCommandSendRRData:
		fallthrough
	case ENIPCommandSendUnitData:
		nl = enip.CommandSpecific.NextLayer()
	case ENIPCommandRegisterSession:
		fallthrough
	default:
		nl = gopacket.LayerTypePayload
	}
	return
}

func decodeENIP(data []byte, p gopacket.PacketBuilder) error {
	if len(data) < enipMinPacketLen {
		p.SetTruncated()
		return ErrENIPDataTooSmall
	}
	enip := &ENIP{}
	return decodingLayerDecoder(enip, data, p)
}

// NextLayer derives the next layer type by checking for a CIP marker
// at the start of the command specific data, returning LayerTypeCIP
// if found; if not present, the next layer type is LayerTypePayload
func (csd ENIPCommandSpecificData) NextLayer() (nl gopacket.LayerType) {
	if len(csd.Data) < 4 {
		nl = gopacket.LayerTypePayload
		return
	}
	switch binary.LittleEndian.Uint32(csd.Data) {
	case 0x0:
		nl = LayerTypeCIP
	default:
		nl = gopacket.LayerTypePayload
	}
	return
}
