// Modbus protocol support for gopacket.
// This implements Modbus TCP (port 502) decoding according to the
// Modbus Application Protocol Specification V1.1b3.
// See: https://modbus.org/docs/Modbus_Application_Protocol_V1_1b3.pdf

package layers

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/gopacket/gopacket"
)

const (
	MBAPHeaderLen      int    = 7
	MinModbusPacketLen int    = MBAPHeaderLen + 1
	ModbusPort         uint16 = 502
)

var (
	ErrModbusDataTooSmall    = errors.New("data too small for Modbus")
	ErrModbusInvalidProtocol = errors.New("invalid Modbus protocol ID (expected 0)")
)

// ModbusFunctionCode represents a Modbus function code
type ModbusFunctionCode byte

// Modbus Function Code constants
const (
	ModbusFuncCodeReadCoils              ModbusFunctionCode = 0x01
	ModbusFuncCodeReadDiscreteInputs     ModbusFunctionCode = 0x02
	ModbusFuncCodeReadHoldingRegisters   ModbusFunctionCode = 0x03
	ModbusFuncCodeReadInputRegisters     ModbusFunctionCode = 0x04
	ModbusFuncCodeWriteSingleCoil        ModbusFunctionCode = 0x05
	ModbusFuncCodeWriteSingleRegister    ModbusFunctionCode = 0x06
	ModbusFuncCodeReadExceptionStatus    ModbusFunctionCode = 0x07
	ModbusFuncCodeDiagnostics            ModbusFunctionCode = 0x08
	ModbusFuncCodeGetCommEventCounter    ModbusFunctionCode = 0x0B
	ModbusFuncCodeGetCommEventLog        ModbusFunctionCode = 0x0C
	ModbusFuncCodeWriteMultipleCoils     ModbusFunctionCode = 0x0F
	ModbusFuncCodeWriteMultipleRegisters ModbusFunctionCode = 0x10
	ModbusFuncCodeReportSlaveID          ModbusFunctionCode = 0x11
	ModbusFuncCodeReadFileRecord         ModbusFunctionCode = 0x14
	ModbusFuncCodeWriteFileRecord        ModbusFunctionCode = 0x15
	ModbusFuncCodeMaskWriteRegister      ModbusFunctionCode = 0x16
	ModbusFuncCodeReadWriteMultipleRegs  ModbusFunctionCode = 0x17
	ModbusFuncCodeReadFIFOQueue          ModbusFunctionCode = 0x18
	ModbusFuncCodeEncapsulatedInterface  ModbusFunctionCode = 0x2B
	// Exception mask (OR'd with function code for exception responses)
	ModbusFuncCodeExceptionMask ModbusFunctionCode = 0x80
)

// String returns a human-readable string representation of the function code
func (fc ModbusFunctionCode) String() string {
	isException := (fc & ModbusFuncCodeExceptionMask) != 0
	code := fc & ^ModbusFuncCodeExceptionMask

	var name string
	switch code {
	case ModbusFuncCodeReadCoils:
		name = "Read Coils"
	case ModbusFuncCodeReadDiscreteInputs:
		name = "Read Discrete Inputs"
	case ModbusFuncCodeReadHoldingRegisters:
		name = "Read Holding Registers"
	case ModbusFuncCodeReadInputRegisters:
		name = "Read Input Registers"
	case ModbusFuncCodeWriteSingleCoil:
		name = "Write Single Coil"
	case ModbusFuncCodeWriteSingleRegister:
		name = "Write Single Register"
	case ModbusFuncCodeReadExceptionStatus:
		name = "Read Exception Status"
	case ModbusFuncCodeDiagnostics:
		name = "Diagnostics"
	case ModbusFuncCodeGetCommEventCounter:
		name = "Get Comm Event Counter"
	case ModbusFuncCodeGetCommEventLog:
		name = "Get Comm Event Log"
	case ModbusFuncCodeWriteMultipleCoils:
		name = "Write Multiple Coils"
	case ModbusFuncCodeWriteMultipleRegisters:
		name = "Write Multiple Registers"
	case ModbusFuncCodeReportSlaveID:
		name = "Report Slave ID"
	case ModbusFuncCodeReadFileRecord:
		name = "Read File Record"
	case ModbusFuncCodeWriteFileRecord:
		name = "Write File Record"
	case ModbusFuncCodeMaskWriteRegister:
		name = "Mask Write Register"
	case ModbusFuncCodeReadWriteMultipleRegs:
		name = "Read/Write Multiple Registers"
	case ModbusFuncCodeReadFIFOQueue:
		name = "Read FIFO Queue"
	case ModbusFuncCodeEncapsulatedInterface:
		name = "Encapsulated Interface Transport"
	default:
		name = fmt.Sprintf("Unknown(0x%02X)", byte(code))
	}

	if isException {
		return "Exception: " + name
	}
	return name
}

// ModbusExceptionCode represents a Modbus exception code
type ModbusExceptionCode byte

// Modbus Exception Code constants
const (
	ModbusExceptionIllegalFunction                    ModbusExceptionCode = 0x01
	ModbusExceptionIllegalDataAddress                 ModbusExceptionCode = 0x02
	ModbusExceptionIllegalDataValue                   ModbusExceptionCode = 0x03
	ModbusExceptionSlaveDeviceFailure                 ModbusExceptionCode = 0x04
	ModbusExceptionAcknowledge                        ModbusExceptionCode = 0x05
	ModbusExceptionSlaveDeviceBusy                    ModbusExceptionCode = 0x06
	ModbusExceptionMemoryParityError                  ModbusExceptionCode = 0x08
	ModbusExceptionGatewayPathUnavailable             ModbusExceptionCode = 0x0A
	ModbusExceptionGatewayTargetDeviceFailedToRespond ModbusExceptionCode = 0x0B
)

// String returns a human-readable string representation of the exception code
func (ec ModbusExceptionCode) String() string {
	switch ec {
	case ModbusExceptionIllegalFunction:
		return "Illegal Function"
	case ModbusExceptionIllegalDataAddress:
		return "Illegal Data Address"
	case ModbusExceptionIllegalDataValue:
		return "Illegal Data Value"
	case ModbusExceptionSlaveDeviceFailure:
		return "Slave Device Failure"
	case ModbusExceptionAcknowledge:
		return "Acknowledge"
	case ModbusExceptionSlaveDeviceBusy:
		return "Slave Device Busy"
	case ModbusExceptionMemoryParityError:
		return "Memory Parity Error"
	case ModbusExceptionGatewayPathUnavailable:
		return "Gateway Path Unavailable"
	case ModbusExceptionGatewayTargetDeviceFailedToRespond:
		return "Gateway Target Device Failed to Respond"
	default:
		return fmt.Sprintf("Unknown(0x%02X)", byte(ec))
	}
}

// MBAP represents the Modbus Application Protocol header
type MBAP struct {
	TransactionID uint16 // Transaction identifier
	ProtocolID    uint16 // Protocol identifier (0 for Modbus)
	Length        uint16 // Length of remaining data
	UnitID        uint8  // Unit identifier
}

// Modbus represents a Modbus TCP packet
type Modbus struct {
	BaseLayer
	MBAP
	FunctionCode uint8  // Raw Modbus function code byte (includes exception bit 0x80 if present)
	Exception    bool   // True if this is an exception response
	ReqResp      []byte // Request/Response data
}

func init() {
	RegisterTCPPortLayerType(TCPPort(ModbusPort), LayerTypeModbus)
}

func (m *Modbus) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	if len(data) < MinModbusPacketLen {
		df.SetTruncated()
		return ErrModbusDataTooSmall
	}
	m.TransactionID = binary.BigEndian.Uint16(data[0:2])
	m.ProtocolID = binary.BigEndian.Uint16(data[2:4])
	m.Length = binary.BigEndian.Uint16(data[4:6])
	m.UnitID = data[6]
	m.FunctionCode = data[7]
	m.Exception = (m.FunctionCode & 0x80) != 0
	end := int(m.Length) + 6
	if len(data) < end || end < 8 {
		df.SetTruncated()
		return ErrModbusDataTooSmall
	}
	m.ReqResp = data[8:end]
	m.Contents = data[:end]
	m.Payload = data[end:]
	return nil
}

func (m *Modbus) LayerType() gopacket.LayerType {
	return LayerTypeModbus
}

func (m *Modbus) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypeZero
}

func (m *Modbus) CanDecode() gopacket.LayerClass {
	return LayerTypeModbus
}

func decodeModbus(data []byte, p gopacket.PacketBuilder) error {
	if len(data) < MinModbusPacketLen {
		p.SetTruncated()
		return ErrModbusDataTooSmall
	}
	modbus := &Modbus{}
	return decodingLayerDecoder(modbus, data, p)
}

// Validate checks if the Modbus packet is valid according to the protocol specification
func (m *Modbus) Validate() error {
	if m.ProtocolID != 0 {
		return ErrModbusInvalidProtocol
	}
	// Length should include UnitID (1 byte) + FunctionCode (1 byte) + Data
	expectedLength := 1 + 1 + len(m.ReqResp)
	if int(m.Length) != expectedLength {
		return errors.New("Modbus length field mismatch")
	}
	return nil
}

// IsException returns true if this is a Modbus exception response
func (m *Modbus) IsException() bool {
	return m.Exception
}

// GetFunction returns the Modbus function code as a ModbusFunctionCode type
func (m *Modbus) GetFunction() ModbusFunctionCode {
	return ModbusFunctionCode(m.FunctionCode)
}

// GetExceptionCode returns the exception code from the first byte of ReqResp data
// Returns 0 if this is not an exception response or if there is no data
func (m *Modbus) GetExceptionCode() ModbusExceptionCode {
	if !m.Exception || len(m.ReqResp) == 0 {
		return 0
	}
	return ModbusExceptionCode(m.ReqResp[0])
}
