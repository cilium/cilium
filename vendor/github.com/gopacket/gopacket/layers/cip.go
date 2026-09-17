// CIP (Common Industrial Protocol) support for gopacket.
// CIP is an industrial protocol defined by ODVA (odva.org) that runs
// on top of EtherNet/IP and other industrial networks.
// See: https://www.odva.org

package layers

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/gopacket/gopacket"
)

const (
	cipBasePacketLen int = 2
)

var (
	// ErrCIPDataTooSmall indicates that a CIP packet has been truncated
	ErrCIPDataTooSmall = errors.New("CIP packet data truncated")
)

// CIPService represents a CIP service code
type CIPService byte

// CIP Service Code constants
const (
	CIPServiceGetAttributesAll       CIPService = 0x01
	CIPServiceSetAttributesAll       CIPService = 0x02
	CIPServiceGetAttributeList       CIPService = 0x03
	CIPServiceSetAttributeList       CIPService = 0x04
	CIPServiceReset                  CIPService = 0x05
	CIPServiceStart                  CIPService = 0x06
	CIPServiceStop                   CIPService = 0x07
	CIPServiceCreate                 CIPService = 0x08
	CIPServiceDelete                 CIPService = 0x09
	CIPServiceMultipleServicePacket  CIPService = 0x0A
	CIPServiceApplyAttributes        CIPService = 0x0D
	CIPServiceGetAttributeSingle     CIPService = 0x0E
	CIPServiceSetAttributeSingle     CIPService = 0x10
	CIPServiceFindNextObjectInstance CIPService = 0x11
	CIPServiceRestore                CIPService = 0x15
	CIPServiceSave                   CIPService = 0x16
	CIPServiceGetMember              CIPService = 0x18
	CIPServiceSetMember              CIPService = 0x19
	CIPServiceInsertMember           CIPService = 0x1A
	CIPServiceRemoveMember           CIPService = 0x1B
	CIPServiceGroupSync              CIPService = 0x1C
	// Connection Manager Services
	CIPServiceForwardOpen          CIPService = 0x54
	CIPServiceForwardClose         CIPService = 0x4E
	CIPServiceUnconnectedSend      CIPService = 0x52
	CIPServiceGetConnectionData    CIPService = 0x56
	CIPServiceSearchConnectionData CIPService = 0x57
	CIPServiceGetConnectionOwner   CIPService = 0x5A
	// Response bit (OR'd with service code for responses)
	CIPServiceResponseMask CIPService = 0x80
)

// String returns a human-readable string representation of the CIP service
func (cs CIPService) String() string {
	// Check if it's a response
	isResponse := (cs & CIPServiceResponseMask) != 0
	service := cs & ^CIPServiceResponseMask

	var serviceName string
	switch service {
	case CIPServiceGetAttributesAll:
		serviceName = "Get_Attributes_All"
	case CIPServiceSetAttributesAll:
		serviceName = "Set_Attributes_All"
	case CIPServiceGetAttributeList:
		serviceName = "Get_Attribute_List"
	case CIPServiceSetAttributeList:
		serviceName = "Set_Attribute_List"
	case CIPServiceReset:
		serviceName = "Reset"
	case CIPServiceStart:
		serviceName = "Start"
	case CIPServiceStop:
		serviceName = "Stop"
	case CIPServiceCreate:
		serviceName = "Create"
	case CIPServiceDelete:
		serviceName = "Delete"
	case CIPServiceMultipleServicePacket:
		serviceName = "Multiple_Service_Packet"
	case CIPServiceApplyAttributes:
		serviceName = "Apply_Attributes"
	case CIPServiceGetAttributeSingle:
		serviceName = "Get_Attribute_Single"
	case CIPServiceSetAttributeSingle:
		serviceName = "Set_Attribute_Single"
	case CIPServiceFindNextObjectInstance:
		serviceName = "Find_Next_Object_Instance"
	case CIPServiceRestore:
		serviceName = "Restore"
	case CIPServiceSave:
		serviceName = "Save"
	case CIPServiceGetMember:
		serviceName = "Get_Member"
	case CIPServiceSetMember:
		serviceName = "Set_Member"
	case CIPServiceInsertMember:
		serviceName = "Insert_Member"
	case CIPServiceRemoveMember:
		serviceName = "Remove_Member"
	case CIPServiceGroupSync:
		serviceName = "Group_Sync"
	case CIPServiceForwardOpen:
		serviceName = "Forward_Open"
	case CIPServiceForwardClose:
		serviceName = "Forward_Close"
	case CIPServiceUnconnectedSend:
		serviceName = "Unconnected_Send"
	case CIPServiceGetConnectionData:
		serviceName = "Get_Connection_Data"
	case CIPServiceSearchConnectionData:
		serviceName = "Search_Connection_Data"
	case CIPServiceGetConnectionOwner:
		serviceName = "Get_Connection_Owner"
	default:
		serviceName = fmt.Sprintf("Unknown(0x%02X)", byte(service))
	}

	if isResponse {
		return serviceName + "_Response"
	}
	return serviceName
}

// CIPStatus represents a CIP status code
type CIPStatus byte

// CIP Status Code constants
const (
	CIPStatusSuccess                       CIPStatus = 0x00
	CIPStatusConnectionFailure             CIPStatus = 0x01
	CIPStatusResourceUnavailable           CIPStatus = 0x02
	CIPStatusInvalidParameterValue         CIPStatus = 0x03
	CIPStatusPathSegmentError              CIPStatus = 0x04
	CIPStatusPathDestinationUnknown        CIPStatus = 0x05
	CIPStatusPartialTransfer               CIPStatus = 0x06
	CIPStatusConnectionLost                CIPStatus = 0x07
	CIPStatusServiceNotSupported           CIPStatus = 0x08
	CIPStatusInvalidAttributeValue         CIPStatus = 0x09
	CIPStatusAttributeListError            CIPStatus = 0x0A
	CIPStatusAlreadyInRequestedMode        CIPStatus = 0x0B
	CIPStatusObjectStateConflict           CIPStatus = 0x0C
	CIPStatusObjectAlreadyExists           CIPStatus = 0x0D
	CIPStatusAttributeNotSettable          CIPStatus = 0x0E
	CIPStatusPrivilegeViolation            CIPStatus = 0x0F
	CIPStatusDeviceStateConflict           CIPStatus = 0x10
	CIPStatusReplyDataTooLarge             CIPStatus = 0x11
	CIPStatusFragmentationOfPrimitiveValue CIPStatus = 0x12
	CIPStatusNotEnoughData                 CIPStatus = 0x13
	CIPStatusAttributeNotSupported         CIPStatus = 0x14
	CIPStatusTooMuchData                   CIPStatus = 0x15
	CIPStatusObjectDoesNotExist            CIPStatus = 0x16
	CIPStatusServiceFragmentationSequence  CIPStatus = 0x17
	CIPStatusNoStoredAttributeData         CIPStatus = 0x18
	CIPStatusStoreOperationFailure         CIPStatus = 0x19
	CIPStatusRoutingFailure                CIPStatus = 0x1A
	CIPStatusRoutingFailureBadSize         CIPStatus = 0x1B
	CIPStatusRoutingFailureBadService      CIPStatus = 0x1C
	CIPStatusInvalidParameter              CIPStatus = 0x20
)

// String returns a human-readable string representation of the CIP status
func (cs CIPStatus) String() string {
	switch cs {
	case CIPStatusSuccess:
		return "Success"
	case CIPStatusConnectionFailure:
		return "Connection Failure"
	case CIPStatusResourceUnavailable:
		return "Resource Unavailable"
	case CIPStatusInvalidParameterValue:
		return "Invalid Parameter Value"
	case CIPStatusPathSegmentError:
		return "Path Segment Error"
	case CIPStatusPathDestinationUnknown:
		return "Path Destination Unknown"
	case CIPStatusPartialTransfer:
		return "Partial Transfer"
	case CIPStatusConnectionLost:
		return "Connection Lost"
	case CIPStatusServiceNotSupported:
		return "Service Not Supported"
	case CIPStatusInvalidAttributeValue:
		return "Invalid Attribute Value"
	case CIPStatusAttributeListError:
		return "Attribute List Error"
	case CIPStatusAlreadyInRequestedMode:
		return "Already In Requested Mode"
	case CIPStatusObjectStateConflict:
		return "Object State Conflict"
	case CIPStatusObjectAlreadyExists:
		return "Object Already Exists"
	case CIPStatusAttributeNotSettable:
		return "Attribute Not Settable"
	case CIPStatusPrivilegeViolation:
		return "Privilege Violation"
	case CIPStatusDeviceStateConflict:
		return "Device State Conflict"
	case CIPStatusReplyDataTooLarge:
		return "Reply Data Too Large"
	case CIPStatusFragmentationOfPrimitiveValue:
		return "Fragmentation Of Primitive Value"
	case CIPStatusNotEnoughData:
		return "Not Enough Data"
	case CIPStatusAttributeNotSupported:
		return "Attribute Not Supported"
	case CIPStatusTooMuchData:
		return "Too Much Data"
	case CIPStatusObjectDoesNotExist:
		return "Object Does Not Exist"
	case CIPStatusServiceFragmentationSequence:
		return "Service Fragmentation Sequence"
	case CIPStatusNoStoredAttributeData:
		return "No Stored Attribute Data"
	case CIPStatusStoreOperationFailure:
		return "Store Operation Failure"
	case CIPStatusRoutingFailure:
		return "Routing Failure"
	case CIPStatusRoutingFailureBadSize:
		return "Routing Failure - Bad Size"
	case CIPStatusRoutingFailureBadService:
		return "Routing Failure - Bad Service"
	case CIPStatusInvalidParameter:
		return "Invalid Parameter"
	default:
		return fmt.Sprintf("Unknown(0x%02X)", byte(cs))
	}
}

// CIP implements encoding/decoding for the Common Industrial Protocol, as
// defined by ODVA (odva.org).
// Refer to https://www.rockwellautomation.com/resources/downloads/rockwellautomation/pdf/sales-partners/technology-licensing/eipexp1_2.pdf
// for more information about the protocol.
type CIP struct {
	BaseLayer
	Response         bool     // false if request, true if response
	ServiceID        byte     // The service specified for the request
	ClassID          uint16   // request only
	InstanceID       uint16   // request only
	Status           byte     // Response only
	AdditionalStatus []uint16 // Response only
	Data             []byte   // Command data for request, reply data for response
}

// DecodeFromBytes unpacks a CIP packet in the `data` argument into the receiver.
func (cip *CIP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	// Initial bounds check
	if len(data) < cipBasePacketLen {
		df.SetTruncated()
		return ErrCIPDataTooSmall
	}

	offset := 0
	tmp := data[offset]
	offset++

	if (tmp & 0x80) == 0x80 {
		cip.Response = true
	} else {
		cip.Response = false
	}
	cip.ServiceID = tmp & 0x7f

	if !cip.Response {
		// Parse out the request
		// path size is in 16-bit words
		if offset >= len(data) {
			df.SetTruncated()
			return ErrCIPDataTooSmall
		}
		pathsize := data[offset]
		offset++

		// Prevent uint8 overflow: pathsize is in 16-bit words and must be small enough to not overflow.
		if pathsize > 127 {
			df.SetTruncated()
			return ErrCIPDataTooSmall
		}
		pathBytes := 2 * int(pathsize)
		if len(data) < cipBasePacketLen+pathBytes {
			df.SetTruncated()
			return ErrCIPDataTooSmall
		}

		// read the class segment
		if offset >= len(data) {
			df.SetTruncated()
			return ErrCIPDataTooSmall
		}
		classInfo := data[offset]
		offset++

		switch classInfo {
		case 0x20:
			// 8-bit ID
			if offset >= len(data) {
				df.SetTruncated()
				return ErrCIPDataTooSmall
			}
			cip.ClassID = uint16(data[offset])
			offset++
		case 0x21:
			// 16-bit ID
			if offset+2 > len(data) {
				df.SetTruncated()
				return ErrCIPDataTooSmall
			}
			cip.ClassID = binary.LittleEndian.Uint16(data[offset : offset+2])
			offset += 2
		}

		// read the instance segment
		if offset >= len(data) {
			df.SetTruncated()
			return ErrCIPDataTooSmall
		}
		instanceInfo := data[offset]
		offset++

		switch instanceInfo {
		case 0x24:
			// 8-bit ID
			if offset >= len(data) {
				df.SetTruncated()
				return ErrCIPDataTooSmall
			}
			cip.InstanceID = uint16(data[offset])
			offset++
		case 0x25:
			// 16-bit ID
			if offset+2 > len(data) {
				df.SetTruncated()
				return ErrCIPDataTooSmall
			}
			cip.InstanceID = binary.LittleEndian.Uint16(data[offset : offset+2])
			offset += 2
		}

		if offset < len(data) {
			cip.Data = data[offset:]
		}
	} else { // response
		if len(data) < cipBasePacketLen+2 {
			df.SetTruncated()
			return ErrCIPDataTooSmall
		}

		offset++ // skip the 00 padding byte

		cip.Status = data[offset]
		offset++

		additionalStatusSize := uint(data[offset])
		offset++

		if len(data) < cipBasePacketLen+2+2*int(additionalStatusSize) {
			df.SetTruncated()
			return ErrCIPDataTooSmall
		}

		for i := 0; i < int(additionalStatusSize); i++ {
			cip.AdditionalStatus = append(cip.AdditionalStatus, binary.LittleEndian.Uint16(data[offset:offset+2]))
			offset += 2
		}

		if offset < len(data) {
			cip.Data = data[offset:]
		}
	}
	return nil
}

// LayerType returns gopacket.LayerTypeCIP
func (cip *CIP) LayerType() gopacket.LayerType { return LayerTypeCIP }

// CanDecode returns gopacket.LayerTypeCIP
func (cip *CIP) CanDecode() gopacket.LayerClass { return LayerTypeCIP }

// NextLayerType returns LayerTypePayload, the only possible next
// layer type for a CIP packet.
func (cip *CIP) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

func decodeCIP(data []byte, p gopacket.PacketBuilder) error {
	if len(data) < cipBasePacketLen {
		p.SetTruncated()
		return ErrCIPDataTooSmall
	}
	cip := &CIP{}
	return decodingLayerDecoder(cip, data, p)
}

// IsRequest returns true if this is a CIP request (not a response)
func (cip *CIP) IsRequest() bool {
	return !cip.Response
}

// IsResponse returns true if this is a CIP response
func (cip *CIP) IsResponse() bool {
	return cip.Response
}

// IsSuccess returns true if this is a response with success status
func (cip *CIP) IsSuccess() bool {
	return cip.Response && cip.Status == 0
}
