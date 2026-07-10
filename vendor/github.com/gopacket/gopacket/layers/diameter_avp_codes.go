package layers

// DiameterAVPCode represents Diameter AVP codes
type DiameterAVPCode uint32

// Standard Diameter AVP Codes from RFC 6733
const (
	DiameterAVPCodeUserName               DiameterAVPCode = 1
	DiameterAVPCodeClass                  DiameterAVPCode = 25
	DiameterAVPCodeSessionTimeout         DiameterAVPCode = 27
	DiameterAVPCodeProxyState             DiameterAVPCode = 33
	DiameterAVPCodeAccountingSessionID    DiameterAVPCode = 44
	DiameterAVPCodeAcctMultiSessionID     DiameterAVPCode = 50
	DiameterAVPCodeEventTimestamp         DiameterAVPCode = 55
	DiameterAVPCodeAcctInterimInterval    DiameterAVPCode = 85
	DiameterAVPCodeHostIPAddress          DiameterAVPCode = 257
	DiameterAVPCodeAuthApplicationID      DiameterAVPCode = 258
	DiameterAVPCodeAcctApplicationID      DiameterAVPCode = 259
	DiameterAVPCodeVendorSpecificAppID    DiameterAVPCode = 260
	DiameterAVPCodeRedirectHostUsage      DiameterAVPCode = 261
	DiameterAVPCodeRedirectMaxCacheTime   DiameterAVPCode = 262
	DiameterAVPCodeSessionID              DiameterAVPCode = 263
	DiameterAVPCodeOriginHost             DiameterAVPCode = 264
	DiameterAVPCodeSupportedVendorID      DiameterAVPCode = 265
	DiameterAVPCodeVendorID               DiameterAVPCode = 266
	DiameterAVPCodeFirmwareRevision       DiameterAVPCode = 267
	DiameterAVPCodeResultCode             DiameterAVPCode = 268
	DiameterAVPCodeProductName            DiameterAVPCode = 269
	DiameterAVPCodeSessionBinding         DiameterAVPCode = 270
	DiameterAVPCodeSessionServerFailover  DiameterAVPCode = 271
	DiameterAVPCodeMultiRoundTimeOut      DiameterAVPCode = 272
	DiameterAVPCodeDisconnectCause        DiameterAVPCode = 273
	DiameterAVPCodeAuthRequestType        DiameterAVPCode = 274
	DiameterAVPCodeAuthGracePeriod        DiameterAVPCode = 276
	DiameterAVPCodeAuthSessionState       DiameterAVPCode = 277
	DiameterAVPCodeOriginStateID          DiameterAVPCode = 278
	DiameterAVPCodeFailedAVP              DiameterAVPCode = 279
	DiameterAVPCodeProxyHost              DiameterAVPCode = 280
	DiameterAVPCodeErrorMessage           DiameterAVPCode = 281
	DiameterAVPCodeRouteRecord            DiameterAVPCode = 282
	DiameterAVPCodeDestinationRealm       DiameterAVPCode = 283
	DiameterAVPCodeProxyInfo              DiameterAVPCode = 284
	DiameterAVPCodeReAuthRequestType      DiameterAVPCode = 285
	DiameterAVPCodeAccountingSubSessionID DiameterAVPCode = 287
	DiameterAVPCodeAuthorizationLifetime  DiameterAVPCode = 291
	DiameterAVPCodeRedirectHost           DiameterAVPCode = 292
	DiameterAVPCodeDestinationHost        DiameterAVPCode = 293
	DiameterAVPCodeErrorReportingHost     DiameterAVPCode = 294
	DiameterAVPCodeTerminationCause       DiameterAVPCode = 295
	DiameterAVPCodeOriginRealm            DiameterAVPCode = 296
	DiameterAVPCodeExperimentalResult     DiameterAVPCode = 297
	DiameterAVPCodeExperimentalResultCode DiameterAVPCode = 298
	DiameterAVPCodeInbandSecurityID       DiameterAVPCode = 299
	DiameterAVPCodeAccountingRecordType   DiameterAVPCode = 480
	DiameterAVPCodeAccountingRealtimeReq  DiameterAVPCode = 483
	DiameterAVPCodeAccountingRecordNumber DiameterAVPCode = 485
)

// 3GPP Vendor AVP Codes (Vendor ID: 10415)
const (
	DiameterAVPCode3GPPUserName           DiameterAVPCode = 1
	DiameterAVPCode3GPPMSISDN             DiameterAVPCode = 8
	DiameterAVPCode3GPPVisitedPLMNId      DiameterAVPCode = 9
	DiameterAVPCode3GPPUserEquipmentType  DiameterAVPCode = 21
	DiameterAVPCode3GPPUserEquipmentValue DiameterAVPCode = 22
	DiameterAVPCode3GPPCCRequestNumber    DiameterAVPCode = 415
	DiameterAVPCode3GPPCCRequestType      DiameterAVPCode = 416
	DiameterAVPCode3GPPSubscriptionId     DiameterAVPCode = 443
	DiameterAVPCode3GPPSubscriptionIdData DiameterAVPCode = 444
	DiameterAVPCode3GPPSubscriptionIdType DiameterAVPCode = 450
	DiameterAVPCode3GPPServingNode        DiameterAVPCode = 873
	DiameterAVPCode3GPPRatingGroup        DiameterAVPCode = 1032
	DiameterAVPCode3GPPTraceData          DiameterAVPCode = 1263
)

// ETSI Vendor AVP Codes (Vendor ID: 13019)
const (
	DiameterAVPCodeETSISIPAuthDataItem      DiameterAVPCode = 311
	DiameterAVPCodeETSIAFChargingIdentifier DiameterAVPCode = 505
	DiameterAVPCodeETSIVisitedNetworkID     DiameterAVPCode = 600
	DiameterAVPCodeETSIPublicIdentity       DiameterAVPCode = 601
	DiameterAVPCodeETSIServerName           DiameterAVPCode = 602
	DiameterAVPCodeETSIServerAssignmentType DiameterAVPCode = 603
	DiameterAVPCodeETSIUserDataAlreadyAvail DiameterAVPCode = 606
	DiameterAVPCodeETSIChargingInformation  DiameterAVPCode = 610
	DiameterAVPCodeETSISupportedFeatures    DiameterAVPCode = 629
	DiameterAVPCodeETSIFeatureListID        DiameterAVPCode = 630
	DiameterAVPCodeETSIFeatureList          DiameterAVPCode = 631
)

// DiameterAVPType represents the data type of an AVP
type DiameterAVPType uint8

const (
	DiameterAVPTypeOctetString DiameterAVPType = iota
	DiameterAVPTypeInteger32
	DiameterAVPTypeInteger64
	DiameterAVPTypeUnsigned32
	DiameterAVPTypeUnsigned64
	DiameterAVPTypeFloat32
	DiameterAVPTypeFloat64
	DiameterAVPTypeGrouped
	DiameterAVPTypeAddress
	DiameterAVPTypeTime
	DiameterAVPTypeUTF8String
	DiameterAVPTypeDiameterIdentity
	DiameterAVPTypeDiameterURI
	DiameterAVPTypeEnumerated
	DiameterAVPTypeIPFilterRule
)

// AVPKey uniquely identifies an AVP by its code and optional vendor ID
type AVPKey struct {
	Code     uint32
	VendorID uint32
}

// diameterAVPTypeMap maps standard AVP codes to their data types
var diameterAVPTypeMap = map[uint32]DiameterAVPType{
	uint32(DiameterAVPCodeUserName):               DiameterAVPTypeUTF8String,
	uint32(DiameterAVPCodeSessionID):              DiameterAVPTypeUTF8String,
	uint32(DiameterAVPCodeOriginHost):             DiameterAVPTypeDiameterIdentity,
	uint32(DiameterAVPCodeOriginRealm):            DiameterAVPTypeDiameterIdentity,
	uint32(DiameterAVPCodeDestinationHost):        DiameterAVPTypeDiameterIdentity,
	uint32(DiameterAVPCodeDestinationRealm):       DiameterAVPTypeDiameterIdentity,
	uint32(DiameterAVPCodeHostIPAddress):          DiameterAVPTypeAddress,
	uint32(DiameterAVPCodeAuthApplicationID):      DiameterAVPTypeUnsigned32,
	uint32(DiameterAVPCodeAcctApplicationID):      DiameterAVPTypeUnsigned32,
	uint32(DiameterAVPCodeVendorID):               DiameterAVPTypeUnsigned32,
	uint32(DiameterAVPCodeProductName):            DiameterAVPTypeUTF8String,
	uint32(DiameterAVPCodeResultCode):             DiameterAVPTypeUnsigned32,
	uint32(DiameterAVPCodeSessionTimeout):         DiameterAVPTypeUnsigned32,
	uint32(DiameterAVPCodeAuthRequestType):        DiameterAVPTypeEnumerated,
	uint32(DiameterAVPCodeAuthGracePeriod):        DiameterAVPTypeUnsigned32,
	uint32(DiameterAVPCodeAuthSessionState):       DiameterAVPTypeEnumerated,
	uint32(DiameterAVPCodeOriginStateID):          DiameterAVPTypeUnsigned32,
	uint32(DiameterAVPCodeFailedAVP):              DiameterAVPTypeGrouped,
	uint32(DiameterAVPCodeProxyInfo):              DiameterAVPTypeGrouped,
	uint32(DiameterAVPCodeRouteRecord):            DiameterAVPTypeDiameterIdentity,
	uint32(DiameterAVPCodeExperimentalResult):     DiameterAVPTypeGrouped,
	uint32(DiameterAVPCodeExperimentalResultCode): DiameterAVPTypeUnsigned32,
	uint32(DiameterAVPCodeVendorSpecificAppID):    DiameterAVPTypeGrouped,
	uint32(DiameterAVPCodeEventTimestamp):         DiameterAVPTypeTime,
	uint32(DiameterAVPCodeAccountingRecordType):   DiameterAVPTypeEnumerated,
	uint32(DiameterAVPCodeAccountingRealtimeReq):  DiameterAVPTypeEnumerated,
	uint32(DiameterAVPCodeAccountingRecordNumber): DiameterAVPTypeUnsigned32,
	uint32(DiameterAVPCodeReAuthRequestType):      DiameterAVPTypeEnumerated,
	uint32(DiameterAVPCodeSessionBinding):         DiameterAVPTypeUnsigned32,
	uint32(DiameterAVPCodeDisconnectCause):        DiameterAVPTypeEnumerated,
	uint32(DiameterAVPCodeTerminationCause):       DiameterAVPTypeEnumerated,
	uint32(DiameterAVPCodeProxyHost):              DiameterAVPTypeDiameterIdentity,
	uint32(DiameterAVPCodeErrorMessage):           DiameterAVPTypeUTF8String,
	uint32(DiameterAVPCodeClass):                  DiameterAVPTypeOctetString,
	uint32(DiameterAVPCodeProxyState):             DiameterAVPTypeOctetString,
}

// diameterVendorAVPTypeMap maps vendor-specific AVP (code, vendorID) to their data types
var diameterVendorAVPTypeMap = map[AVPKey]DiameterAVPType{
	// 3GPP Vendor AVPs (Vendor ID: 10415)
	{Code: uint32(DiameterAVPCode3GPPUserName), VendorID: uint32(DiameterVendor3GPP)}:           DiameterAVPTypeUTF8String,
	{Code: uint32(DiameterAVPCode3GPPMSISDN), VendorID: uint32(DiameterVendor3GPP)}:             DiameterAVPTypeUnsigned32,
	{Code: uint32(DiameterAVPCode3GPPVisitedPLMNId), VendorID: uint32(DiameterVendor3GPP)}:      DiameterAVPTypeOctetString,
	{Code: uint32(DiameterAVPCode3GPPUserEquipmentType), VendorID: uint32(DiameterVendor3GPP)}:  DiameterAVPTypeEnumerated,
	{Code: uint32(DiameterAVPCode3GPPUserEquipmentValue), VendorID: uint32(DiameterVendor3GPP)}: DiameterAVPTypeOctetString,
	{Code: uint32(DiameterAVPCode3GPPCCRequestNumber), VendorID: uint32(DiameterVendor3GPP)}:    DiameterAVPTypeUnsigned32,
	{Code: uint32(DiameterAVPCode3GPPCCRequestType), VendorID: uint32(DiameterVendor3GPP)}:      DiameterAVPTypeEnumerated,
	{Code: uint32(DiameterAVPCode3GPPSubscriptionId), VendorID: uint32(DiameterVendor3GPP)}:     DiameterAVPTypeGrouped,
	{Code: uint32(DiameterAVPCode3GPPSubscriptionIdType), VendorID: uint32(DiameterVendor3GPP)}: DiameterAVPTypeEnumerated,
	{Code: uint32(DiameterAVPCode3GPPSubscriptionIdData), VendorID: uint32(DiameterVendor3GPP)}: DiameterAVPTypeUTF8String,
	{Code: uint32(DiameterAVPCode3GPPServingNode), VendorID: uint32(DiameterVendor3GPP)}:        DiameterAVPTypeOctetString,
	{Code: uint32(DiameterAVPCode3GPPRatingGroup), VendorID: uint32(DiameterVendor3GPP)}:        DiameterAVPTypeUnsigned32,
	{Code: uint32(DiameterAVPCode3GPPTraceData), VendorID: uint32(DiameterVendor3GPP)}:          DiameterAVPTypeGrouped,

	// ETSI Vendor AVPs (Vendor ID: 13019)
	{Code: uint32(DiameterAVPCodeETSISIPAuthDataItem), VendorID: uint32(DiameterVendorETSI)}:      DiameterAVPTypeOctetString,
	{Code: uint32(DiameterAVPCodeETSIAFChargingIdentifier), VendorID: uint32(DiameterVendorETSI)}: DiameterAVPTypeUnsigned32,
	{Code: uint32(DiameterAVPCodeETSIVisitedNetworkID), VendorID: uint32(DiameterVendorETSI)}:     DiameterAVPTypeGrouped,
	{Code: uint32(DiameterAVPCodeETSIPublicIdentity), VendorID: uint32(DiameterVendorETSI)}:       DiameterAVPTypeUTF8String,
	{Code: uint32(DiameterAVPCodeETSIServerName), VendorID: uint32(DiameterVendorETSI)}:           DiameterAVPTypeUTF8String,
	{Code: uint32(DiameterAVPCodeETSIServerAssignmentType), VendorID: uint32(DiameterVendorETSI)}: DiameterAVPTypeEnumerated,
	{Code: uint32(DiameterAVPCodeETSIUserDataAlreadyAvail), VendorID: uint32(DiameterVendorETSI)}: DiameterAVPTypeEnumerated,
	{Code: uint32(DiameterAVPCodeETSIChargingInformation), VendorID: uint32(DiameterVendorETSI)}:  DiameterAVPTypeGrouped,
	{Code: uint32(DiameterAVPCodeETSISupportedFeatures), VendorID: uint32(DiameterVendorETSI)}:    DiameterAVPTypeGrouped,
	{Code: uint32(DiameterAVPCodeETSIFeatureListID), VendorID: uint32(DiameterVendorETSI)}:        DiameterAVPTypeUnsigned32,
	{Code: uint32(DiameterAVPCodeETSIFeatureList), VendorID: uint32(DiameterVendorETSI)}:          DiameterAVPTypeUnsigned32,
}

// GetDiameterAVPType returns the data type for an AVP based on its code and vendor ID
func GetDiameterAVPType(code uint32, vendorID uint32) (DiameterAVPType, bool) {
	// First check vendor-specific AVPs if vendor ID is set
	if vendorID != 0 {
		key := AVPKey{Code: code, VendorID: vendorID}
		if avpType, ok := diameterVendorAVPTypeMap[key]; ok {
			return avpType, true
		}
	}

	// Then check standard AVPs
	if avpType, ok := diameterAVPTypeMap[code]; ok {
		return avpType, true
	}

	return DiameterAVPTypeOctetString, false
}
