package bgp

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
)

// Validator for BGPUpdate
func ValidateUpdateMsg(m *BGPUpdate, rfs map[Family]BGPAddPathMode, isEBGP bool, isConfed bool, loopbackNextHopAllowed bool) (bool, error) {
	var strongestError error

	eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
	eSubCodeAttrList := uint8(BGP_ERROR_SUB_MALFORMED_ATTRIBUTE_LIST)
	eSubCodeMissing := uint8(BGP_ERROR_SUB_MISSING_WELL_KNOWN_ATTRIBUTE)

	if len(m.NLRI) > 0 || len(m.WithdrawnRoutes) > 0 {
		if _, ok := rfs[RF_IPv4_UC]; !ok {
			return false, NewMessageError(0, 0, nil, fmt.Sprintf("Address-family rf %d not available for session", RF_IPv4_UC))
		}
	}

	seen := make(map[BGPAttrType]PathAttributeInterface)
	newAttrs := make([]PathAttributeInterface, 0, len(seen))
	// check path attribute
	for _, a := range m.PathAttributes {
		// check duplication
		if _, ok := seen[a.GetType()]; !ok {
			seen[a.GetType()] = a
			newAttrs = append(newAttrs, a)
			// check specific path attribute
			ok, err := ValidateAttribute(a, rfs, isEBGP, isConfed, loopbackNextHopAllowed)
			if !ok {
				msgErr := err.(*MessageError)
				if msgErr.ErrorHandling == ERROR_HANDLING_SESSION_RESET {
					return false, err
				} else if msgErr.Stronger(strongestError) {
					strongestError = err
				}
			}
		} else if a.GetType() == BGP_ATTR_TYPE_MP_REACH_NLRI || a.GetType() == BGP_ATTR_TYPE_MP_UNREACH_NLRI {
			eMsg := "the path attribute appears twice. Type : " + strconv.Itoa(int(a.GetType()))
			return false, NewMessageError(eCode, eSubCodeAttrList, nil, eMsg)
		} else {
			eMsg := "the path attribute appears twice. Type : " + strconv.Itoa(int(a.GetType()))
			e := NewMessageErrorWithErrorHandling(eCode, eSubCodeAttrList, nil, ERROR_HANDLING_ATTRIBUTE_DISCARD, nil, eMsg)
			if e.(*MessageError).Stronger(strongestError) {
				strongestError = e
			}
		}
	}
	m.PathAttributes = newAttrs

	if _, ok := seen[BGP_ATTR_TYPE_MP_REACH_NLRI]; ok || len(m.NLRI) > 0 {
		// check the existence of well-known mandatory attributes
		exist := func(attrs []BGPAttrType) (bool, BGPAttrType) {
			for _, attr := range attrs {
				_, ok := seen[attr]
				if !ok {
					return false, attr
				}
			}
			return true, 0
		}
		mandatory := []BGPAttrType{BGP_ATTR_TYPE_ORIGIN, BGP_ATTR_TYPE_AS_PATH}
		if len(m.NLRI) > 0 {
			mandatory = append(mandatory, BGP_ATTR_TYPE_NEXT_HOP)
		}
		if ok, t := exist(mandatory); !ok {
			eMsg := "well-known mandatory attributes are not present. type : " + strconv.Itoa(int(t))
			data := []byte{byte(t)}
			e := NewMessageErrorWithErrorHandling(eCode, eSubCodeMissing, data, ERROR_HANDLING_TREAT_AS_WITHDRAW, nil, eMsg)
			if e.(*MessageError).Stronger(strongestError) {
				strongestError = e
			}
		}
	}

	return strongestError == nil, strongestError
}

func ValidateAttribute(a PathAttributeInterface, rfs map[Family]BGPAddPathMode, isEBGP bool, isConfed bool, loopbackNextHopAllowed bool) (bool, error) {
	var strongestError error

	eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
	eSubCodeBadOrigin := uint8(BGP_ERROR_SUB_INVALID_ORIGIN_ATTRIBUTE)
	eSubCodeBadNextHop := uint8(BGP_ERROR_SUB_INVALID_NEXT_HOP_ATTRIBUTE)
	eSubCodeUnknown := uint8(BGP_ERROR_SUB_UNRECOGNIZED_WELL_KNOWN_ATTRIBUTE)
	eSubCodeMalformedAspath := uint8(BGP_ERROR_SUB_MALFORMED_AS_PATH)

	checkPrefix := func(family Family, l []PathNLRI) error {
		if _, ok := rfs[family]; !ok {
			return NewMessageError(0, 0, nil, fmt.Sprintf("Address-family %s not available for this session", family))
		}

		for _, prefix := range l {
			switch family {
			case RF_FS_IPv4_UC, RF_FS_IPv6_UC, RF_FS_IPv4_VPN, RF_FS_IPv6_VPN, RF_FS_L2_VPN:
				t := BGPFlowSpecType(0)
				for _, v := range prefix.NLRI.(*FlowSpecNLRI).Value {
					if v.Type() <= t {
						return NewMessageError(0, 0, nil, fmt.Sprintf("%s nlri violate strict type ordering", family))
					}
					t = v.Type()
				}
			}
		}
		return nil
	}

	switch p := a.(type) {
	case *PathAttributeMpUnreachNLRI:
		if err := checkPrefix(NewFamily(p.AFI, p.SAFI), p.Value); err != nil {
			return false, err
		}
	case *PathAttributeMpReachNLRI:
		if err := checkPrefix(NewFamily(p.AFI, p.SAFI), p.Value); err != nil {
			return false, err
		}
	case *PathAttributeOrigin:
		v := p.Value
		if v != BGP_ORIGIN_ATTR_TYPE_IGP &&
			v != BGP_ORIGIN_ATTR_TYPE_EGP &&
			v != BGP_ORIGIN_ATTR_TYPE_INCOMPLETE {
			data, _ := a.Serialize()
			eMsg := "invalid origin attribute. value : " + strconv.Itoa(int(v))
			e := NewMessageErrorWithErrorHandling(eCode, eSubCodeBadOrigin, data, getErrorHandlingFromPathAttribute(p.GetType()), nil, eMsg)
			if e.(*MessageError).Stronger(strongestError) {
				strongestError = e
			}
		}
	case *PathAttributeNextHop:

		isZero := func(ip net.IP) bool {
			res := ip[0] & 0xff
			return res == 0x00
		}

		isClassDorE := func(ip net.IP) bool {
			if ip.To4() == nil {
				// needs to verify ipv6 too?
				return false
			}
			res := ip[0] & 0xe0
			return res == 0xe0
		}
		addr := net.IP(p.Value.AsSlice())
		// check IP address represents host address
		if !loopbackNextHopAllowed && p.Value.IsLoopback() || isZero(addr) || isClassDorE(addr) {
			eMsg := "invalid nexthop address"
			data, _ := a.Serialize()
			e := NewMessageErrorWithErrorHandling(eCode, eSubCodeBadNextHop, data, getErrorHandlingFromPathAttribute(p.GetType()), nil, eMsg)
			if e.(*MessageError).Stronger(strongestError) {
				strongestError = e
			}
		}
	case *PathAttributeAsPath:
		if isEBGP {
			if isConfed {
				if segType := p.Value[0].GetType(); segType != BGP_ASPATH_ATTR_TYPE_CONFED_SEQ {
					return false, NewMessageError(eCode, eSubCodeMalformedAspath, nil, fmt.Sprintf("segment type is not confederation seq (%d)", segType))
				}
			} else {
				for _, param := range p.Value {
					segType := param.GetType()
					switch segType {
					case BGP_ASPATH_ATTR_TYPE_CONFED_SET, BGP_ASPATH_ATTR_TYPE_CONFED_SEQ:
						err := NewMessageErrorWithErrorHandling(
							eCode, eSubCodeMalformedAspath, nil, getErrorHandlingFromPathAttribute(p.GetType()), nil, fmt.Sprintf("segment type confederation(%d) found", segType))
						if err.(*MessageError).Stronger(strongestError) {
							strongestError = err
						}
					}
				}
			}
		}
	case *PathAttributeLargeCommunities:
		uniq := make([]*LargeCommunity, 0, len(p.Values))
		for _, x := range p.Values {
			found := slices.ContainsFunc(uniq, x.Eq)
			if !found {
				uniq = append(uniq, x)
			}
		}
		p.Values = uniq

	case *PathAttributeUnknown:
		if p.GetFlags()&BGP_ATTR_FLAG_OPTIONAL == 0 {
			eMsg := fmt.Sprintf("unrecognized well-known attribute %s", p.GetType())
			data, _ := a.Serialize()
			return false, NewMessageError(eCode, eSubCodeUnknown, data, eMsg)
		}
	}

	return strongestError == nil, strongestError
}

// validator for PathAttribute
func validatePathAttributeFlags(t BGPAttrType, flags BGPAttrFlag) string {
	/*
	 * RFC 4271 P.17 For well-known attributes, the Transitive bit MUST be set to 1.
	 */
	if flags&BGP_ATTR_FLAG_OPTIONAL == 0 && flags&BGP_ATTR_FLAG_TRANSITIVE == 0 {
		eMsg := fmt.Sprintf("well-known attribute %s must have transitive flag 1", t)
		return eMsg
	}
	/*
	 * RFC 4271 P.17 For well-known attributes and for optional non-transitive attributes,
	 * the Partial bit MUST be set to 0.
	 */
	if flags&BGP_ATTR_FLAG_OPTIONAL == 0 && flags&BGP_ATTR_FLAG_PARTIAL != 0 {
		eMsg := fmt.Sprintf("well-known attribute %s must have partial bit 0", t)
		return eMsg
	}
	if flags&BGP_ATTR_FLAG_OPTIONAL != 0 && flags&BGP_ATTR_FLAG_TRANSITIVE == 0 && flags&BGP_ATTR_FLAG_PARTIAL != 0 {
		eMsg := fmt.Sprintf("optional non-transitive attribute %s must have partial bit 0", t)
		return eMsg
	}

	// check flags are correct
	if f, ok := PathAttrFlags[t]; ok {
		if f != flags & ^BGP_ATTR_FLAG_EXTENDED_LENGTH & ^BGP_ATTR_FLAG_PARTIAL {
			eMsg := fmt.Sprintf("flags are invalid. attribute type: %s, expect: %s, actual: %s", t, f, flags)
			return eMsg
		}
	}
	return ""
}

func validateAsPathValueBytes(data []byte, options ...*MarshallingOption) (bool, error) {
	eCode := uint8(BGP_ERROR_UPDATE_MESSAGE_ERROR)
	eSubCode := uint8(BGP_ERROR_SUB_MALFORMED_AS_PATH)
	if len(data)%2 != 0 {
		return false, NewMessageError(eCode, eSubCode, nil, "AS PATH length is not odd")
	}

	// Determine AS encoding format
	// Default: 4-byte AS (modern standard)
	// Use2ByteAS=true: 2-byte AS (legacy peers without 4-byte AS capability)
	use2ByteAS := false
	for _, opt := range options {
		if opt != nil && opt.Use2ByteAS {
			use2ByteAS = true
			break
		}
	}
	use4ByteAS := !use2ByteAS

	// Validate AS_PATH structure
	d := data
	for len(d) > 0 {
		if len(d) < 2 {
			return false, NewMessageError(eCode, eSubCode, nil, "AS PATH header is short")
		}
		segType := d[0]
		if segType == 0 || segType > 4 {
			return false, NewMessageError(eCode, eSubCode, nil, "unknown AS_PATH seg type")
		}
		asNum := d[1]
		d = d[2:]
		if asNum == 0 {
			return false, NewMessageError(eCode, eSubCode, nil, "AS PATH segment has zero AS count")
		}
		segLength := int(asNum)
		if use4ByteAS {
			segLength *= 4
		} else {
			segLength *= 2
		}
		if segLength > len(d) {
			return false, NewMessageError(eCode, eSubCode, nil, "seg length is short")
		}
		d = d[segLength:]
	}
	return use4ByteAS, nil
}

func ValidateOpenMsg(m *BGPOpen, expectedAS uint32, myAS uint32, myId netip.Addr) (uint32, error) {
	if m.Version != 4 {
		return 0, NewMessageError(BGP_ERROR_OPEN_MESSAGE_ERROR, BGP_ERROR_SUB_UNSUPPORTED_VERSION_NUMBER, nil, fmt.Sprintf("unsupported version %d", m.Version))
	}

	as := uint32(m.MyAS)
	for _, p := range m.OptParams {
		paramCap, y := p.(*OptionParameterCapability)
		if !y {
			continue
		}
		for _, c := range paramCap.Capability {
			if c.Code() == BGP_CAP_FOUR_OCTET_AS_NUMBER {
				cap := c.(*CapFourOctetASNumber)
				as = cap.CapValue
			}
		}
	}

	// rfc6286 (Autonomous-System-Wide Unique BGP Identifier for BGP-4)
	// If the BGP Identifier field of the OPEN message is zero, or if it
	// is the same as the BGP Identifier of the local BGP speaker and the
	// message is from an internal peer, then the Error Subcode is set to
	// "Bad BGP Identifier".
	routerId := m.ID
	if routerId.IsUnspecified() {
		return 0, NewMessageError(BGP_ERROR_OPEN_MESSAGE_ERROR, BGP_ERROR_SUB_BAD_BGP_IDENTIFIER, nil, fmt.Sprintf("bad BGP identifier %s (0.0.0.0)", routerId.String()))
	}
	if as == myAS && routerId == myId {
		return 0, NewMessageError(BGP_ERROR_OPEN_MESSAGE_ERROR, BGP_ERROR_SUB_BAD_BGP_IDENTIFIER, nil, fmt.Sprintf("bad BGP identifier %s", routerId.String()))
	}

	if expectedAS != 0 && as != expectedAS {
		return 0, NewMessageError(BGP_ERROR_OPEN_MESSAGE_ERROR, BGP_ERROR_SUB_BAD_PEER_AS, nil, fmt.Sprintf("as number mismatch expected %d, received %d", expectedAS, as))
	}

	if m.HoldTime < 3 && m.HoldTime != 0 {
		return 0, NewMessageError(BGP_ERROR_OPEN_MESSAGE_ERROR, BGP_ERROR_SUB_UNACCEPTABLE_HOLD_TIME, nil, fmt.Sprintf("unacceptable hold time %d", m.HoldTime))
	}
	return as, nil
}
