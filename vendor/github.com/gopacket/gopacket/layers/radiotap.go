// Copyright 2014 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"strings"

	"github.com/gopacket/gopacket"
)

// align calculates the number of bytes needed to align with the width
// on the offset, returning the number of bytes we need to skip to
// align to the offset (width).
func align(offset uint16, width uint16) uint16 {
	return ((((offset) + ((width) - 1)) & (^((width) - 1))) - offset)
}

type RadioTapPresent uint32

const (
	RadioTapPresentTSFT RadioTapPresent = 1 << iota
	RadioTapPresentFlags
	RadioTapPresentRate
	RadioTapPresentChannel
	RadioTapPresentFHSS
	RadioTapPresentDBMAntennaSignal
	RadioTapPresentDBMAntennaNoise
	RadioTapPresentLockQuality
	RadioTapPresentTxAttenuation
	RadioTapPresentDBTxAttenuation
	RadioTapPresentDBMTxPower
	RadioTapPresentAntenna
	RadioTapPresentDBAntennaSignal
	RadioTapPresentDBAntennaNoise
	RadioTapPresentRxFlags
	RadioTapPresentTxFlags
	RadioTapPresentRtsRetries
	RadioTapPresentDataRetries
	_
	RadioTapPresentMCS
	RadioTapPresentAMPDUStatus
	RadioTapPresentVHT
	RadiotapPresentTimestamp
	RadiotapPresentHE
	RadioTapPresentHEMU
	RadioTapPresentHEUOtherUser
	RadioTapPresentEXT RadioTapPresent = 1 << 31
)

func (r RadioTapPresent) TSFT() bool {
	return r&RadioTapPresentTSFT != 0
}
func (r RadioTapPresent) Flags() bool {
	return r&RadioTapPresentFlags != 0
}
func (r RadioTapPresent) Rate() bool {
	return r&RadioTapPresentRate != 0
}
func (r RadioTapPresent) Channel() bool {
	return r&RadioTapPresentChannel != 0
}
func (r RadioTapPresent) FHSS() bool {
	return r&RadioTapPresentFHSS != 0
}
func (r RadioTapPresent) DBMAntennaSignal() bool {
	return r&RadioTapPresentDBMAntennaSignal != 0
}
func (r RadioTapPresent) DBMAntennaNoise() bool {
	return r&RadioTapPresentDBMAntennaNoise != 0
}
func (r RadioTapPresent) LockQuality() bool {
	return r&RadioTapPresentLockQuality != 0
}
func (r RadioTapPresent) TxAttenuation() bool {
	return r&RadioTapPresentTxAttenuation != 0
}
func (r RadioTapPresent) DBTxAttenuation() bool {
	return r&RadioTapPresentDBTxAttenuation != 0
}
func (r RadioTapPresent) DBMTxPower() bool {
	return r&RadioTapPresentDBMTxPower != 0
}
func (r RadioTapPresent) Antenna() bool {
	return r&RadioTapPresentAntenna != 0
}
func (r RadioTapPresent) DBAntennaSignal() bool {
	return r&RadioTapPresentDBAntennaSignal != 0
}
func (r RadioTapPresent) DBAntennaNoise() bool {
	return r&RadioTapPresentDBAntennaNoise != 0
}
func (r RadioTapPresent) RxFlags() bool {
	return r&RadioTapPresentRxFlags != 0
}
func (r RadioTapPresent) TxFlags() bool {
	return r&RadioTapPresentTxFlags != 0
}
func (r RadioTapPresent) RtsRetries() bool {
	return r&RadioTapPresentRtsRetries != 0
}
func (r RadioTapPresent) DataRetries() bool {
	return r&RadioTapPresentDataRetries != 0
}
func (r RadioTapPresent) MCS() bool {
	return r&RadioTapPresentMCS != 0
}
func (r RadioTapPresent) AMPDUStatus() bool {
	return r&RadioTapPresentAMPDUStatus != 0
}
func (r RadioTapPresent) VHT() bool {
	return r&RadioTapPresentVHT != 0
}
func (r RadioTapPresent) Timestamp() bool {
	return r&RadiotapPresentTimestamp != 0
}
func (r RadioTapPresent) HE() bool {
	return r&RadiotapPresentHE != 0
}
func (r RadioTapPresent) HEMU() bool {
	return r&RadioTapPresentHEMU != 0
}
func (r RadioTapPresent) HEUOtherUser() bool {
	return r&RadioTapPresentHEUOtherUser != 0
}
func (r RadioTapPresent) EXT() bool {
	return r&RadioTapPresentEXT != 0
}

type RadioTapChannelFlags uint16

const (
	RadioTapChannelFlagsTurbo   RadioTapChannelFlags = 0x0010 // Turbo channel
	RadioTapChannelFlagsCCK     RadioTapChannelFlags = 0x0020 // CCK channel
	RadioTapChannelFlagsOFDM    RadioTapChannelFlags = 0x0040 // OFDM channel
	RadioTapChannelFlagsGhz2    RadioTapChannelFlags = 0x0080 // 2 GHz spectrum channel.
	RadioTapChannelFlagsGhz5    RadioTapChannelFlags = 0x0100 // 5 GHz spectrum channel
	RadioTapChannelFlagsPassive RadioTapChannelFlags = 0x0200 // Only passive scan allowed
	RadioTapChannelFlagsDynamic RadioTapChannelFlags = 0x0400 // Dynamic CCK-OFDM channel
	RadioTapChannelFlagsGFSK    RadioTapChannelFlags = 0x0800 // GFSK channel (FHSS PHY)
)

func (r RadioTapChannelFlags) Turbo() bool {
	return r&RadioTapChannelFlagsTurbo != 0
}
func (r RadioTapChannelFlags) CCK() bool {
	return r&RadioTapChannelFlagsCCK != 0
}
func (r RadioTapChannelFlags) OFDM() bool {
	return r&RadioTapChannelFlagsOFDM != 0
}
func (r RadioTapChannelFlags) Ghz2() bool {
	return r&RadioTapChannelFlagsGhz2 != 0
}
func (r RadioTapChannelFlags) Ghz5() bool {
	return r&RadioTapChannelFlagsGhz5 != 0
}
func (r RadioTapChannelFlags) Passive() bool {
	return r&RadioTapChannelFlagsPassive != 0
}
func (r RadioTapChannelFlags) Dynamic() bool {
	return r&RadioTapChannelFlagsDynamic != 0
}
func (r RadioTapChannelFlags) GFSK() bool {
	return r&RadioTapChannelFlagsGFSK != 0
}

// String provides a human readable string for RadioTapChannelFlags.
// This string is possibly subject to change over time; if you're storing this
// persistently, you should probably store the RadioTapChannelFlags value, not its string.
func (a RadioTapChannelFlags) String() string {
	var out bytes.Buffer
	if a.Turbo() {
		out.WriteString("Turbo,")
	}
	if a.CCK() {
		out.WriteString("CCK,")
	}
	if a.OFDM() {
		out.WriteString("OFDM,")
	}
	if a.Ghz2() {
		out.WriteString("Ghz2,")
	}
	if a.Ghz5() {
		out.WriteString("Ghz5,")
	}
	if a.Passive() {
		out.WriteString("Passive,")
	}
	if a.Dynamic() {
		out.WriteString("Dynamic,")
	}
	if a.GFSK() {
		out.WriteString("GFSK,")
	}

	if length := out.Len(); length > 0 {
		return string(out.Bytes()[:length-1]) // strip final comma
	}
	return ""
}

type RadioTapFlags uint8

const (
	RadioTapFlagsCFP           RadioTapFlags = 1 << iota // sent/received during CFP
	RadioTapFlagsShortPreamble                           // sent/received * with short * preamble
	RadioTapFlagsWEP                                     // sent/received * with WEP encryption
	RadioTapFlagsFrag                                    // sent/received * with fragmentation
	RadioTapFlagsFCS                                     // frame includes FCS
	RadioTapFlagsDatapad                                 // frame has padding between * 802.11 header and payload * (to 32-bit boundary)
	RadioTapFlagsBadFCS                                  // does not pass FCS check
	RadioTapFlagsShortGI                                 // HT short GI
)

func (r RadioTapFlags) CFP() bool {
	return r&RadioTapFlagsCFP != 0
}
func (r RadioTapFlags) ShortPreamble() bool {
	return r&RadioTapFlagsShortPreamble != 0
}
func (r RadioTapFlags) WEP() bool {
	return r&RadioTapFlagsWEP != 0
}
func (r RadioTapFlags) Frag() bool {
	return r&RadioTapFlagsFrag != 0
}
func (r RadioTapFlags) FCS() bool {
	return r&RadioTapFlagsFCS != 0
}
func (r RadioTapFlags) Datapad() bool {
	return r&RadioTapFlagsDatapad != 0
}
func (r RadioTapFlags) BadFCS() bool {
	return r&RadioTapFlagsBadFCS != 0
}
func (r RadioTapFlags) ShortGI() bool {
	return r&RadioTapFlagsShortGI != 0
}

// String provides a human readable string for RadioTapFlags.
// This string is possibly subject to change over time; if you're storing this
// persistently, you should probably store the RadioTapFlags value, not its string.
func (a RadioTapFlags) String() string {
	var out bytes.Buffer
	if a.CFP() {
		out.WriteString("CFP,")
	}
	if a.ShortPreamble() {
		out.WriteString("SHORT-PREAMBLE,")
	}
	if a.WEP() {
		out.WriteString("WEP,")
	}
	if a.Frag() {
		out.WriteString("FRAG,")
	}
	if a.FCS() {
		out.WriteString("FCS,")
	}
	if a.Datapad() {
		out.WriteString("DATAPAD,")
	}
	if a.ShortGI() {
		out.WriteString("SHORT-GI,")
	}

	if length := out.Len(); length > 0 {
		return string(out.Bytes()[:length-1]) // strip final comma
	}
	return ""
}

type RadioTapRate uint8

func (a RadioTapRate) String() string {
	return fmt.Sprintf("%v Mb/s", 0.5*float32(a))
}

type RadioTapChannelFrequency uint16

func (a RadioTapChannelFrequency) String() string {
	return fmt.Sprintf("%d MHz", a)
}

type RadioTapRxFlags uint16

const (
	RadioTapRxFlagsBadPlcp RadioTapRxFlags = 0x0002
)

func (self RadioTapRxFlags) BadPlcp() bool {
	return self&RadioTapRxFlagsBadPlcp != 0
}

func (self RadioTapRxFlags) String() string {
	if self.BadPlcp() {
		return "BADPLCP"
	}
	return ""
}

type RadioTapTxFlags uint16

const (
	RadioTapTxFlagsFail RadioTapTxFlags = 1 << iota
	RadioTapTxFlagsCTS
	RadioTapTxFlagsRTS
	RadioTapTxFlagsNoACK
)

func (self RadioTapTxFlags) Fail() bool  { return self&RadioTapTxFlagsFail != 0 }
func (self RadioTapTxFlags) CTS() bool   { return self&RadioTapTxFlagsCTS != 0 }
func (self RadioTapTxFlags) RTS() bool   { return self&RadioTapTxFlagsRTS != 0 }
func (self RadioTapTxFlags) NoACK() bool { return self&RadioTapTxFlagsNoACK != 0 }

func (self RadioTapTxFlags) String() string {
	var tokens []string
	if self.Fail() {
		tokens = append(tokens, "Fail")
	}
	if self.CTS() {
		tokens = append(tokens, "CTS")
	}
	if self.RTS() {
		tokens = append(tokens, "RTS")
	}
	if self.NoACK() {
		tokens = append(tokens, "NoACK")
	}
	return strings.Join(tokens, ",")
}

type RadioTapMCS struct {
	Known RadioTapMCSKnown
	Flags RadioTapMCSFlags
	MCS   uint8
}

func (self RadioTapMCS) String() string {
	var tokens []string
	if self.Known.Bandwidth() {
		token := "?"
		switch self.Flags.Bandwidth() {
		case 0:
			token = "20"
		case 1:
			token = "40"
		case 2:
			token = "40(20L)"
		case 3:
			token = "40(20U)"
		}
		tokens = append(tokens, token)
	}
	if self.Known.MCSIndex() {
		tokens = append(tokens, fmt.Sprintf("MCSIndex#%d", self.MCS))
	}
	if self.Known.GuardInterval() {
		if self.Flags.ShortGI() {
			tokens = append(tokens, fmt.Sprintf("shortGI"))
		} else {
			tokens = append(tokens, fmt.Sprintf("longGI"))
		}
	}
	if self.Known.HTFormat() {
		if self.Flags.Greenfield() {
			tokens = append(tokens, fmt.Sprintf("HT-greenfield"))
		} else {
			tokens = append(tokens, fmt.Sprintf("HT-mixed"))
		}
	}
	if self.Known.FECType() {
		if self.Flags.FECLDPC() {
			tokens = append(tokens, fmt.Sprintf("LDPC"))
		} else {
			tokens = append(tokens, fmt.Sprintf("BCC"))
		}
	}
	if self.Known.STBC() {
		tokens = append(tokens, fmt.Sprintf("STBC#%d", self.Flags.STBC()))
	}
	if self.Known.NESS() {
		num := 0
		if self.Known.NESS1() {
			num |= 0x02
		}
		if self.Flags.NESS0() {
			num |= 0x01
		}
		tokens = append(tokens, fmt.Sprintf("num-of-ESS#%d", num))
	}
	return strings.Join(tokens, ",")
}

type RadioTapMCSKnown uint8

const (
	RadioTapMCSKnownBandwidth RadioTapMCSKnown = 1 << iota
	RadioTapMCSKnownMCSIndex
	RadioTapMCSKnownGuardInterval
	RadioTapMCSKnownHTFormat
	RadioTapMCSKnownFECType
	RadioTapMCSKnownSTBC
	RadioTapMCSKnownNESS
	RadioTapMCSKnownNESS1
)

func (self RadioTapMCSKnown) Bandwidth() bool     { return self&RadioTapMCSKnownBandwidth != 0 }
func (self RadioTapMCSKnown) MCSIndex() bool      { return self&RadioTapMCSKnownMCSIndex != 0 }
func (self RadioTapMCSKnown) GuardInterval() bool { return self&RadioTapMCSKnownGuardInterval != 0 }
func (self RadioTapMCSKnown) HTFormat() bool      { return self&RadioTapMCSKnownHTFormat != 0 }
func (self RadioTapMCSKnown) FECType() bool       { return self&RadioTapMCSKnownFECType != 0 }
func (self RadioTapMCSKnown) STBC() bool          { return self&RadioTapMCSKnownSTBC != 0 }
func (self RadioTapMCSKnown) NESS() bool          { return self&RadioTapMCSKnownNESS != 0 }
func (self RadioTapMCSKnown) NESS1() bool         { return self&RadioTapMCSKnownNESS1 != 0 }

type RadioTapMCSFlags uint8

const (
	RadioTapMCSFlagsBandwidthMask RadioTapMCSFlags = 0x03
	RadioTapMCSFlagsShortGI                        = 0x04
	RadioTapMCSFlagsGreenfield                     = 0x08
	RadioTapMCSFlagsFECLDPC                        = 0x10
	RadioTapMCSFlagsSTBCMask                       = 0x60
	RadioTapMCSFlagsNESS0                          = 0x80
)

func (self RadioTapMCSFlags) Bandwidth() int {
	return int(self & RadioTapMCSFlagsBandwidthMask)
}
func (self RadioTapMCSFlags) ShortGI() bool    { return self&RadioTapMCSFlagsShortGI != 0 }
func (self RadioTapMCSFlags) Greenfield() bool { return self&RadioTapMCSFlagsGreenfield != 0 }
func (self RadioTapMCSFlags) FECLDPC() bool    { return self&RadioTapMCSFlagsFECLDPC != 0 }
func (self RadioTapMCSFlags) STBC() int {
	return int(self&RadioTapMCSFlagsSTBCMask) >> 5
}
func (self RadioTapMCSFlags) NESS0() bool { return self&RadioTapMCSFlagsNESS0 != 0 }

type RadioTapAMPDUStatus struct {
	Reference uint32
	Flags     RadioTapAMPDUStatusFlags
	CRC       uint8
}

func (self RadioTapAMPDUStatus) String() string {
	tokens := []string{
		fmt.Sprintf("ref#%x", self.Reference),
	}
	if self.Flags.ReportZerolen() && self.Flags.IsZerolen() {
		tokens = append(tokens, fmt.Sprintf("zero-length"))
	}
	if self.Flags.LastKnown() && self.Flags.IsLast() {
		tokens = append(tokens, "last")
	}
	if self.Flags.DelimCRCErr() {
		tokens = append(tokens, "delimiter CRC error")
	}
	if self.Flags.DelimCRCKnown() {
		tokens = append(tokens, fmt.Sprintf("delimiter-CRC=%02x", self.CRC))
	}
	return strings.Join(tokens, ",")
}

type RadioTapAMPDUStatusFlags uint16

const (
	RadioTapAMPDUStatusFlagsReportZerolen RadioTapAMPDUStatusFlags = 1 << iota
	RadioTapAMPDUIsZerolen
	RadioTapAMPDULastKnown
	RadioTapAMPDUIsLast
	RadioTapAMPDUDelimCRCErr
	RadioTapAMPDUDelimCRCKnown
)

func (self RadioTapAMPDUStatusFlags) ReportZerolen() bool {
	return self&RadioTapAMPDUStatusFlagsReportZerolen != 0
}
func (self RadioTapAMPDUStatusFlags) IsZerolen() bool   { return self&RadioTapAMPDUIsZerolen != 0 }
func (self RadioTapAMPDUStatusFlags) LastKnown() bool   { return self&RadioTapAMPDULastKnown != 0 }
func (self RadioTapAMPDUStatusFlags) IsLast() bool      { return self&RadioTapAMPDUIsLast != 0 }
func (self RadioTapAMPDUStatusFlags) DelimCRCErr() bool { return self&RadioTapAMPDUDelimCRCErr != 0 }
func (self RadioTapAMPDUStatusFlags) DelimCRCKnown() bool {
	return self&RadioTapAMPDUDelimCRCKnown != 0
}

type RadioTapVHT struct {
	Known      RadioTapVHTKnown
	Flags      RadioTapVHTFlags
	Bandwidth  uint8
	MCSNSS     [4]RadioTapVHTMCSNSS
	Coding     uint8
	GroupId    uint8
	PartialAID uint16
}

func (self RadioTapVHT) String() string {
	var tokens []string
	if self.Known.STBC() {
		if self.Flags.STBC() {
			tokens = append(tokens, "STBC")
		} else {
			tokens = append(tokens, "no STBC")
		}
	}
	if self.Known.TXOPPSNotAllowed() {
		if self.Flags.TXOPPSNotAllowed() {
			tokens = append(tokens, "TXOP doze not allowed")
		} else {
			tokens = append(tokens, "TXOP doze allowed")
		}
	}
	if self.Known.GI() {
		if self.Flags.SGI() {
			tokens = append(tokens, "short GI")
		} else {
			tokens = append(tokens, "long GI")
		}
	}
	if self.Known.SGINSYMDisambiguation() {
		if self.Flags.SGINSYMMod() {
			tokens = append(tokens, "NSYM mod 10=9")
		} else {
			tokens = append(tokens, "NSYM mod 10!=9 or no short GI")
		}
	}
	if self.Known.LDPCExtraOFDMSymbol() {
		if self.Flags.LDPCExtraOFDMSymbol() {
			tokens = append(tokens, "LDPC extra OFDM symbols")
		} else {
			tokens = append(tokens, "no LDPC extra OFDM symbols")
		}
	}
	if self.Known.Beamformed() {
		if self.Flags.Beamformed() {
			tokens = append(tokens, "beamformed")
		} else {
			tokens = append(tokens, "no beamformed")
		}
	}
	if self.Known.Bandwidth() {
		token := "?"
		switch self.Bandwidth & 0x1f {
		case 0:
			token = "20"
		case 1:
			token = "40"
		case 2:
			token = "40(20L)"
		case 3:
			token = "40(20U)"
		case 4:
			token = "80"
		case 5:
			token = "80(40L)"
		case 6:
			token = "80(40U)"
		case 7:
			token = "80(20LL)"
		case 8:
			token = "80(20LU)"
		case 9:
			token = "80(20UL)"
		case 10:
			token = "80(20UU)"
		case 11:
			token = "160"
		case 12:
			token = "160(80L)"
		case 13:
			token = "160(80U)"
		case 14:
			token = "160(40LL)"
		case 15:
			token = "160(40LU)"
		case 16:
			token = "160(40UL)"
		case 17:
			token = "160(40UU)"
		case 18:
			token = "160(20LLL)"
		case 19:
			token = "160(20LLU)"
		case 20:
			token = "160(20LUL)"
		case 21:
			token = "160(20LUU)"
		case 22:
			token = "160(20ULL)"
		case 23:
			token = "160(20ULU)"
		case 24:
			token = "160(20UUL)"
		case 25:
			token = "160(20UUU)"
		}
		tokens = append(tokens, token)
	}
	for i, MCSNSS := range self.MCSNSS {
		if MCSNSS.Present() {
			fec := "?"
			switch self.Coding & (1 << uint8(i)) {
			case 0:
				fec = "BCC"
			case 1:
				fec = "LDPC"
			}
			tokens = append(tokens, fmt.Sprintf("user%d(%s,%s)", i, MCSNSS.String(), fec))
		}
	}
	if self.Known.GroupId() {
		tokens = append(tokens,
			fmt.Sprintf("group=%d", self.GroupId))
	}
	if self.Known.PartialAID() {
		tokens = append(tokens,
			fmt.Sprintf("partial-AID=%d", self.PartialAID))
	}
	return strings.Join(tokens, ",")
}

type RadioTapVHTKnown uint16

const (
	RadioTapVHTKnownSTBC RadioTapVHTKnown = 1 << iota
	RadioTapVHTKnownTXOPPSNotAllowed
	RadioTapVHTKnownGI
	RadioTapVHTKnownSGINSYMDisambiguation
	RadioTapVHTKnownLDPCExtraOFDMSymbol
	RadioTapVHTKnownBeamformed
	RadioTapVHTKnownBandwidth
	RadioTapVHTKnownGroupId
	RadioTapVHTKnownPartialAID
)

func (self RadioTapVHTKnown) STBC() bool { return self&RadioTapVHTKnownSTBC != 0 }
func (self RadioTapVHTKnown) TXOPPSNotAllowed() bool {
	return self&RadioTapVHTKnownTXOPPSNotAllowed != 0
}
func (self RadioTapVHTKnown) GI() bool { return self&RadioTapVHTKnownGI != 0 }
func (self RadioTapVHTKnown) SGINSYMDisambiguation() bool {
	return self&RadioTapVHTKnownSGINSYMDisambiguation != 0
}
func (self RadioTapVHTKnown) LDPCExtraOFDMSymbol() bool {
	return self&RadioTapVHTKnownLDPCExtraOFDMSymbol != 0
}
func (self RadioTapVHTKnown) Beamformed() bool { return self&RadioTapVHTKnownBeamformed != 0 }
func (self RadioTapVHTKnown) Bandwidth() bool  { return self&RadioTapVHTKnownBandwidth != 0 }
func (self RadioTapVHTKnown) GroupId() bool    { return self&RadioTapVHTKnownGroupId != 0 }
func (self RadioTapVHTKnown) PartialAID() bool { return self&RadioTapVHTKnownPartialAID != 0 }

type RadioTapVHTFlags uint8

const (
	RadioTapVHTFlagsSTBC RadioTapVHTFlags = 1 << iota
	RadioTapVHTFlagsTXOPPSNotAllowed
	RadioTapVHTFlagsSGI
	RadioTapVHTFlagsSGINSYMMod
	RadioTapVHTFlagsLDPCExtraOFDMSymbol
	RadioTapVHTFlagsBeamformed
)

func (self RadioTapVHTFlags) STBC() bool { return self&RadioTapVHTFlagsSTBC != 0 }
func (self RadioTapVHTFlags) TXOPPSNotAllowed() bool {
	return self&RadioTapVHTFlagsTXOPPSNotAllowed != 0
}
func (self RadioTapVHTFlags) SGI() bool        { return self&RadioTapVHTFlagsSGI != 0 }
func (self RadioTapVHTFlags) SGINSYMMod() bool { return self&RadioTapVHTFlagsSGINSYMMod != 0 }
func (self RadioTapVHTFlags) LDPCExtraOFDMSymbol() bool {
	return self&RadioTapVHTFlagsLDPCExtraOFDMSymbol != 0
}
func (self RadioTapVHTFlags) Beamformed() bool { return self&RadioTapVHTFlagsBeamformed != 0 }

type RadioTapVHTMCSNSS uint8

func (self RadioTapVHTMCSNSS) Present() bool {
	return self&0x0F != 0
}

func (self RadioTapVHTMCSNSS) String() string {
	return fmt.Sprintf("NSS#%dMCS#%d", uint32(self&0xf), uint32(self>>4))
}

type RadiotapHE struct {
	Data1 RadiotapHEData1
	Data2 RadiotapHEData2
	Data3 RadiotapHEData3
	Data4 RadiotapHEData4
	Data5 RadiotapHEData5
	Data6 RadiotapHEData6
}

func (self RadiotapHE) String() string {
	var tokens []string
	tokens = append(tokens, fmt.Sprintf("HE PPDU Format: %v", self.Data1.HE_PPDUFormat()))
	if self.Data1.BSSColorKnown() {
		tokens = append(tokens, fmt.Sprintf("BSS Color: %d", self.Data3.BSSColor()))
	}
	if self.Data1.BeamChangeKnown() {
		if self.Data3.BeamChange() {
			tokens = append(tokens, "Beam Change")
		} else {
			tokens = append(tokens, "No Beam Change")
		}
	}
	if self.Data1.ULDLKnown() {
		if self.Data3.ULDL() {
			tokens = append(tokens, "UL")
		} else {
			tokens = append(tokens, "DL")
		}
	}
	if self.Data1.DataMCSKnown() {
		tokens = append(tokens, fmt.Sprintf("Data MCS: %d", self.Data3.DataMCS()))
	}
	if self.Data1.DataDCMKnown() {
		if self.Data3.DataDCM() {
			tokens = append(tokens, "Data DCM applied")
		} else {
			tokens = append(tokens, "Data DCM not applied")
		}
	}
	if self.Data1.CodingKnown() {
		tokens = append(tokens, fmt.Sprintf("Coding: %v", self.Data3.Coding()))
	}
	if self.Data1.LDPCExtraSymbolSegmentKnown() {
		if self.Data3.LDPCExtraSymbolSegment() {
			tokens = append(tokens, "LDPC Extra Symbol Segment")
		} else {
			tokens = append(tokens, "No LDPC Extra Symbol Segment")
		}
	}
	if self.Data1.STBCKnown() {
		if self.Data3.STBC() {
			tokens = append(tokens, "STBC")
		} else {
			tokens = append(tokens, "No STBC")
		}
	}
	switch self.Data1.HE_PPDUFormat() {
	case RadiotapHePpduFormatHE_SU:
	case RadiotapHePpduFormatHE_EXT_SU:
		if self.Data1.SpatialReuseKnown() {
			tokens = append(tokens, fmt.Sprintf("Spatial Reuse: %d", self.Data4&0x000f))
		}
	case RadiotapHePpduFormatHE_TRIG:
		if self.Data1.SpatialReuse1Known() {
			tokens = append(tokens, fmt.Sprintf("Spatial Reuse 1: %d", self.Data4&0x000f))
		}
		if self.Data1.SpatialReuse2Known() {
			tokens = append(tokens, fmt.Sprintf("Spatial Reuse 2: %d", self.Data4&0x00f0>>4))
		}
		if self.Data1.SpatialReuse3Known() {
			tokens = append(tokens, fmt.Sprintf("Spatial Reuse 3: %d", self.Data4&0x0f00>>8))
		}
		if self.Data1.SpatialReuse4Known() {
			tokens = append(tokens, fmt.Sprintf("Spatial Reuse 4: %d", self.Data4&0xf000>>12))
		}
	case RadiotapHePpduFormatHE_MU:
		if self.Data1.SpatialReuseKnown() {
			tokens = append(tokens, fmt.Sprintf("Spatial Reuse: %d", self.Data4&0x000f))
		}
		if self.Data1.StaIDKnown() {
			tokens = append(tokens, fmt.Sprintf("STA ID: %d", self.Data4&0x7ff0>>4))
		}
	}
	if self.Data1.DataBWRUAllocationKnown() {
		tokens = append(tokens, fmt.Sprintf("Data BW/RU Allocation: %s", self.Data5.DataBandwidth()))
	}
	if self.Data2.GIKnown() {
		tokens = append(tokens, fmt.Sprintf("GI: %v", self.Data5.Gi()))
	}
	if self.Data2.NumLTFKnown() {
		tokens = append(tokens, fmt.Sprintf("LTF Symbol size: %s", self.Data5.LTFSize()))
		tokens = append(tokens, fmt.Sprintf("Number of LTF symbols: %s", self.Data5.NumLTFSymbols()))
	}
	if self.Data2.PreFECPaddingFactorKnown() {
		tokens = append(tokens, fmt.Sprintf("Pre-FEC Padding Factor: %d", self.Data5.PreFECPaddingFactor()))
	}
	if self.Data2.TxBFKnown() {
		if self.Data5.TxBF() {
			tokens = append(tokens, "TxBF")
		} else {
			tokens = append(tokens, "No TxBF")
		}
	}
	if self.Data2.PEDisambiguityKnown() {
		if self.Data5.PEDisambiguity() {
			tokens = append(tokens, "PE Disambiguity")
		} else {
			tokens = append(tokens, "No PE Disambiguity")
		}
	}
	nSts := self.Data6.NSTS()
	if nSts > 0 {
		tokens = append(tokens, fmt.Sprintf("NSTS: %d", self.Data6.NSTS()))
	} else {
		tokens = append(tokens, "NSTS: unknown")
	}
	if self.Data1.DopplerKnown() {
		if self.Data6.Doppler() {
			tokens = append(tokens, "Doppler")
		} else {
			tokens = append(tokens, "No Doppler")
		}
	}
	if self.Data2.TXOPKnown() {
		tokens = append(tokens, fmt.Sprintf("TXOP: %d", self.Data6.TXOP()))
	}
	if self.Data2.MidamblePeriodicityKnown() {
		tokens = append(tokens, fmt.Sprintf("Midamble Periodicity: %v", self.Data6.MidamblePeriodicity()))
	}
	return strings.Join(tokens, ",")
}

type RadiotapHEData1 uint16

const (
	RadiotapHEData1_HE_PPDUFormatMask          RadiotapHEData1 = 0x0003
	RadiotapHEData1BSSColorKnown               RadiotapHEData1 = 0x0004
	RadiotapHEData1BeamChangeKnown             RadiotapHEData1 = 0x0008
	RadiotapHEData1ULDLKnown                   RadiotapHEData1 = 0x0010
	RadiotapHEData1DataMCSKnown                RadiotapHEData1 = 0x0020
	RadiotapHEData1DataDCMKnown                RadiotapHEData1 = 0x0040
	RadiotapHEData1CodingKnown                 RadiotapHEData1 = 0x0080
	RadiotapHEData1LDPCExtraSymbolSegmentKnown RadiotapHEData1 = 0x0100
	RadiotapHEData1STBCKnown                   RadiotapHEData1 = 0x0200
	RadiotapHEData1SpatialReuseKnown           RadiotapHEData1 = 0x0400
	RadiotapHEData1SpatialReuse1Known          RadiotapHEData1 = 0x0400
	RadiotapHEData1SpatialReuse2Known          RadiotapHEData1 = 0x0800
	RadiotapHEData1StaIDKnown                  RadiotapHEData1 = 0x8000
	RadiotapHEData1SpatialReuse3Known          RadiotapHEData1 = 0x1000
	RadiotapHEData1SpatialReuse4Known          RadiotapHEData1 = 0x2000
	RadiotapHEData1DataBWRUAllocationKnown     RadiotapHEData1 = 0x4000
	RadiotapHEData1DopplerKnown                RadiotapHEData1 = 0x8000
)

func (self RadiotapHEData1) HE_PPDUFormat() RadiotapHePpduFormat {
	return RadiotapHePpduFormat(self & 0x0003)
}

func (self RadiotapHEData1) BSSColorKnown() bool {
	return self&RadiotapHEData1BSSColorKnown != 0
}

func (self RadiotapHEData1) BeamChangeKnown() bool {
	return self&RadiotapHEData1BeamChangeKnown != 0
}

func (self RadiotapHEData1) ULDLKnown() bool {
	return self&RadiotapHEData1ULDLKnown != 0
}

func (self RadiotapHEData1) DataMCSKnown() bool {
	return self&RadiotapHEData1DataMCSKnown != 0
}

func (self RadiotapHEData1) DataDCMKnown() bool {
	return self&RadiotapHEData1DataDCMKnown != 0
}

func (self RadiotapHEData1) CodingKnown() bool {
	return self&RadiotapHEData1CodingKnown != 0
}

func (self RadiotapHEData1) LDPCExtraSymbolSegmentKnown() bool {
	return self&RadiotapHEData1LDPCExtraSymbolSegmentKnown != 0
}

func (self RadiotapHEData1) STBCKnown() bool {
	return self&RadiotapHEData1STBCKnown != 0
}

func (self RadiotapHEData1) SpatialReuseKnown() bool {
	return self&RadiotapHEData1SpatialReuseKnown != 0
}

func (self RadiotapHEData1) SpatialReuse1Known() bool {
	return self&RadiotapHEData1SpatialReuse1Known != 0
}

func (self RadiotapHEData1) SpatialReuse2Known() bool {
	return self&RadiotapHEData1SpatialReuse2Known != 0
}

func (self RadiotapHEData1) StaIDKnown() bool {
	return self&RadiotapHEData1StaIDKnown != 0
}

func (self RadiotapHEData1) SpatialReuse3Known() bool {
	return self&RadiotapHEData1SpatialReuse3Known != 0
}

func (self RadiotapHEData1) SpatialReuse4Known() bool {
	return self&RadiotapHEData1SpatialReuse4Known != 0
}

func (self RadiotapHEData1) DataBWRUAllocationKnown() bool {
	return self&RadiotapHEData1DataBWRUAllocationKnown != 0
}

func (self RadiotapHEData1) DopplerKnown() bool {
	return self&RadiotapHEData1DopplerKnown != 0
}

type RadiotapHePpduFormat uint8

const (
	RadiotapHePpduFormatHE_SU RadiotapHePpduFormat = iota
	RadiotapHePpduFormatHE_EXT_SU
	RadiotapHePpduFormatHE_MU
	RadiotapHePpduFormatHE_TRIG
)

func (self RadiotapHePpduFormat) String() string {
	switch self {
	case RadiotapHePpduFormatHE_SU:
		return "HE SU"
	case RadiotapHePpduFormatHE_EXT_SU:
		return "HE EXT SU"
	case RadiotapHePpduFormatHE_MU:
		return "HE MU"
	case RadiotapHePpduFormatHE_TRIG:
		return "HE TRIG"
	}
	return fmt.Sprintf("HE Unknown(%d)", self)
}

type RadiotapHEData2 uint16

const (
	RadiotapHEData2PriSec80MHzKnown         RadiotapHEData2 = 0x0001
	RadiotapHEData2GIKnown                  RadiotapHEData2 = 0x0002
	RadiotapHEData2NumLTFKnown              RadiotapHEData2 = 0x0004
	RadiotapHEData2PreFECPaddingFactorKnown RadiotapHEData2 = 0x0008
	RadiotapHEData2TxBFKnown                RadiotapHEData2 = 0x0010
	RadiotapHEData2PEDisambiguityKnown      RadiotapHEData2 = 0x0020
	RadiotapHEData2TXOPKnown                RadiotapHEData2 = 0x0040
	RadiotapHEData2MidamblePeriodicityKnown RadiotapHEData2 = 0x0080
	RadiotapHEData2RUAllocationOffset       RadiotapHEData2 = 0x3f00
	RadiotapHEData2RUAllocationOffsetKnown  RadiotapHEData2 = 0x4000
	RadiotapHEData2PriSec80MHz              RadiotapHEData2 = 0x8000
)

func (self RadiotapHEData2) PriSec80MHzKnown() bool {
	return self&RadiotapHEData2PriSec80MHzKnown != 0
}

func (self RadiotapHEData2) GIKnown() bool {
	return self&RadiotapHEData2GIKnown != 0
}

func (self RadiotapHEData2) NumLTFKnown() bool {
	return self&RadiotapHEData2NumLTFKnown != 0
}

func (self RadiotapHEData2) PreFECPaddingFactorKnown() bool {
	return self&RadiotapHEData2PreFECPaddingFactorKnown != 0
}

func (self RadiotapHEData2) TxBFKnown() bool {
	return self&RadiotapHEData2TxBFKnown != 0
}

func (self RadiotapHEData2) PEDisambiguityKnown() bool {
	return self&RadiotapHEData2PEDisambiguityKnown != 0
}

func (self RadiotapHEData2) TXOPKnown() bool {
	return self&RadiotapHEData2TXOPKnown != 0
}

func (self RadiotapHEData2) MidamblePeriodicityKnown() bool {
	return self&RadiotapHEData2MidamblePeriodicityKnown != 0
}

func (self RadiotapHEData2) RUAllocationOffset() int {
	return int(self&RadiotapHEData2RUAllocationOffset) >> 8
}

func (self RadiotapHEData2) RUAllocationOffsetKnown() bool {
	return self&RadiotapHEData2RUAllocationOffsetKnown != 0
}

func (self RadiotapHEData2) PriSec80MHz() bool {
	return self&RadiotapHEData2PriSec80MHz != 0
}

type RadiotapHEPriSec80MHz bool

type RadiotapHEData3 uint16

const (
	RadiotapHEData3BSSColorMask           RadiotapHEData3 = 0x003F
	RadiotapHEData3BeamChange             RadiotapHEData3 = 0x0040
	RadiotapHEData3ULDL                   RadiotapHEData3 = 0x0080
	RadiotapHEData3DataMCSMask            RadiotapHEData3 = 0x0F00
	RadiotapHEData3DataDCM                RadiotapHEData3 = 0x1000
	RadiotapHEData3Coding                 RadiotapHEData3 = 0x2000
	RadiotapHEData3LDPCEXtraSymbolSegment RadiotapHEData3 = 0x4000
	RadiotapHEData3STBC                   RadiotapHEData3 = 0x8000
)

func (self RadiotapHEData3) BSSColor() int {
	return int(self & RadiotapHEData3BSSColorMask)
}

func (self RadiotapHEData3) BeamChange() bool {
	return self&RadiotapHEData3BeamChange != 0
}

func (self RadiotapHEData3) ULDL() bool {
	return self&RadiotapHEData3ULDL != 0
}

func (self RadiotapHEData3) DataMCS() uint8 {
	return uint8((self & RadiotapHEData3DataMCSMask) >> 8)
}

func (self RadiotapHEData3) DataDCM() bool {
	return self&RadiotapHEData3DataDCM != 0
}

func (self RadiotapHEData3) Coding() RadiotapHECoding {
	return self&RadiotapHEData3Coding != 0
}

func (self RadiotapHEData3) LDPCExtraSymbolSegment() bool {
	return self&RadiotapHEData3LDPCEXtraSymbolSegment != 0
}

func (self RadiotapHEData3) STBC() bool {
	return self&RadiotapHEData3STBC != 0
}

type RadiotapHECoding bool

const (
	RadiotapHECodingBCC  RadiotapHECoding = false
	RadiotapHECodingLDPC RadiotapHECoding = true
)

type RadiotapHEData4 uint16

type RadiotapHEData5 uint16

const (
	RadiotapHEData5DataBandwidthMask   RadiotapHEData5 = 0x000F
	RadiotapHEData5GI                  RadiotapHEData5 = 0x0030
	RadiotapHEData5LTFSize             RadiotapHEData5 = 0x00C0
	RadiotapHEData5NumLTFSymbols       RadiotapHEData5 = 0x0700
	RadiotapHEData5PreFECPaddingFactor RadiotapHEData5 = 0x3000
	RadiotapHEData5TxBF                RadiotapHEData5 = 0x4000
	RadiotapHEData5PEDisambiguity      RadiotapHEData5 = 0x8000
)

type DataBandwidth uint8

const (
	DataBandwidth20 DataBandwidth = iota
	DataBandwidth40
	DataBandwidth80
	DataBandwidth160
	DataBandwidth26ToneRU
	DataBandwidth52ToneRU
	DataBandwidth106ToneRU
	DataBandwidth242ToneRU
	DataBandwidth484ToneRU
	DataBandwidth996ToneRU
	DataBandwidth2x996ToneRU
)

func (db DataBandwidth) String() string {
	switch db {
	case DataBandwidth20:
		return "20"
	case DataBandwidth40:
		return "40"
	case DataBandwidth80:
		return "80"
	case DataBandwidth160:
		return "160/80+80"
	case DataBandwidth26ToneRU:
		return "26-tone RU"
	case DataBandwidth52ToneRU:
		return "52-tone RU"
	case DataBandwidth106ToneRU:
		return "106-tone RU"
	case DataBandwidth242ToneRU:
		return "242-tone RU"
	case DataBandwidth484ToneRU:
		return "484-tone RU"
	case DataBandwidth996ToneRU:
		return "996-tone RU"
	case DataBandwidth2x996ToneRU:
		return "2x996-tone RU"
	default:
		return "Unknown"
	}
}

func (self RadiotapHEData5) DataBandwidth() DataBandwidth {
	return DataBandwidth(self & RadiotapHEData5DataBandwidthMask)
}

func (self RadiotapHEData5) Gi() Gi {
	return Gi((self & RadiotapHEData5GI) >> 4)
}

func (self RadiotapHEData5) LTFSize() LTF {
	return LTF((self & RadiotapHEData5LTFSize) >> 6)
}

func (self RadiotapHEData5) NumLTFSymbols() NLTF {
	return NLTF((self & RadiotapHEData5NumLTFSymbols) >> 8)
}

func (self RadiotapHEData5) PreFECPaddingFactor() uint8 {
	return uint8((self & RadiotapHEData5PreFECPaddingFactor) >> 12)
}

func (self RadiotapHEData5) TxBF() bool {
	return self&RadiotapHEData5TxBF != 0
}

func (self RadiotapHEData5) PEDisambiguity() bool {
	return self&RadiotapHEData5PEDisambiguity != 0
}

type Gi uint8

const (
	Gi_0_8us Gi = iota
	Gi_1_6us
	Gi_3_2us
	Gi_reserved
)

func (gi Gi) String() string {
	switch gi {
	case Gi_0_8us:
		return "0.8us"
	case Gi_1_6us:
		return "1.6us"
	case Gi_3_2us:
		return "3.2us"
	default:
		return "Reserved"
	}
}

type LTF uint8

const (
	LTF_unknown LTF = iota
	LTF_1x
	LTF_2x
	LTF_4x
)

func (ltf LTF) String() string {
	switch ltf {
	case LTF_unknown:
		return "Unknown"
	case LTF_1x:
		return "1x"
	case LTF_2x:
		return "2x"
	case LTF_4x:
		return "4x"
	default:
		return "Unknown"
	}
}

type NLTF uint8

const (
	NLTF_1x NLTF = iota
	NLTF_2x
	NLTF_4x
	NLTF_6x
	NLTF_8x
	NLTF_reserved
)

func (nltf NLTF) String() string {
	switch nltf {
	case NLTF_1x:
		return "1x"
	case NLTF_2x:
		return "2x"
	case NLTF_4x:
		return "4x"
	case NLTF_6x:
		return "6x"
	case NLTF_8x:
		return "8x"
	default:
		return "Reserved"
	}
}

type MidamblePeriodicity uint8

const (
	MidamblePeriodicity_10 MidamblePeriodicity = iota
	MidamblePeriodicity_20
)

func (mp MidamblePeriodicity) String() string {
	switch mp {
	case MidamblePeriodicity_10:
		return "10"
	case MidamblePeriodicity_20:
		return "20"
	default:
		return "Unknown"
	}
}

type RadiotapHEData6 uint16

const (
	RadiotapHEData6NSTS             RadiotapHEData6 = 0x000F
	RadiotapHEData6Doppler          RadiotapHEData6 = 0x0010
	RadiotapHEData6TXOP             RadiotapHEData6 = 0x7F00
	RadiotapHEData6MidamblePeriodic RadiotapHEData6 = 0x8000
)

func (self RadiotapHEData6) NSTS() int {
	return int(self & RadiotapHEData6NSTS)
}

func (self RadiotapHEData6) Doppler() bool {
	return self&RadiotapHEData6Doppler != 0
}

func (self RadiotapHEData6) TXOP() int {
	return int((self & RadiotapHEData6TXOP) >> 8)
}

func (self RadiotapHEData6) MidamblePeriodicity() MidamblePeriodicity {
	return MidamblePeriodicity((self & RadiotapHEData6MidamblePeriodic) >> 15)
}

func decodeRadioTap(data []byte, p gopacket.PacketBuilder) error {
	d := &RadioTap{}
	// TODO: Should we set LinkLayer here? And implement LinkFlow
	return decodingLayerDecoder(d, data, p)
}

type RadioTap struct {
	BaseLayer

	// Version 0. Only increases for drastic changes, introduction of compatible new fields does not count.
	Version uint8
	// Length of the whole header in bytes, including it_version, it_pad, it_len, and data fields.
	Length uint16
	// Present is a bitmap telling which fields are present. Set bit 31 (0x80000000) to extend the bitmap by another 32 bits. Additional extensions are made by setting bit 31.
	Present RadioTapPresent
	// TSFT: value in microseconds of the MAC's 64-bit 802.11 Time Synchronization Function timer when the first bit of the MPDU arrived at the MAC. For received frames, only.
	TSFT  uint64
	Flags RadioTapFlags
	// Rate Tx/Rx data rate
	Rate RadioTapRate
	// ChannelFrequency Tx/Rx frequency in MHz, followed by flags
	ChannelFrequency RadioTapChannelFrequency
	ChannelFlags     RadioTapChannelFlags
	// FHSS For frequency-hopping radios, the hop set (first byte) and pattern (second byte).
	FHSS uint16
	// DBMAntennaSignal RF signal power at the antenna, decibel difference from one milliwatt.
	DBMAntennaSignal int8
	// DBMAntennaNoise RF noise power at the antenna, decibel difference from one milliwatt.
	DBMAntennaNoise int8
	// LockQuality Quality of Barker code lock. Unitless. Monotonically nondecreasing with "better" lock strength. Called "Signal Quality" in datasheets.
	LockQuality uint16
	// TxAttenuation Transmit power expressed as unitless distance from max power set at factory calibration.  0 is max power. Monotonically nondecreasing with lower power levels.
	TxAttenuation uint16
	// DBTxAttenuation Transmit power expressed as decibel distance from max power set at factory calibration.  0 is max power.  Monotonically nondecreasing with lower power levels.
	DBTxAttenuation uint16
	// DBMTxPower Transmit power expressed as dBm (decibels from a 1 milliwatt reference). This is the absolute power level measured at the antenna port.
	DBMTxPower int8
	// Antenna Unitless indication of the Rx/Tx antenna for this packet. The first antenna is antenna 0.
	Antenna uint8
	// DBAntennaSignal RF signal power at the antenna, decibel difference from an arbitrary, fixed reference.
	DBAntennaSignal uint8
	// DBAntennaNoise RF noise power at the antenna, decibel difference from an arbitrary, fixed reference point.
	DBAntennaNoise uint8
	//
	RxFlags     RadioTapRxFlags
	TxFlags     RadioTapTxFlags
	RtsRetries  uint8
	DataRetries uint8
	MCS         RadioTapMCS
	AMPDUStatus RadioTapAMPDUStatus
	VHT         RadioTapVHT
	HE          RadiotapHE
}

func (m *RadioTap) LayerType() gopacket.LayerType { return LayerTypeRadioTap }

func (m *RadioTap) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	dataLen := uint16(len(data))
	if dataLen < 8 {
		df.SetTruncated()
		return errors.New("RadioTap too small")
	}
	m.Version = uint8(data[0])
	m.Length = binary.LittleEndian.Uint16(data[2:4])
	m.Present = RadioTapPresent(binary.LittleEndian.Uint32(data[4:8]))

	// Truncate the length to avoid panics, might be smaller due to corruption or loss
	if m.Length > dataLen {
		m.Length = dataLen
	}

	offset := uint16(4)

	for (binary.LittleEndian.Uint32(data[offset:offset+4]) & 0x80000000) != 0 {
		// This parser only handles standard radiotap namespace,
		// and expects all fields are packed in the first it_present.
		// Extended bitmap will be just ignored.
		offset += 4
	}
	offset += 4 // skip the bitmap

	if m.Present.TSFT() {
		offset += align(offset, 8)
		m.TSFT = binary.LittleEndian.Uint64(data[offset : offset+8])
		offset += 8
	}
	if m.Present.Flags() {
		m.Flags = RadioTapFlags(data[offset])
		offset++
	}
	if m.Present.Rate() {
		m.Rate = RadioTapRate(data[offset])
		offset++
	}
	if m.Present.Channel() {
		offset += align(offset, 2)
		m.ChannelFrequency = RadioTapChannelFrequency(binary.LittleEndian.Uint16(data[offset : offset+2]))
		offset += 2
		m.ChannelFlags = RadioTapChannelFlags(binary.LittleEndian.Uint16(data[offset : offset+2]))
		offset += 2
	}
	if m.Present.FHSS() {
		m.FHSS = binary.LittleEndian.Uint16(data[offset : offset+2])
		offset += 2
	}
	if m.Present.DBMAntennaSignal() {
		m.DBMAntennaSignal = int8(data[offset])
		offset++
	}
	if m.Present.DBMAntennaNoise() {
		m.DBMAntennaNoise = int8(data[offset])
		offset++
	}
	if m.Present.LockQuality() {
		offset += align(offset, 2)
		m.LockQuality = binary.LittleEndian.Uint16(data[offset : offset+2])
		offset += 2
	}
	if m.Present.TxAttenuation() {
		offset += align(offset, 2)
		m.TxAttenuation = binary.LittleEndian.Uint16(data[offset : offset+2])
		offset += 2
	}
	if m.Present.DBTxAttenuation() {
		offset += align(offset, 2)
		m.DBTxAttenuation = binary.LittleEndian.Uint16(data[offset : offset+2])
		offset += 2
	}
	if m.Present.DBMTxPower() {
		m.DBMTxPower = int8(data[offset])
		offset++
	}
	if m.Present.Antenna() {
		m.Antenna = uint8(data[offset])
		offset++
	}
	if m.Present.DBAntennaSignal() {
		m.DBAntennaSignal = uint8(data[offset])
		offset++
	}
	if m.Present.DBAntennaNoise() {
		m.DBAntennaNoise = uint8(data[offset])
		offset++
	}
	if m.Present.RxFlags() {
		offset += align(offset, 2)
		m.RxFlags = RadioTapRxFlags(binary.LittleEndian.Uint16(data[offset:]))
		offset += 2
	}
	if m.Present.TxFlags() {
		offset += align(offset, 2)
		m.TxFlags = RadioTapTxFlags(binary.LittleEndian.Uint16(data[offset:]))
		offset += 2
	}
	if m.Present.RtsRetries() {
		m.RtsRetries = uint8(data[offset])
		offset++
	}
	if m.Present.DataRetries() {
		m.DataRetries = uint8(data[offset])
		offset++
	}
	if m.Present.MCS() {
		m.MCS = RadioTapMCS{
			RadioTapMCSKnown(data[offset]),
			RadioTapMCSFlags(data[offset+1]),
			uint8(data[offset+2]),
		}
		offset += 3
	}
	if m.Present.AMPDUStatus() {
		offset += align(offset, 4)
		m.AMPDUStatus = RadioTapAMPDUStatus{
			Reference: binary.LittleEndian.Uint32(data[offset:]),
			Flags:     RadioTapAMPDUStatusFlags(binary.LittleEndian.Uint16(data[offset+4:])),
			CRC:       uint8(data[offset+6]),
		}
		offset += 8
	}
	if m.Present.VHT() {
		offset += align(offset, 2)
		m.VHT = RadioTapVHT{
			Known:     RadioTapVHTKnown(binary.LittleEndian.Uint16(data[offset:])),
			Flags:     RadioTapVHTFlags(data[offset+2]),
			Bandwidth: uint8(data[offset+3]),
			MCSNSS: [4]RadioTapVHTMCSNSS{
				RadioTapVHTMCSNSS(data[offset+4]),
				RadioTapVHTMCSNSS(data[offset+5]),
				RadioTapVHTMCSNSS(data[offset+6]),
				RadioTapVHTMCSNSS(data[offset+7]),
			},
			Coding:     uint8(data[offset+8]),
			GroupId:    uint8(data[offset+9]),
			PartialAID: binary.LittleEndian.Uint16(data[offset+10:]),
		}
		offset += 12
	}
	if m.Present.Timestamp() {
		offset += align(offset, 8)
		offset += 12
	}
	if m.Present.HE() {
		offset += align(offset, 2)
		m.HE = RadiotapHE{
			Data1: RadiotapHEData1(binary.LittleEndian.Uint16(data[offset:])),
			Data2: RadiotapHEData2(binary.LittleEndian.Uint16(data[offset+2:])),
			Data3: RadiotapHEData3(binary.LittleEndian.Uint16(data[offset+4:])),
			Data4: RadiotapHEData4(binary.LittleEndian.Uint16(data[offset+6:])),
			Data5: RadiotapHEData5(binary.LittleEndian.Uint16(data[offset+8:])),
			Data6: RadiotapHEData6(binary.LittleEndian.Uint16(data[offset+10:])),
		}
		offset += 12
	}

	payload := data[m.Length:]

	// Remove non standard padding used by some Wi-Fi drivers
	if m.Flags.Datapad() &&
		payload[0]&0xC == 0x8 { //&& // Data frame
		headlen := 24
		if payload[0]&0x8C == 0x88 { // QoS
			headlen += 2
		}
		if payload[1]&0x3 == 0x3 { // 4 addresses
			headlen += 2
		}
		if headlen%4 == 2 {
			payload = append(payload[:headlen], payload[headlen+2:len(payload)]...)
		}
	}

	if !m.Flags.FCS() {
		// Dot11.DecodeFromBytes() expects FCS present and performs a hard chop on the checksum
		// If a user is handing in subslices or packets from a buffered stream, the capacity of the slice
		// may extend beyond the len, rather than expecting callers to enforce cap==len on every packet
		// we take the hit in this one case and do a reallocation.  If the user DOES enforce cap==len
		// then the reallocation will happen anyway on the append.  This is requried because the append
		// write to the memory directly after the payload if there is sufficient capacity, which callers
		// may not expect.
		reallocPayload := make([]byte, len(payload)+4)
		copy(reallocPayload[0:len(payload)], payload)
		h := crc32.NewIEEE()
		h.Write(payload)
		binary.LittleEndian.PutUint32(reallocPayload[len(payload):], h.Sum32())
		payload = reallocPayload
	}
	m.BaseLayer = BaseLayer{Contents: data[:m.Length], Payload: payload}

	return nil
}

func (m RadioTap) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	buf := make([]byte, 1024)

	buf[0] = m.Version
	buf[1] = 0

	binary.LittleEndian.PutUint32(buf[4:8], uint32(m.Present))

	offset := uint16(4)

	for (binary.LittleEndian.Uint32(buf[offset:offset+4]) & 0x80000000) != 0 {
		offset += 4
	}

	offset += 4

	if m.Present.TSFT() {
		offset += align(offset, 8)
		binary.LittleEndian.PutUint64(buf[offset:offset+8], m.TSFT)
		offset += 8
	}

	if m.Present.Flags() {
		buf[offset] = uint8(m.Flags)
		offset++
	}

	if m.Present.Rate() {
		buf[offset] = uint8(m.Rate)
		offset++
	}

	if m.Present.Channel() {
		offset += align(offset, 2)
		binary.LittleEndian.PutUint16(buf[offset:offset+2], uint16(m.ChannelFrequency))
		offset += 2
		binary.LittleEndian.PutUint16(buf[offset:offset+2], uint16(m.ChannelFlags))
		offset += 2
	}

	if m.Present.FHSS() {
		binary.LittleEndian.PutUint16(buf[offset:offset+2], m.FHSS)
		offset += 2
	}

	if m.Present.DBMAntennaSignal() {
		buf[offset] = byte(m.DBMAntennaSignal)
		offset++
	}

	if m.Present.DBMAntennaNoise() {
		buf[offset] = byte(m.DBMAntennaNoise)
		offset++
	}

	if m.Present.LockQuality() {
		offset += align(offset, 2)
		binary.LittleEndian.PutUint16(buf[offset:offset+2], m.LockQuality)
		offset += 2
	}

	if m.Present.TxAttenuation() {
		offset += align(offset, 2)
		binary.LittleEndian.PutUint16(buf[offset:offset+2], m.TxAttenuation)
		offset += 2
	}

	if m.Present.DBTxAttenuation() {
		offset += align(offset, 2)
		binary.LittleEndian.PutUint16(buf[offset:offset+2], m.DBTxAttenuation)
		offset += 2
	}

	if m.Present.DBMTxPower() {
		buf[offset] = byte(m.DBMTxPower)
		offset++
	}

	if m.Present.Antenna() {
		buf[offset] = uint8(m.Antenna)
		offset++
	}

	if m.Present.DBAntennaSignal() {
		buf[offset] = uint8(m.DBAntennaSignal)
		offset++
	}

	if m.Present.DBAntennaNoise() {
		buf[offset] = uint8(m.DBAntennaNoise)
		offset++
	}

	if m.Present.RxFlags() {
		offset += align(offset, 2)
		binary.LittleEndian.PutUint16(buf[offset:offset+2], uint16(m.RxFlags))
		offset += 2
	}

	if m.Present.TxFlags() {
		offset += align(offset, 2)
		binary.LittleEndian.PutUint16(buf[offset:offset+2], uint16(m.TxFlags))
		offset += 2
	}

	if m.Present.RtsRetries() {
		buf[offset] = m.RtsRetries
		offset++
	}

	if m.Present.DataRetries() {
		buf[offset] = m.DataRetries
		offset++
	}

	if m.Present.MCS() {
		buf[offset] = uint8(m.MCS.Known)
		buf[offset+1] = uint8(m.MCS.Flags)
		buf[offset+2] = uint8(m.MCS.MCS)

		offset += 3
	}

	if m.Present.AMPDUStatus() {
		offset += align(offset, 4)

		binary.LittleEndian.PutUint32(buf[offset:offset+4], m.AMPDUStatus.Reference)
		binary.LittleEndian.PutUint16(buf[offset+4:offset+6], uint16(m.AMPDUStatus.Flags))

		buf[offset+6] = m.AMPDUStatus.CRC

		offset += 8
	}

	if m.Present.VHT() {
		offset += align(offset, 2)

		binary.LittleEndian.PutUint16(buf[offset:], uint16(m.VHT.Known))

		buf[offset+2] = uint8(m.VHT.Flags)
		buf[offset+3] = uint8(m.VHT.Bandwidth)
		buf[offset+4] = uint8(m.VHT.MCSNSS[0])
		buf[offset+5] = uint8(m.VHT.MCSNSS[1])
		buf[offset+6] = uint8(m.VHT.MCSNSS[2])
		buf[offset+7] = uint8(m.VHT.MCSNSS[3])
		buf[offset+8] = uint8(m.VHT.Coding)
		buf[offset+9] = uint8(m.VHT.GroupId)

		binary.LittleEndian.PutUint16(buf[offset+10:offset+12], m.VHT.PartialAID)

		offset += 12
	}

	packetBuf, err := b.PrependBytes(int(offset))

	if err != nil {
		return err
	}

	if opts.FixLengths {
		m.Length = offset
	}

	binary.LittleEndian.PutUint16(buf[2:4], m.Length)

	copy(packetBuf, buf)

	return nil
}

func (m *RadioTap) CanDecode() gopacket.LayerClass    { return LayerTypeRadioTap }
func (m *RadioTap) NextLayerType() gopacket.LayerType { return LayerTypeDot11 }
