// Copyright 2014, 2018, 2024 GoPacket Authors. All rights reserved.
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
	"net"
	"strings"

	"github.com/gopacket/gopacket"
)

// DNSClass defines the class associated with a request/response.  Different DNS
// classes can be thought of as an array of parallel namespace trees.
type DNSClass uint16

// DNSClass known values.
const (
	DNSClassIN  DNSClass = 1   // Internet
	DNSClassCS  DNSClass = 2   // the CSNET class (Obsolete)
	DNSClassCH  DNSClass = 3   // the CHAOS class
	DNSClassHS  DNSClass = 4   // Hesiod [Dyer 87]
	DNSClassAny DNSClass = 255 // AnyClass
)

func (dc DNSClass) String() string {
	switch dc {
	default:
		return "Unknown"
	case DNSClassIN:
		return "IN"
	case DNSClassCS:
		return "CS"
	case DNSClassCH:
		return "CH"
	case DNSClassHS:
		return "HS"
	case DNSClassAny:
		return "Any"
	}
}

// DNSType defines the type of data being requested/returned in a
// question/answer.
type DNSType uint16

// DNSType known values.
const (
	DNSTypeA      DNSType = 1   // a host address
	DNSTypeNS     DNSType = 2   // an authoritative name server
	DNSTypeMD     DNSType = 3   // a mail destination (Obsolete - use MX)
	DNSTypeMF     DNSType = 4   // a mail forwarder (Obsolete - use MX)
	DNSTypeCNAME  DNSType = 5   // the canonical name for an alias
	DNSTypeSOA    DNSType = 6   // marks the start of a zone of authority
	DNSTypeMB     DNSType = 7   // a mailbox domain name (EXPERIMENTAL)
	DNSTypeMG     DNSType = 8   // a mail group member (EXPERIMENTAL)
	DNSTypeMR     DNSType = 9   // a mail rename domain name (EXPERIMENTAL)
	DNSTypeNULL   DNSType = 10  // a null RR (EXPERIMENTAL)
	DNSTypeWKS    DNSType = 11  // a well known service description
	DNSTypePTR    DNSType = 12  // a domain name pointer
	DNSTypeHINFO  DNSType = 13  // host information
	DNSTypeMINFO  DNSType = 14  // mailbox or mail list information
	DNSTypeMX     DNSType = 15  // mail exchange
	DNSTypeTXT    DNSType = 16  // text strings
	DNSTypeAAAA   DNSType = 28  // a IPv6 host address [RFC3596]
	DNSTypeSRV    DNSType = 33  // server discovery [RFC2782] [RFC6195]
	DNSTypeNAPTR  DNSType = 35  // naming authority pointer [RFC3403]
	DNSTypeOPT    DNSType = 41  // OPT Pseudo-RR [RFC6891]
	DNSTypeRRSIG  DNSType = 46  // RRSIG RR [RFC4034][RFC3755]
	DNSTypeDNSKEY DNSType = 48  // DNSKEY RR [RFC4034][RFC3755]
	DNSTypeSVCB   DNSType = 64  // SVCB DNS RR [RFC9460]
	DNSTypeHTTPS  DNSType = 65  // HTTPS RR [RFC9460]
	DNSTypeURI    DNSType = 256 // URI RR [RFC7553]
)

func (dt DNSType) String() string {
	switch dt {
	default:
		return "Unknown"
	case DNSTypeA:
		return "A"
	case DNSTypeNS:
		return "NS"
	case DNSTypeMD:
		return "MD"
	case DNSTypeMF:
		return "MF"
	case DNSTypeCNAME:
		return "CNAME"
	case DNSTypeSOA:
		return "SOA"
	case DNSTypeMB:
		return "MB"
	case DNSTypeMG:
		return "MG"
	case DNSTypeMR:
		return "MR"
	case DNSTypeNULL:
		return "NULL"
	case DNSTypeWKS:
		return "WKS"
	case DNSTypePTR:
		return "PTR"
	case DNSTypeHINFO:
		return "HINFO"
	case DNSTypeMINFO:
		return "MINFO"
	case DNSTypeMX:
		return "MX"
	case DNSTypeTXT:
		return "TXT"
	case DNSTypeAAAA:
		return "AAAA"
	case DNSTypeSRV:
		return "SRV"
	case DNSTypeNAPTR:
		return "NAPTR"
	case DNSTypeOPT:
		return "OPT"
	case DNSTypeRRSIG:
		return "RRSIG"
	case DNSTypeDNSKEY:
		return "DNSKEY"
	case DNSTypeSVCB:
		return "SVCB"
	case DNSTypeHTTPS:
		return "HTTPS"
	case DNSTypeURI:
		return "URI"
	}
}

// DNSResponseCode provides response codes for question answers.
type DNSResponseCode uint8

// DNSResponseCode known values.
const (
	DNSResponseCodeNoErr     DNSResponseCode = 0  // No error
	DNSResponseCodeFormErr   DNSResponseCode = 1  // Format Error                       [RFC1035]
	DNSResponseCodeServFail  DNSResponseCode = 2  // Server Failure                     [RFC1035]
	DNSResponseCodeNXDomain  DNSResponseCode = 3  // Non-Existent Domain                [RFC1035]
	DNSResponseCodeNotImp    DNSResponseCode = 4  // Not Implemented                    [RFC1035]
	DNSResponseCodeRefused   DNSResponseCode = 5  // Query Refused                      [RFC1035]
	DNSResponseCodeYXDomain  DNSResponseCode = 6  // Name Exists when it should not     [RFC2136]
	DNSResponseCodeYXRRSet   DNSResponseCode = 7  // RR Set Exists when it should not   [RFC2136]
	DNSResponseCodeNXRRSet   DNSResponseCode = 8  // RR Set that should exist does not  [RFC2136]
	DNSResponseCodeNotAuth   DNSResponseCode = 9  // Server Not Authoritative for zone  [RFC2136]
	DNSResponseCodeNotZone   DNSResponseCode = 10 // Name not contained in zone         [RFC2136]
	DNSResponseCodeBadVers   DNSResponseCode = 16 // Bad OPT Version                    [RFC2671]
	DNSResponseCodeBadSig    DNSResponseCode = 16 // TSIG Signature Failure             [RFC2845]
	DNSResponseCodeBadKey    DNSResponseCode = 17 // Key not recognized                 [RFC2845]
	DNSResponseCodeBadTime   DNSResponseCode = 18 // Signature out of time window       [RFC2845]
	DNSResponseCodeBadMode   DNSResponseCode = 19 // Bad TKEY Mode                      [RFC2930]
	DNSResponseCodeBadName   DNSResponseCode = 20 // Duplicate key name                 [RFC2930]
	DNSResponseCodeBadAlg    DNSResponseCode = 21 // Algorithm not supported            [RFC2930]
	DNSResponseCodeBadTruc   DNSResponseCode = 22 // Bad Truncation                     [RFC4635]
	DNSResponseCodeBadCookie DNSResponseCode = 23 // Bad/missing Server Cookie          [RFC7873]
)

func (drc DNSResponseCode) String() string {
	switch drc {
	default:
		return "Unknown"
	case DNSResponseCodeNoErr:
		return "No Error"
	case DNSResponseCodeFormErr:
		return "Format Error"
	case DNSResponseCodeServFail:
		return "Server Failure"
	case DNSResponseCodeNXDomain:
		return "Non-Existent Domain"
	case DNSResponseCodeNotImp:
		return "Not Implemented"
	case DNSResponseCodeRefused:
		return "Query Refused"
	case DNSResponseCodeYXDomain:
		return "Name Exists when it should not"
	case DNSResponseCodeYXRRSet:
		return "RR Set Exists when it should not"
	case DNSResponseCodeNXRRSet:
		return "RR Set that should exist does not"
	case DNSResponseCodeNotAuth:
		return "Server Not Authoritative for zone"
	case DNSResponseCodeNotZone:
		return "Name not contained in zone"
	case DNSResponseCodeBadVers:
		return "Bad OPT Version"
	case DNSResponseCodeBadKey:
		return "Key not recognized"
	case DNSResponseCodeBadTime:
		return "Signature out of time window"
	case DNSResponseCodeBadMode:
		return "Bad TKEY Mode"
	case DNSResponseCodeBadName:
		return "Duplicate key name"
	case DNSResponseCodeBadAlg:
		return "Algorithm not supported"
	case DNSResponseCodeBadTruc:
		return "Bad Truncation"
	case DNSResponseCodeBadCookie:
		return "Bad Cookie"
	}
}

// DNSOpCode defines a set of different operation types.
type DNSOpCode uint8

// DNSOpCode known values.
const (
	DNSOpCodeQuery  DNSOpCode = 0 // Query                  [RFC1035]
	DNSOpCodeIQuery DNSOpCode = 1 // Inverse Query Obsolete [RFC3425]
	DNSOpCodeStatus DNSOpCode = 2 // Status                 [RFC1035]
	DNSOpCodeNotify DNSOpCode = 4 // Notify                 [RFC1996]
	DNSOpCodeUpdate DNSOpCode = 5 // Update                 [RFC2136]
)

func (doc DNSOpCode) String() string {
	switch doc {
	default:
		return "Unknown"
	case DNSOpCodeQuery:
		return "Query"
	case DNSOpCodeIQuery:
		return "Inverse Query"
	case DNSOpCodeStatus:
		return "Status"
	case DNSOpCodeNotify:
		return "Notify"
	case DNSOpCodeUpdate:
		return "Update"
	}
}

// DNS is specified in RFC 1034 / RFC 1035
// +---------------------+
// |        Header       |
// +---------------------+
// |       Question      | the question for the name server
// +---------------------+
// |        Answer       | RRs answering the question
// +---------------------+
// |      Authority      | RRs pointing toward an authority
// +---------------------+
// |      Additional     | RRs holding additional information
// +---------------------+
//
//  DNS Header
//  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                      ID                       |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    QDCOUNT                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    ANCOUNT                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    NSCOUNT                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                    ARCOUNT                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

// DNS contains data from a single Domain Name Service packet.
//
// DNS name fields (such as DNSQuestion.Name and DNSResourceRecord.Name) hold
// names in dotted presentation form. When a packet decoded by this layer is
// re-serialized without changing a name field, the original wire label
// boundaries are preserved, so a label that legitimately contains a literal
// dot (for example a DNS-SD instance label "foo.bar") round-trips correctly.
//
// A name field that is newly constructed or changed is instead parsed as a
// presentation name, where a dot separates labels. To embed a literal dot,
// backslash, or arbitrary byte in a single label, use the escapes "\.", "\\",
// or "\DDD" (three decimal digits). A decoded name copied verbatim into a
// different field loses its preserved boundaries and is re-parsed this way, so
// any literal dot in it must be escaped first.
type DNS struct {
	BaseLayer

	// Header fields
	ID     uint16
	QR     bool
	OpCode DNSOpCode

	AA bool  // Authoritative answer
	TC bool  // Truncated
	RD bool  // Recursion desired
	RA bool  // Recursion available
	Z  uint8 // Reserved for future use

	ResponseCode DNSResponseCode
	QDCount      uint16 // Number of questions to expect
	ANCount      uint16 // Number of answers to expect
	NSCount      uint16 // Number of authorities to expect
	ARCount      uint16 // Number of additional records to expect

	// Entries
	Questions   []DNSQuestion
	Answers     []DNSResourceRecord
	Authorities []DNSResourceRecord
	Additionals []DNSResourceRecord

	// buffer for doing name decoding.  We use a single reusable buffer to avoid
	// name decoding on a single object via multiple DecodeFromBytes calls
	// requiring constant allocation of small byte slices.
	buffer []byte
}

// LayerType returns gopacket.LayerTypeDNS.
func (d *DNS) LayerType() gopacket.LayerType { return LayerTypeDNS }

// decodeDNS decodes the byte slice into a DNS type. It also
// setups the application Layer in PacketBuilder.
func decodeDNS(data []byte, p gopacket.PacketBuilder) error {
	d := &DNS{}
	err := d.DecodeFromBytes(data, p)
	if err != nil {
		return err
	}
	p.AddLayer(d)
	p.SetApplicationLayer(d)
	return nil
}

// DecodeFromBytes decodes the slice into the DNS struct.
func (d *DNS) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	d.buffer = d.buffer[:0]

	if len(data) < 12 {
		df.SetTruncated()
		return errDNSPacketTooShort
	}

	// since there are no further layers, the baselayer's content is
	// pointing to this layer
	d.BaseLayer = BaseLayer{Contents: data[:len(data)]}
	d.ID = binary.BigEndian.Uint16(data[:2])
	d.QR = data[2]&0x80 != 0
	d.OpCode = DNSOpCode(data[2]>>3) & 0x0F
	d.AA = data[2]&0x04 != 0
	d.TC = data[2]&0x02 != 0
	d.RD = data[2]&0x01 != 0
	d.RA = data[3]&0x80 != 0
	d.Z = uint8(data[3]>>4) & 0x7
	d.ResponseCode = DNSResponseCode(data[3] & 0xF)
	d.QDCount = binary.BigEndian.Uint16(data[4:6])
	d.ANCount = binary.BigEndian.Uint16(data[6:8])
	d.NSCount = binary.BigEndian.Uint16(data[8:10])
	d.ARCount = binary.BigEndian.Uint16(data[10:12])

	d.Questions = d.Questions[:0]
	d.Answers = d.Answers[:0]
	d.Authorities = d.Authorities[:0]
	d.Additionals = d.Additionals[:0]

	offset := 12
	var err error
	for i := 0; i < int(d.QDCount); i++ {
		var q DNSQuestion
		if offset, err = q.decode(data, offset, df, &d.buffer); err != nil {
			return err
		}
		d.Questions = append(d.Questions, q)
	}

	// For some horrible reason, if we do the obvious thing in this loop:
	//   var r DNSResourceRecord
	//   if blah := r.decode(blah); err != nil {
	//     return err
	//   }
	//   d.Foo = append(d.Foo, r)
	// the Go compiler thinks that 'r' escapes to the heap, causing a malloc for
	// every Answer, Authority, and Additional.  To get around this, we do
	// something really silly:  we append an empty resource record to our slice,
	// then use the last value in the slice to call decode.  Since the value is
	// already in the slice, there's no WAY it can escape... on the other hand our
	// code is MUCH uglier :(
	for i := 0; i < int(d.ANCount); i++ {
		d.Answers = append(d.Answers, DNSResourceRecord{})
		if offset, err = d.Answers[i].decode(data, offset, df, &d.buffer); err != nil {
			d.Answers = d.Answers[:i] // strip off erroneous value
			return err
		}
	}
	for i := 0; i < int(d.NSCount); i++ {
		d.Authorities = append(d.Authorities, DNSResourceRecord{})
		if offset, err = d.Authorities[i].decode(data, offset, df, &d.buffer); err != nil {
			d.Authorities = d.Authorities[:i] // strip off erroneous value
			return err
		}
	}
	for i := 0; i < int(d.ARCount); i++ {
		d.Additionals = append(d.Additionals, DNSResourceRecord{})
		if offset, err = d.Additionals[i].decode(data, offset, df, &d.buffer); err != nil {
			d.Additionals = d.Additionals[:i] // strip off erroneous value
			return err
		}
		// extract extended RCODE from OPT RRs, RFC 6891 section 6.1.3
		if d.Additionals[i].Type == DNSTypeOPT {
			d.ResponseCode = DNSResponseCode(uint8(d.ResponseCode) | uint8(d.Additionals[i].TTL>>20&0xF0))
		}
	}

	if uint16(len(d.Questions)) != d.QDCount {
		return errDecodeQueryBadQDCount
	} else if uint16(len(d.Answers)) != d.ANCount {
		return errDecodeQueryBadANCount
	} else if uint16(len(d.Authorities)) != d.NSCount {
		return errDecodeQueryBadNSCount
	} else if uint16(len(d.Additionals)) != d.ARCount {
		return errDecodeQueryBadARCount
	}
	return nil
}

// CanDecode implements gopacket.DecodingLayer.
func (d *DNS) CanDecode() gopacket.LayerClass {
	return LayerTypeDNS
}

// NextLayerType implements gopacket.DecodingLayer.
func (d *DNS) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

// Payload returns nil.
func (d *DNS) Payload() []byte {
	return nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// dnsNameLabels is the sequence of raw wire labels (each without its length
// octet) that a DNS name decoded to. It is recorded only when a name needs its
// exact label boundaries preserved across a decode -> serialize round trip.
type dnsNameLabels [][]byte

// dnsNameMeta preserves one decoded DNS name's wire label boundaries together
// with a snapshot of the decoded presentation bytes. Serialization reproduces
// the exact labels only while the public name field still equals orig; once the
// caller changes the name, the metadata is treated as stale.
type dnsNameMeta struct {
	labels dnsNameLabels
	orig   []byte
}

// dnsRecordNameMeta holds the preserved name metadata for one resource record.
// It is allocated lazily, only when a decoded name actually contains a label
// boundary that the dotted presentation form cannot represent, so the common
// case costs a single nil pointer rather than a metadata field per name. A
// record carries at most its owner name plus the one or two DNS names in its
// RDATA, so rdata holds the single RDATA name (NS, CNAME, PTR, MX, SRV, the
// NAPTR Replacement, the SVCB/HTTPS Target, the RRSIG SignerName, or the SOA
// MName), and rdata2 holds the SOA RName.
type dnsRecordNameMeta struct {
	name   dnsNameMeta
	rdata  dnsNameMeta
	rdata2 dnsNameMeta
}

// newDNSNameMeta builds metadata for a decoded name. Call it only when labels
// is non-nil (the name needs boundary preservation).
func newDNSNameMeta(name []byte, labels dnsNameLabels) dnsNameMeta {
	return dnsNameMeta{labels: labels, orig: bytes.Clone(name)}
}

// dnsLabelNeedsPreservation reports whether a wire label cannot be represented
// unambiguously in the dotted presentation Name. '.' and '\' are the only
// metacharacters of presentation form: the label separator and the escape
// introducer (see encodeDNSPresentationName). A label containing either would be
// mis-split or mis-escaped if flattened into Name and re-encoded, so its exact
// wire boundaries must be preserved. Every other byte round-trips literally.
func dnsLabelNeedsPreservation(label []byte) bool {
	for _, b := range label {
		if b == '.' || b == '\\' {
			return true
		}
	}
	return false
}

// collectDNSWireLabels reads the literal wire labels of a name in data[offset:end].
// It stops at the first compression pointer or out-of-range length, returning the
// labels gathered so far; the caller appends any pointed-to labels separately.
func collectDNSWireLabels(data []byte, offset, end int) dnsNameLabels {
	var labels dnsNameLabels
	for offset < end {
		if offset >= len(data) || data[offset]&0xc0 != 0 {
			return labels
		}
		next := offset + int(data[offset]) + 1
		if next > end || next > len(data) {
			return labels
		}
		labels = append(labels, bytes.Clone(data[offset+1:next]))
		offset = next
	}
	return labels
}

// encodeDNSPresentationName encodes a presentation-form DNS name (where '.'
// separates labels and '\' introduces an escape) into wire format. When data
// is non-nil it writes the encoding starting at offset; when data is nil it only
// measures. Either way it returns the wire size, so a caller sizes a buffer with
// data == nil and then fills it with identical logic: one source of truth for
// the grammar, with no separate size/write passes to keep in sync.
//
// Recognized escapes are \. \\ and \DDD (three decimal digits, value <= 255);
// any other \X is preserved literally as backslash plus X.
func encodeDNSPresentationName(name []byte, data []byte, offset int) (int, error) {
	start := offset
	if len(name) == 0 || (len(name) == 1 && name[0] == '.') {
		if data != nil {
			data[offset] = 0x00
		}
		return 1, nil
	}
	labelOffset := offset // reserved slot for the current label's length octet
	offset++
	labelLen := 0
	lastWasSeparator := false
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c == '.' {
			if labelLen > 63 {
				return 0, errDNSNameTooLong
			}
			if data != nil {
				data[labelOffset] = byte(labelLen)
			}
			labelOffset = offset
			offset++
			labelLen = 0
			lastWasSeparator = true
			continue
		}
		if c == '\\' {
			if i+1 >= len(name) {
				return 0, errDNSNameInvalidIndex
			}
			next := name[i+1]
			switch {
			case next == '.' || next == '\\':
				if data != nil {
					data[offset] = next
				}
				offset++
				labelLen++
				i++
			case next >= '0' && next <= '9':
				if i+3 >= len(name) || name[i+2] < '0' || name[i+2] > '9' || name[i+3] < '0' || name[i+3] > '9' {
					return 0, errDNSNameInvalidIndex
				}
				v := int(name[i+1]-'0')*100 + int(name[i+2]-'0')*10 + int(name[i+3]-'0')
				if v > 255 {
					return 0, errDNSNameInvalidIndex
				}
				if data != nil {
					data[offset] = byte(v)
				}
				offset++
				labelLen++
				i += 3
			default:
				if data != nil {
					data[offset] = c
					data[offset+1] = next
				}
				offset += 2
				labelLen += 2
				i++
			}
			lastWasSeparator = false
			continue
		}
		if data != nil {
			data[offset] = c
		}
		offset++
		labelLen++
		lastWasSeparator = false
	}
	if labelLen > 63 {
		return 0, errDNSNameTooLong
	}
	if !lastWasSeparator {
		if data != nil {
			data[labelOffset] = byte(labelLen)
		}
	} else {
		offset = labelOffset
	}
	if data != nil {
		data[offset] = 0x00
	}
	size := offset + 1 - start
	if size > 255 {
		return 0, errDNSNameTooLong
	}
	return size, nil
}

func dnsNameLabelsSize(labels dnsNameLabels) (int, error) {
	size := 1
	for _, label := range labels {
		if len(label) > 63 {
			return 0, errDNSNameTooLong
		}
		size += 1 + len(label)
		if size > 255 {
			return 0, errDNSNameTooLong
		}
	}
	return size, nil
}

// usePreservedDNSLabels reports whether the preserved wire labels in m should be
// used to encode name: only when metadata exists, recorded labels, and the public
// name field still matches the decoded snapshot (i.e. the caller did not change it).
func usePreservedDNSLabels(name []byte, m *dnsNameMeta) bool {
	return m != nil && m.labels != nil && bytes.Equal(name, m.orig)
}

func dnsNameSize(name []byte, m *dnsNameMeta) (int, error) {
	if usePreservedDNSLabels(name, m) {
		return dnsNameLabelsSize(m.labels)
	}
	return encodeDNSPresentationName(name, nil, 0)
}

func recSize(rr *DNSResourceRecord) (int, error) {
	switch rr.Type {
	case DNSTypeA:
		return 4, nil
	case DNSTypeAAAA:
		return 16, nil
	case DNSTypeNS:
		return dnsNameSize(rr.NS, rr.rdataMeta())
	case DNSTypeCNAME:
		return dnsNameSize(rr.CNAME, rr.rdataMeta())
	case DNSTypePTR:
		return dnsNameSize(rr.PTR, rr.rdataMeta())
	case DNSTypeSOA:
		mNameSize, err := dnsNameSize(rr.SOA.MName, rr.rdataMeta())
		if err != nil {
			return 0, err
		}
		rNameSize, err := dnsNameSize(rr.SOA.RName, rr.rdata2Meta())
		if err != nil {
			return 0, err
		}
		return mNameSize + rNameSize + 20, nil
	case DNSTypeMX:
		nameSize, err := dnsNameSize(rr.MX.Name, rr.rdataMeta())
		if err != nil {
			return 0, err
		}
		return 2 + nameSize, nil
	case DNSTypeTXT:
		l := len(rr.TXTs)
		for _, txt := range rr.TXTs {
			l += len(txt)
		}
		return l, nil
	case DNSTypeSRV:
		nameSize, err := dnsNameSize(rr.SRV.Name, rr.rdataMeta())
		if err != nil {
			return 0, err
		}
		return 6 + nameSize, nil
	case DNSTypeNAPTR:
		replacementSize, err := dnsNameSize(rr.NAPTR.Replacement, rr.rdataMeta())
		if err != nil {
			return 0, err
		}
		return 4 + 1 + len(rr.NAPTR.Flags) + 1 + len(rr.NAPTR.Service) + 1 + len(rr.NAPTR.Regexp) + replacementSize, nil
	case DNSTypeURI:
		return 4 + len(rr.URI.Target), nil
	case DNSTypeOPT:
		l := len(rr.OPT) * 4
		for _, opt := range rr.OPT {
			l += len(opt.Data)
		}
		return l, nil
	case DNSTypeRRSIG:
		return rr.RRSIG.size(rr.rdataMeta())
	case DNSTypeDNSKEY:
		return rr.DNSKEY.size(), nil
	case DNSTypeSVCB, DNSTypeHTTPS:
		return rr.SVCB.size(rr.rdataMeta())
	}

	return 0, nil
}

func computeSize(recs []DNSResourceRecord) (int, error) {
	sz := 0
	for _, rr := range recs {
		v, err := dnsNameSize(rr.Name, rr.ownerMeta())
		if err != nil {
			return 0, err
		}
		sz += v + 10

		rSz, err := recSize(&rr)
		if err != nil {
			return 0, err
		}
		sz += rSz
	}
	return sz, nil
}

// SerializeTo writes the serialized form of this layer into the
// SerializationBuffer, implementing gopacket.SerializableLayer.
func (d *DNS) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	dsz := 0
	for _, q := range d.Questions {
		qSize, err := dnsNameSize(q.Name, q.nameMeta)
		if err != nil {
			return err
		}
		dsz += qSize + 4
	}
	answersSize, err := computeSize(d.Answers)
	if err != nil {
		return err
	}
	dsz += answersSize
	authoritiesSize, err := computeSize(d.Authorities)
	if err != nil {
		return err
	}
	dsz += authoritiesSize
	additionalsSize, err := computeSize(d.Additionals)
	if err != nil {
		return err
	}
	dsz += additionalsSize

	bytes, err := b.PrependBytes(12 + dsz)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint16(bytes, d.ID)
	bytes[2] = byte((b2i(d.QR) << 7) | (int(d.OpCode) << 3) | (b2i(d.AA) << 2) | (b2i(d.TC) << 1) | b2i(d.RD))
	bytes[3] = byte((b2i(d.RA) << 7) | (int(d.Z) << 4) | int(d.ResponseCode))

	if opts.FixLengths {
		d.QDCount = uint16(len(d.Questions))
		d.ANCount = uint16(len(d.Answers))
		d.NSCount = uint16(len(d.Authorities))
		d.ARCount = uint16(len(d.Additionals))
	}
	binary.BigEndian.PutUint16(bytes[4:], d.QDCount)
	binary.BigEndian.PutUint16(bytes[6:], d.ANCount)
	binary.BigEndian.PutUint16(bytes[8:], d.NSCount)
	binary.BigEndian.PutUint16(bytes[10:], d.ARCount)

	off := 12
	for _, qd := range d.Questions {
		n, err := qd.encode(bytes, off)
		if err != nil {
			return err
		}
		off += n
	}

	for i := range d.Answers {
		// done this way so we can modify DNSResourceRecord to fix
		// lengths if requested
		qa := &d.Answers[i]
		n, err := qa.encode(bytes, off, opts)
		if err != nil {
			return err
		}
		off += n
	}

	for i := range d.Authorities {
		qa := &d.Authorities[i]
		n, err := qa.encode(bytes, off, opts)
		if err != nil {
			return err
		}
		off += n
	}
	for i := range d.Additionals {
		qa := &d.Additionals[i]
		n, err := qa.encode(bytes, off, opts)
		if err != nil {
			return err
		}
		off += n
	}

	return nil
}

const maxRecursionLevel = 255

func decodeName(data []byte, offset int, buffer *[]byte, level int) ([]byte, dnsNameLabels, int, error) {
	if level > maxRecursionLevel {
		return nil, nil, 0, errMaxRecursion
	} else if offset >= len(data) {
		return nil, nil, 0, errDNSNameOffsetTooHigh
	} else if offset < 0 {
		return nil, nil, 0, errDNSNameOffsetNegative
	}
	start := len(*buffer)
	index := offset
	var labels dnsNameLabels
	if data[index] == 0x00 {
		return nil, labels, index + 1, nil
	}
loop:
	for data[index] != 0x00 {
		switch data[index] & 0xc0 {
		default:
			/* RFC 1035
			   A domain name represented as a sequence of labels, where
			   each label consists of a length octet followed by that
			   number of octets.  The domain name terminates with the
			   zero length octet for the null label of the root.  Note
			   that this field may be an odd number of octets; no
			   padding is used.
			*/
			index2 := index + int(data[index]) + 1
			if index2-offset > 255 {
				return nil, nil, 0, errDNSNameTooLong
			} else if index2 < index+1 || index2 > len(data) {
				return nil, nil, 0, errDNSNameInvalidIndex
			}
			label := data[index+1 : index2]
			*buffer = append(*buffer, '.')
			*buffer = append(*buffer, label...)
			if labels != nil {
				labels = append(labels, bytes.Clone(label))
			} else if dnsLabelNeedsPreservation(label) {
				labels = collectDNSWireLabels(data, offset, index2)
			}
			index = index2

		case 0xc0:
			/* RFC 1035
			   The pointer takes the form of a two octet sequence.

			   The first two bits are ones.  This allows a pointer to
			   be distinguished from a label, since the label must
			   begin with two zero bits because labels are restricted
			   to 63 octets or less.  (The 10 and 01 combinations are
			   reserved for future use.)  The OFFSET field specifies
			   an offset from the start of the message (i.e., the
			   first octet of the ID field in the domain header).  A
			   zero offset specifies the first byte of the ID field,
			   etc.

			   The compression scheme allows a domain name in a message to be
			   represented as either:
			      - a sequence of labels ending in a zero octet
			      - a pointer
			      - a sequence of labels ending with a pointer
			*/
			if index+2 > len(data) {
				return nil, nil, 0, errDNSPointerOffsetTooHigh
			}
			offsetp := int(binary.BigEndian.Uint16(data[index:index+2]) & 0x3fff)
			if offsetp > len(data) {
				return nil, nil, 0, errDNSPointerOffsetTooHigh
			}
			// This looks a little tricky, but actually isn't.  Because of how
			// decodeName is written, calling it appends the decoded name to the
			// current buffer.  We already have the start of the buffer, then, so
			// once this call is done buffer[start:] will contain our full name.
			pointedName, pointedLabels, _, err := decodeName(data, offsetp, buffer, level+1)
			if err != nil {
				return nil, nil, 0, err
			}
			if pointedLabels != nil {
				if labels == nil {
					labels = collectDNSWireLabels(data, offset, index)
				}
				labels = append(labels, pointedLabels...)
			} else if labels != nil && len(pointedName) > 0 {
				for _, lbl := range bytes.Split(pointedName, []byte{'.'}) {
					labels = append(labels, bytes.Clone(lbl))
				}
			}
			index++ // pointer is two bytes, so add an extra byte here.
			break loop
		/* EDNS, or other DNS option ? */
		case 0x40: // RFC 2673
			return nil, nil, 0, fmt.Errorf("qname '0x40' - RFC 2673 unsupported yet (data=%x index=%d)",
				data[index], index)

		case 0x80:
			return nil, nil, 0, fmt.Errorf("qname '0x80' unsupported yet (data=%x index=%d)",
				data[index], index)
		}
		if index >= len(data) {
			return nil, nil, 0, errDNSIndexOutOfRange
		}
	}
	if len(*buffer) <= start {
		return (*buffer)[start:], labels, index + 1, nil
	}
	return (*buffer)[start+1:], labels, index + 1, nil
}

// DNSQuestion wraps a single request (question) within a DNS query.
type DNSQuestion struct {
	Name  []byte
	Type  DNSType
	Class DNSClass

	// nameMeta preserves the wire label boundaries of a decoded Name; it is set
	// only when Name contains a label with a literal dot or backslash. See DNS.
	nameMeta *dnsNameMeta
}

func (q *DNSQuestion) decode(data []byte, offset int, df gopacket.DecodeFeedback, buffer *[]byte) (int, error) {
	name, labels, endq, err := decodeName(data, offset, buffer, 1)
	if err != nil {
		return 0, err
	}

	if len(data) < endq+4 {
		return 0, errors.New("DNS question too small")
	}

	q.Name = name
	if labels != nil {
		meta := newDNSNameMeta(name, labels)
		q.nameMeta = &meta
	}
	q.Type = DNSType(binary.BigEndian.Uint16(data[endq : endq+2]))
	q.Class = DNSClass(binary.BigEndian.Uint16(data[endq+2 : endq+4]))

	return endq + 4, nil
}

func (q *DNSQuestion) encode(data []byte, offset int) (int, error) {
	nSz, err := encodeDNSName(q.Name, q.nameMeta, data, offset)
	if err != nil {
		return 0, err
	}
	noff := offset + nSz
	binary.BigEndian.PutUint16(data[noff:], uint16(q.Type))
	binary.BigEndian.PutUint16(data[noff+2:], uint16(q.Class))
	return nSz + 4, nil
}

//  DNSResourceRecord
//  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                                               |
//  /                                               /
//  /                      NAME                     /
//  |                                               |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                      TYPE                     |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                     CLASS                     |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                      TTL                      |
//  |                                               |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//  |                   RDLENGTH                    |
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
//  /                     RDATA                     /
//  /                                               /
//  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

// DNSResourceRecord wraps the data from a single DNS resource within a
// response.
type DNSResourceRecord struct {
	// Header
	Name  []byte
	Type  DNSType
	Class DNSClass
	TTL   uint32

	// RDATA Raw Values
	DataLength uint16
	Data       []byte

	// RDATA Decoded Values
	IP             net.IP
	NS, CNAME, PTR []byte
	TXTs           [][]byte
	SOA            DNSSOA
	SRV            DNSSRV
	MX             DNSMX
	NAPTR          DNSNAPTR
	OPT            []DNSOPT // See RFC 6891, section 6.1.2
	RRSIG          DNSRRSIG // See RFC 4034, section 3.1
	DNSKEY         DNSKEY   // See RFC 4034, section 2.1
	SVCB           DNSSVCB  // See RFC 9460, this contains both SVCB and HTTPS
	URI            DNSURI

	// Undecoded TXT for backward compatibility
	TXT []byte

	// names preserves wire label boundaries for this record's owner and RDATA
	// names; allocated lazily, only when a name needs it. See DNS and dnsRecordNameMeta.
	names *dnsRecordNameMeta
}

// ensureNameMeta returns the record's preserved-name metadata block, allocating it
// on first use. Only call it when a decoded name actually needs preservation.
func (rr *DNSResourceRecord) ensureNameMeta() *dnsRecordNameMeta {
	if rr.names == nil {
		rr.names = &dnsRecordNameMeta{}
	}
	return rr.names
}

// ownerMeta, rdataMeta, and rdata2Meta return the preserved metadata for the
// owner name, the single RDATA name (or SOA MName), and the SOA RName. They
// return nil when no preservation metadata was recorded, which the size and
// encode helpers treat as "use presentation form".
func (rr *DNSResourceRecord) ownerMeta() *dnsNameMeta {
	if rr.names == nil {
		return nil
	}
	return &rr.names.name
}

func (rr *DNSResourceRecord) rdataMeta() *dnsNameMeta {
	if rr.names == nil {
		return nil
	}
	return &rr.names.rdata
}

func (rr *DNSResourceRecord) rdata2Meta() *dnsNameMeta {
	if rr.names == nil {
		return nil
	}
	return &rr.names.rdata2
}

// decode decodes the resource record, returning the total length of the record.
func (rr *DNSResourceRecord) decode(data []byte, offset int, df gopacket.DecodeFeedback, buffer *[]byte) (int, error) {
	name, labels, endq, err := decodeName(data, offset, buffer, 1)
	if err != nil {
		return 0, err
	}

	if len(data) < endq+10 {
		return 0, errors.New("DNS record too small")
	}

	rr.Name = name
	if labels != nil {
		rr.ensureNameMeta().name = newDNSNameMeta(name, labels)
	}
	rr.Type = DNSType(binary.BigEndian.Uint16(data[endq : endq+2]))
	rr.Class = DNSClass(binary.BigEndian.Uint16(data[endq+2 : endq+4]))
	rr.TTL = binary.BigEndian.Uint32(data[endq+4 : endq+8])
	rr.DataLength = binary.BigEndian.Uint16(data[endq+8 : endq+10])
	end := endq + 10 + int(rr.DataLength)
	if end > len(data) {
		return 0, errDecodeRecordLength
	}
	rr.Data = data[endq+10 : end]

	if rr.DataLength > 0 {
		if err = rr.decodeRData(data[:end], endq+10, buffer); err != nil {
			return 0, err
		}
	}

	return endq + 10 + int(rr.DataLength), nil
}

func encodeDNSNameLabels(labels dnsNameLabels, data []byte, offset int) (int, error) {
	size, err := dnsNameLabelsSize(labels)
	if err != nil {
		return 0, err
	}
	start := offset
	for _, label := range labels {
		data[offset] = byte(len(label))
		offset++
		copy(data[offset:], label)
		offset += len(label)
	}
	data[offset] = 0x00
	if offset+1-start != size {
		return 0, errDNSNameInvalidIndex
	}
	return size, nil
}

// encodeDNSName writes name into data at offset, returning the wire size. If the
// preserved wire labels in m still match name (an unchanged decoded name), they
// are re-emitted exactly; otherwise name is parsed as presentation form.
func encodeDNSName(name []byte, m *dnsNameMeta, data []byte, offset int) (int, error) {
	if usePreservedDNSLabels(name, m) {
		return encodeDNSNameLabels(m.labels, data, offset)
	}
	return encodeDNSPresentationName(name, data, offset)
}

func (rr *DNSResourceRecord) encode(data []byte, offset int, opts gopacket.SerializeOptions) (int, error) {

	nSz, err := encodeDNSName(rr.Name, rr.ownerMeta(), data, offset)
	if err != nil {
		return 0, err
	}
	noff := offset + nSz

	binary.BigEndian.PutUint16(data[noff:], uint16(rr.Type))
	binary.BigEndian.PutUint16(data[noff+2:], uint16(rr.Class))
	binary.BigEndian.PutUint32(data[noff+4:], uint32(rr.TTL))

	switch rr.Type {
	case DNSTypeA:
		copy(data[noff+10:], rr.IP.To4())
	case DNSTypeAAAA:
		copy(data[noff+10:], rr.IP)
	case DNSTypeNS:
		if _, err = encodeDNSName(rr.NS, rr.rdataMeta(), data, noff+10); err != nil {
			return 0, err
		}
	case DNSTypeCNAME:
		if _, err = encodeDNSName(rr.CNAME, rr.rdataMeta(), data, noff+10); err != nil {
			return 0, err
		}
	case DNSTypePTR:
		if _, err = encodeDNSName(rr.PTR, rr.rdataMeta(), data, noff+10); err != nil {
			return 0, err
		}
	case DNSTypeSOA:
		n1, err := encodeDNSName(rr.SOA.MName, rr.rdataMeta(), data, noff+10)
		if err != nil {
			return 0, err
		}
		n2, err := encodeDNSName(rr.SOA.RName, rr.rdata2Meta(), data, noff+10+n1)
		if err != nil {
			return 0, err
		}
		noff2 := noff + 10 + n1 + n2
		binary.BigEndian.PutUint32(data[noff2:], rr.SOA.Serial)
		binary.BigEndian.PutUint32(data[noff2+4:], rr.SOA.Refresh)
		binary.BigEndian.PutUint32(data[noff2+8:], rr.SOA.Retry)
		binary.BigEndian.PutUint32(data[noff2+12:], rr.SOA.Expire)
		binary.BigEndian.PutUint32(data[noff2+16:], rr.SOA.Minimum)
	case DNSTypeMX:
		binary.BigEndian.PutUint16(data[noff+10:], rr.MX.Preference)
		if _, err = encodeDNSName(rr.MX.Name, rr.rdataMeta(), data, noff+12); err != nil {
			return 0, err
		}
	case DNSTypeTXT:
		noff2 := noff + 10
		for _, txt := range rr.TXTs {
			data[noff2] = byte(len(txt))
			copy(data[noff2+1:], txt)
			noff2 += 1 + len(txt)
		}
	case DNSTypeSRV:
		binary.BigEndian.PutUint16(data[noff+10:], rr.SRV.Priority)
		binary.BigEndian.PutUint16(data[noff+12:], rr.SRV.Weight)
		binary.BigEndian.PutUint16(data[noff+14:], rr.SRV.Port)
		if _, err = encodeDNSName(rr.SRV.Name, rr.rdataMeta(), data, noff+16); err != nil {
			return 0, err
		}
	case DNSTypeNAPTR:
		binary.BigEndian.PutUint16(data[noff+10:], rr.NAPTR.Order)
		binary.BigEndian.PutUint16(data[noff+12:], rr.NAPTR.Preference)
		noff2 := noff + 14
		data[noff2] = byte(len(rr.NAPTR.Flags))
		copy(data[noff2+1:], rr.NAPTR.Flags)
		noff2 += 1 + len(rr.NAPTR.Flags)
		data[noff2] = byte(len(rr.NAPTR.Service))
		copy(data[noff2+1:], rr.NAPTR.Service)
		noff2 += 1 + len(rr.NAPTR.Service)
		data[noff2] = byte(len(rr.NAPTR.Regexp))
		copy(data[noff2+1:], rr.NAPTR.Regexp)
		noff2 += 1 + len(rr.NAPTR.Regexp)
		if _, err = encodeDNSName(rr.NAPTR.Replacement, rr.rdataMeta(), data, noff2); err != nil {
			return 0, err
		}
	case DNSTypeURI:
		binary.BigEndian.PutUint16(data[noff+10:], rr.URI.Priority)
		binary.BigEndian.PutUint16(data[noff+12:], rr.URI.Weight)
		copy(data[noff+14:], rr.URI.Target)
	case DNSTypeOPT:
		noff2 := noff + 10
		for _, opt := range rr.OPT {
			binary.BigEndian.PutUint16(data[noff2:], uint16(opt.Code))
			binary.BigEndian.PutUint16(data[noff2+2:], uint16(len(opt.Data)))
			copy(data[noff2+4:], opt.Data)
			noff2 += 4 + len(opt.Data)
		}
	case DNSTypeRRSIG:
		if err = rr.RRSIG.encode(rr.rdataMeta(), data, noff+10); err != nil {
			return 0, err
		}
	case DNSTypeDNSKEY:
		rr.DNSKEY.encode(data, noff+10)
	case DNSTypeSVCB, DNSTypeHTTPS:
		if _, err = rr.SVCB.encode(rr.rdataMeta(), data, noff+10); err != nil {
			return 0, err
		}
	default:
		return 0, fmt.Errorf("serializing resource record of type %v not supported", rr.Type)
	}

	// DataLength
	dSz, err := recSize(rr)
	if err != nil {
		return 0, err
	}
	binary.BigEndian.PutUint16(data[noff+8:], uint16(dSz))

	if opts.FixLengths {
		rr.DataLength = uint16(dSz)
	}

	return nSz + 10 + dSz, nil
}

func (rr *DNSResourceRecord) String() string {

	if rr.Type == DNSTypeOPT {
		opts := make([]string, len(rr.OPT))
		for i, opt := range rr.OPT {
			opts[i] = opt.String()
		}
		return "OPT " + strings.Join(opts, ",")
	}
	if rr.Type == DNSTypeURI {
		return fmt.Sprintf("URI %d %d %s", rr.URI.Priority, rr.URI.Weight, string(rr.URI.Target))
	}
	if rr.Class == DNSClassIN {
		switch rr.Type {
		case DNSTypeA, DNSTypeAAAA:
			return rr.IP.String()
		case DNSTypeNS:
			return "NS " + string(rr.NS)
		case DNSTypeCNAME:
			return "CNAME " + string(rr.CNAME)
		case DNSTypePTR:
			return "PTR " + string(rr.PTR)
		case DNSTypeTXT:
			return "TXT " + string(rr.TXT)
		}
	}

	return fmt.Sprintf("<%v, %v>", rr.Class, rr.Type)
}

func decodeCharacterStrings(data []byte) ([][]byte, error) {
	strings := make([][]byte, 0, 1)
	end := len(data)
	for index, index2 := 0, 0; index != end; index = index2 {
		index2 = index + 1 + int(data[index]) // index increases by 1..256 and does not overflow
		if index2 > end {
			return nil, errCharStringMissData
		}
		strings = append(strings, data[index+1:index2])
	}
	return strings, nil
}

func decodeOPTs(data []byte, offset int) ([]DNSOPT, error) {
	allOPT := []DNSOPT{}
	end := len(data)

	if offset == end {
		return allOPT, nil // There is no data to read
	}

	if offset+4 > end {
		return allOPT, fmt.Errorf("DNSOPT record is of length %d, it should be at least length 4", end-offset)
	}

	for i := offset; i < end; {
		opt := DNSOPT{}
		if len(data) < i+4 {
			return allOPT, fmt.Errorf("Malformed DNSOPT record.  Length %d < %d", len(data), i+4)
		}
		opt.Code = DNSOptionCode(binary.BigEndian.Uint16(data[i : i+2]))
		l := binary.BigEndian.Uint16(data[i+2 : i+4])
		if i+4+int(l) > end {
			return allOPT, fmt.Errorf("Malformed DNSOPT record. The length (%d) field implies a packet larger than the one received", l)
		}
		opt.Data = data[i+4 : i+4+int(l)]
		allOPT = append(allOPT, opt)
		i += int(l) + 4
	}
	return allOPT, nil
}

func decodeSVCB(data []byte, offset int, buffer *[]byte) (DNSSVCB, dnsNameLabels, error) {
	var svcb DNSSVCB
	end := len(data)

	if offset == end {
		return svcb, nil, fmt.Errorf("DNSSVCB record is empty")
	}

	if offset+3 > end {
		return svcb, nil, fmt.Errorf("DNSSVCB record is of length %d, it should be at least length 3", end-offset)
	}
	priority := binary.BigEndian.Uint16(data[offset:])
	target, labels, ofs, err := decodeName(data, offset+2, buffer, 1)
	if err != nil {
		return svcb, nil, err
	}

	var params []DNSSvcParam
	for ofs < end {
		if ofs+4 > end {
			return svcb, nil, fmt.Errorf("DNSSVCB record truncated in SvcParams")
		}
		key := DNSSvcParamKey(binary.BigEndian.Uint16(data[ofs:]))
		l := int(binary.BigEndian.Uint16(data[ofs+2:]))
		if ofs+4+l > end {
			return svcb, nil, fmt.Errorf("DNSSVCB record truncated in SvcParams")
		}
		params = append(params, DNSSvcParam{
			Key:   key,
			Value: data[ofs+4 : ofs+4+l],
		})
		ofs += 4 + l
	}

	return DNSSVCB{
		Priority: priority,
		Target:   target,
		Params:   params,
	}, labels, nil
}

func (rr *DNSResourceRecord) decodeRData(data []byte, offset int, buffer *[]byte) error {
	switch rr.Type {
	case DNSTypeA:
		rr.IP = rr.Data
	case DNSTypeAAAA:
		rr.IP = rr.Data
	case DNSTypeTXT, DNSTypeHINFO:
		rr.TXT = rr.Data
		txts, err := decodeCharacterStrings(rr.Data)
		if err != nil {
			return err
		}
		rr.TXTs = txts
	case DNSTypeNS:
		name, labels, _, err := decodeName(data, offset, buffer, 1)
		if err != nil {
			return err
		}
		rr.NS = name
		if labels != nil {
			rr.ensureNameMeta().rdata = newDNSNameMeta(name, labels)
		}
	case DNSTypeCNAME:
		name, labels, _, err := decodeName(data, offset, buffer, 1)
		if err != nil {
			return err
		}
		rr.CNAME = name
		if labels != nil {
			rr.ensureNameMeta().rdata = newDNSNameMeta(name, labels)
		}
	case DNSTypePTR:
		name, labels, _, err := decodeName(data, offset, buffer, 1)
		if err != nil {
			return err
		}
		rr.PTR = name
		if labels != nil {
			rr.ensureNameMeta().rdata = newDNSNameMeta(name, labels)
		}
	case DNSTypeSOA:
		name, labels, endq, err := decodeName(data, offset, buffer, 1)
		if err != nil {
			return err
		}
		rr.SOA.MName = name
		if labels != nil {
			rr.ensureNameMeta().rdata = newDNSNameMeta(name, labels)
		}
		name, labels, endq, err = decodeName(data, endq, buffer, 1)
		if err != nil {
			return err
		}
		if len(data) < endq+20 {
			return errors.New("SOA too small")
		}
		rr.SOA.RName = name
		if labels != nil {
			rr.ensureNameMeta().rdata2 = newDNSNameMeta(name, labels)
		}
		rr.SOA.Serial = binary.BigEndian.Uint32(data[endq : endq+4])
		rr.SOA.Refresh = binary.BigEndian.Uint32(data[endq+4 : endq+8])
		rr.SOA.Retry = binary.BigEndian.Uint32(data[endq+8 : endq+12])
		rr.SOA.Expire = binary.BigEndian.Uint32(data[endq+12 : endq+16])
		rr.SOA.Minimum = binary.BigEndian.Uint32(data[endq+16 : endq+20])
	case DNSTypeMX:
		if len(data) < offset+2 {
			return errors.New("MX too small")
		}
		rr.MX.Preference = binary.BigEndian.Uint16(data[offset : offset+2])
		name, labels, _, err := decodeName(data, offset+2, buffer, 1)
		if err != nil {
			return err
		}
		rr.MX.Name = name
		if labels != nil {
			rr.ensureNameMeta().rdata = newDNSNameMeta(name, labels)
		}
	case DNSTypeURI:
		if len(rr.Data) < 4 {
			return errors.New("URI too small")
		}
		rr.URI.Priority = binary.BigEndian.Uint16(data[offset : offset+2])
		rr.URI.Weight = binary.BigEndian.Uint16(data[offset+2 : offset+4])
		rr.URI.Target = rr.Data[4:]
	case DNSTypeSRV:
		if len(data) < offset+6 {
			return errors.New("SRV too small")
		}
		rr.SRV.Priority = binary.BigEndian.Uint16(data[offset : offset+2])
		rr.SRV.Weight = binary.BigEndian.Uint16(data[offset+2 : offset+4])
		rr.SRV.Port = binary.BigEndian.Uint16(data[offset+4 : offset+6])
		name, labels, _, err := decodeName(data, offset+6, buffer, 1)
		if err != nil {
			return err
		}
		rr.SRV.Name = name
		if labels != nil {
			rr.ensureNameMeta().rdata = newDNSNameMeta(name, labels)
		}
	case DNSTypeNAPTR:
		if len(data) < offset+4 {
			return errors.New("NAPTR too small")
		}
		rr.NAPTR.Order = binary.BigEndian.Uint16(data[offset : offset+2])
		rr.NAPTR.Preference = binary.BigEndian.Uint16(data[offset+2 : offset+4])
		offset += 4
		// Decode Flags (character-string)
		if len(data) < offset+1 {
			return errors.New("NAPTR Flags missing")
		}
		flagsLen := int(data[offset])
		offset++
		if len(data) < offset+flagsLen {
			return errors.New("NAPTR Flags truncated")
		}
		rr.NAPTR.Flags = data[offset : offset+flagsLen]
		offset += flagsLen
		// Decode Service (character-string)
		if len(data) < offset+1 {
			return errors.New("NAPTR Service missing")
		}
		serviceLen := int(data[offset])
		offset++
		if len(data) < offset+serviceLen {
			return errors.New("NAPTR Service truncated")
		}
		rr.NAPTR.Service = data[offset : offset+serviceLen]
		offset += serviceLen
		// Decode Regexp (character-string)
		if len(data) < offset+1 {
			return errors.New("NAPTR Regexp missing")
		}
		regexpLen := int(data[offset])
		offset++
		if len(data) < offset+regexpLen {
			return errors.New("NAPTR Regexp truncated")
		}
		rr.NAPTR.Regexp = data[offset : offset+regexpLen]
		offset += regexpLen
		// Decode Replacement (domain-name)
		name, labels, _, err := decodeName(data, offset, buffer, 1)
		if err != nil {
			return err
		}
		rr.NAPTR.Replacement = name
		if labels != nil {
			rr.ensureNameMeta().rdata = newDNSNameMeta(name, labels)
		}
	case DNSTypeOPT:
		allOPT, err := decodeOPTs(data, offset)
		if err != nil {
			return err
		}
		rr.OPT = allOPT
	case DNSTypeRRSIG:
		labels, err := rr.RRSIG.decode(data, offset)
		if err != nil {
			return err
		}
		if labels != nil {
			rr.ensureNameMeta().rdata = newDNSNameMeta(rr.RRSIG.SignerName, labels)
		}
	case DNSTypeDNSKEY:
		err := rr.DNSKEY.decode(data, offset)
		if err != nil {
			return err
		}
	case DNSTypeSVCB, DNSTypeHTTPS:
		svcb, labels, err := decodeSVCB(data, offset, buffer)
		if err != nil {
			return err
		}
		rr.SVCB = svcb
		if labels != nil {
			rr.ensureNameMeta().rdata = newDNSNameMeta(svcb.Target, labels)
		}
	}
	return nil
}

// DNSSOA is a Start of Authority record.  Each domain requires a SOA record at
// the cutover where a domain is delegated from its parent.
type DNSSOA struct {
	MName, RName                            []byte
	Serial, Refresh, Retry, Expire, Minimum uint32
}

// DNSSRV is a Service record, defining a location (hostname/port) of a
// server/service.
type DNSSRV struct {
	Priority, Weight, Port uint16
	Name                   []byte
}

// DNSMX is a mail exchange record, defining a mail server for a recipient's
// domain.
type DNSMX struct {
	Preference uint16
	Name       []byte
}

// DNSNAPTR is a Naming Authority Pointer record, used for application-specific
// string transformations (e.g., for SIP, ENUM).
type DNSNAPTR struct {
	Order       uint16
	Preference  uint16
	Flags       []byte
	Service     []byte
	Regexp      []byte
	Replacement []byte
}

// DNSSVCB resource record is used to facilitate the lookup of
// information needed to make connections to network services, such as
// for HTTP origins.
type DNSSVCB struct {
	Priority uint16
	Target   []byte
	Params   []DNSSvcParam
}

func (svcb DNSSVCB) size(m *dnsNameMeta) (int, error) {
	// Target.
	targetSize, err := dnsNameSize(svcb.Target, m)
	if err != nil {
		return 0, err
	}
	sz := targetSize
	// Priority.
	sz += 2

	// Params.
	for _, param := range svcb.Params {
		sz += param.size()
	}
	return sz, nil
}

func (svcb DNSSVCB) String() string {
	return fmt.Sprintf("%v [%s] %v",
		svcb.Priority, string(svcb.Target), svcb.Params)
}

func (svcb DNSSVCB) encode(m *dnsNameMeta, data []byte, offset int) (int, error) {
	start := offset
	binary.BigEndian.PutUint16(data[offset:], svcb.Priority)
	n, err := encodeDNSName(svcb.Target, m, data, offset+2)
	if err != nil {
		return 0, err
	}
	offset += 2 + n

	for _, param := range svcb.Params {
		offset = param.encode(data, offset)
	}
	return offset - start, nil
}

// DNSSvcParamKey defines SVCB service parameter keys.
type DNSSvcParamKey uint16

func (key DNSSvcParamKey) String() string {
	switch key {
	default:
		return "Unknown"
	case DNSSvcParamKeyMandatory:
		return "mandatory"
	case DNSSvcParamKeyAlpn:
		return "alpn"
	case DNSSvcParamKeyNoDefaultAlpn:
		return "no-default-alpn"
	case DNSSvcParamKeyPort:
		return "port"
	case DNSSvcParamKeyIPv4Hint:
		return "ipv4hint"
	case DNSSvcParamKeyECH:
		return "ech"
	case DNSSvcParamKeyIPv6Hint:
		return "ipv6hint"
	case DNSSvcParamKeyDoHPath:
		return "dohpath"
	case DNSSvcParamKeyOHTTP:
		return "ohttp"
	case DNSSvcParamKeyDoHURI:
		return "dohuri"
	case DNSSvcParamKeyInvalidKey:
		return "Invalid key"
	}
}

// DNSSvcParamKey known values.
const (
	DNSSvcParamKeyMandatory     DNSSvcParamKey = 0     // RFC9460, Section 8
	DNSSvcParamKeyAlpn          DNSSvcParamKey = 1     // RFC9460, Section 7.1
	DNSSvcParamKeyNoDefaultAlpn DNSSvcParamKey = 2     // RFC9460, Section 7.1
	DNSSvcParamKeyPort          DNSSvcParamKey = 3     // RFC9460, Section 7.2
	DNSSvcParamKeyIPv4Hint      DNSSvcParamKey = 4     // RFC9460, Section 7.3
	DNSSvcParamKeyECH           DNSSvcParamKey = 5     // RFC9460
	DNSSvcParamKeyIPv6Hint      DNSSvcParamKey = 6     // RFC9460, Section 7.3
	DNSSvcParamKeyDoHPath       DNSSvcParamKey = 7     // RFC9461
	DNSSvcParamKeyOHTTP         DNSSvcParamKey = 8     // RFC9540, Section 4
	DNSSvcParamKeyDoHURI        DNSSvcParamKey = 32768 // draft-pauly-add-resolver-discovery-00.html
	DNSSvcParamKeyInvalidKey    DNSSvcParamKey = 65535 // RFC9460
)

// DNSSvcParam is a service param, see RFC9460, section 2.2.
type DNSSvcParam struct {
	Key   DNSSvcParamKey
	Value []byte
}

func (param DNSSvcParam) size() int {
	return 2 + 2 + len(param.Value)
}

func (param DNSSvcParam) encode(data []byte, offset int) int {
	binary.BigEndian.PutUint16(data[offset:], uint16(param.Key))
	offset += 2
	binary.BigEndian.PutUint16(data[offset:], uint16(len(param.Value)))
	offset += 2
	copy(data[offset:], param.Value)
	offset += len(param.Value)

	return offset
}

func (param DNSSvcParam) String() string {
	return fmt.Sprintf("%s=%x", param.Key, param.Value)
}

// DNSRRSIG is a DNS RRSIG record, see RFC 4034, section 3.1
type DNSRRSIG struct {
	TypeCovered                        DNSType
	Algorithm                          DNSSECAlgorithm
	Labels                             uint8
	OriginalTTL, Expiration, Inception uint32
	KeyTag                             uint16
	SignerName, Signature              []byte
}

func (rrsig DNSRRSIG) size(m *dnsNameMeta) (int, error) {
	// 18 bytes for the fixed fields, plus the wire-encoded signer name and the signature.
	signerSize, err := dnsNameSize(rrsig.SignerName, m)
	if err != nil {
		return 0, err
	}
	return 18 + signerSize + len(rrsig.Signature), nil
}

func (rrsig DNSRRSIG) String() string {
	return fmt.Sprintf("RRSIG %d %d %d %d %d %d %d %v %v",
		rrsig.TypeCovered, rrsig.Algorithm, rrsig.Labels, rrsig.OriginalTTL,
		rrsig.Expiration, rrsig.Inception, rrsig.KeyTag, rrsig.SignerName, rrsig.Signature)
}

// RRSIG RDATA Wire Format
// 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          Type Covered        |   Algorithm   |     Labels     |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                          Original TTL                         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                      Signature Expiration                     |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                      Signature Inception                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |            Key Tag           |                                /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+          Signer’s Name        /
// /                                                               /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// /                                         						/
// /                            Signature                          /
// / 																/
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
func (rrsig *DNSRRSIG) decode(data []byte, offset int) (dnsNameLabels, error) {
	if len(data) < offset+18 {
		return nil, errors.New("RRSIG too small")
	}
	var err error
	var labels dnsNameLabels
	rrsig.TypeCovered = DNSType(binary.BigEndian.Uint16(data[offset:]))
	rrsig.Algorithm = DNSSECAlgorithm(data[offset+2])
	rrsig.Labels = data[offset+3]
	rrsig.OriginalTTL = binary.BigEndian.Uint32(data[offset+4:])
	rrsig.Expiration = binary.BigEndian.Uint32(data[offset+8:])
	rrsig.Inception = binary.BigEndian.Uint32(data[offset+12:])
	rrsig.KeyTag = binary.BigEndian.Uint16(data[offset+16:])
	_, labels, offset, err = decodeName(data, offset+18, &rrsig.SignerName, 1)
	if len(rrsig.SignerName) > 1 {
		rrsig.SignerName = rrsig.SignerName[1:] // Remove leading '.'
	}
	if err != nil {
		return nil, err
	}
	rrsig.Signature = data[offset:]
	return labels, nil
}

func (rrsig DNSRRSIG) encode(m *dnsNameMeta, data []byte, offset int) error {
	binary.BigEndian.PutUint16(data[offset:], uint16(rrsig.TypeCovered))
	data[offset+2] = uint8(rrsig.Algorithm)
	data[offset+3] = rrsig.Labels
	binary.BigEndian.PutUint32(data[offset+4:], rrsig.OriginalTTL)
	binary.BigEndian.PutUint32(data[offset+8:], rrsig.Expiration)
	binary.BigEndian.PutUint32(data[offset+12:], rrsig.Inception)
	binary.BigEndian.PutUint16(data[offset+16:], rrsig.KeyTag)
	n, err := encodeDNSName(rrsig.SignerName, m, data, offset+18)
	if err != nil {
		return err
	}
	offset += 18 + n
	copy(data[offset:], rrsig.Signature)
	return nil
}

// DNSSECAlgorithm common values
const (
	DNSSECAlgorithmRSAMD5          DNSSECAlgorithm = 1
	DNSSECAlgorithmDH              DNSSECAlgorithm = 3
	DNSSECAlgorithmDSASHA1         DNSSECAlgorithm = 3
	DNSSECAlgorithmECC             DNSSECAlgorithm = 4
	DNSSECAlgorithmRSASHA1         DNSSECAlgorithm = 5
	DNSSECAlgorithmDSASHA1NSEC3    DNSSECAlgorithm = 6
	DNSSECAlgorithmRSASHA1NSEC3    DNSSECAlgorithm = 7
	DNSSECAlgorithmRSASHA256       DNSSECAlgorithm = 8
	DNSSECAlgorithmRSASHA512       DNSSECAlgorithm = 10
	DNSSECAlgorithmECCGOST         DNSSECAlgorithm = 12
	DNSSECAlgorithmECDSAP256SHA256 DNSSECAlgorithm = 13
	DNSSECAlgorithmECDSAP384SHA384 DNSSECAlgorithm = 14
	DNSSECAlgorithmED25519         DNSSECAlgorithm = 15
	DNSSECAlgorithmED448           DNSSECAlgorithm = 16
)

// DNSSECAlgorithm represents the algorithm used in a DNSSEC record, see RFC 4034, section 5.1
type DNSSECAlgorithm uint8

// DNSKEY is a DNSKEY record, see RFC 4034, section 2.1
type DNSKEY struct {
	Flags     DNSKEYFlag
	Protocol  DNSKEYProtocol
	Algorithm DNSSECAlgorithm
	PublicKey []byte
}

func (dnskey DNSKEY) size() int {
	return 4 + len(dnskey.PublicKey)
}

func (dnskey DNSKEY) String() string {
	return fmt.Sprintf("DNSKEY %d %d %d %v",
		dnskey.Flags, dnskey.Protocol, dnskey.Algorithm, dnskey.PublicKey)
}

// DNSKEY RDATA Wire Format
// 1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |             Flags            |    Protocol   |    Algorithm   |                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// /                                                               /
// /                           Public Key                          /
// /                                                               /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
func (dnskey *DNSKEY) decode(data []byte, offset int) error {
	if len(data) < offset+4 {
		return errors.New("DNSKEY too small")
	}
	dnskey.Flags = DNSKEYFlag(binary.BigEndian.Uint16(data[offset:]))
	dnskey.Protocol = DNSKEYProtocol(data[offset+2])
	dnskey.Algorithm = DNSSECAlgorithm(data[offset+3])
	dnskey.PublicKey = data[offset+4:]
	return nil
}

func (dnskey DNSKEY) encode(data []byte, offset int) {
	binary.BigEndian.PutUint16(data[offset:], uint16(dnskey.Flags))
	data[offset+2] = uint8(dnskey.Protocol)
	data[offset+3] = uint8(dnskey.Algorithm)
	copy(data[offset+4:], dnskey.PublicKey)
}

// DNSKEYFlag common values
const (
	DNSKEYFlagOtherKey         DNSKEYFlag = 0
	DNSKEYFlagZoneKey          DNSKEYFlag = 256
	DNSKEYFlagSecureEntryPoint DNSKEYFlag = 257
)

// DNSKEYFlag represents the key type of a DNSKEY record, see RFC 4034, section 2.1.1
type DNSKEYFlag uint16

// DNSKEYProtocol common values, see RFC 4034, section 2.1.2
const (
	DNSKEYProtocolReserved DNSKEYProtocol = 0
	DNSKEYProtocolValue    DNSKEYProtocol = 3
)

type DNSKEYProtocol uint8

// DNSURI is a URI record, defining a target (URI) of a server/service
type DNSURI struct {
	Priority, Weight uint16
	Target           []byte
}

// DNSOptionCode represents the code of a DNS Option, see RFC6891, section 6.1.2
type DNSOptionCode uint16

func (doc DNSOptionCode) String() string {
	switch doc {
	default:
		return "Unknown"
	case DNSOptionCodeNSID:
		return "NSID"
	case DNSOptionCodeDAU:
		return "DAU"
	case DNSOptionCodeDHU:
		return "DHU"
	case DNSOptionCodeN3U:
		return "N3U"
	case DNSOptionCodeEDNSClientSubnet:
		return "EDNSClientSubnet"
	case DNSOptionCodeEDNSExpire:
		return "EDNSExpire"
	case DNSOptionCodeCookie:
		return "Cookie"
	case DNSOptionCodeEDNSKeepAlive:
		return "EDNSKeepAlive"
	case DNSOptionCodePadding:
		return "CodePadding"
	case DNSOptionCodeChain:
		return "CodeChain"
	case DNSOptionCodeEDNSKeyTag:
		return "CodeEDNSKeyTag"
	case DNSOptionCodeEDNSClientTag:
		return "EDNSClientTag"
	case DNSOptionCodeEDNSServerTag:
		return "EDNSServerTag"
	case DNSOptionCodeDeviceID:
		return "DeviceID"
	}
}

// DNSOptionCode known values. See IANA
const (
	DNSOptionCodeNSID             DNSOptionCode = 3
	DNSOptionCodeDAU              DNSOptionCode = 5
	DNSOptionCodeDHU              DNSOptionCode = 6
	DNSOptionCodeN3U              DNSOptionCode = 7
	DNSOptionCodeEDNSClientSubnet DNSOptionCode = 8
	DNSOptionCodeEDNSExpire       DNSOptionCode = 9
	DNSOptionCodeCookie           DNSOptionCode = 10
	DNSOptionCodeEDNSKeepAlive    DNSOptionCode = 11
	DNSOptionCodePadding          DNSOptionCode = 12
	DNSOptionCodeChain            DNSOptionCode = 13
	DNSOptionCodeEDNSKeyTag       DNSOptionCode = 14
	DNSOptionCodeEDNSClientTag    DNSOptionCode = 16
	DNSOptionCodeEDNSServerTag    DNSOptionCode = 17
	DNSOptionCodeDeviceID         DNSOptionCode = 26946
)

// DNSOPT is a DNS Option, see RFC6891, section 6.1.2
type DNSOPT struct {
	Code DNSOptionCode
	Data []byte
}

func (opt DNSOPT) String() string {
	return fmt.Sprintf("%s=%x", opt.Code, opt.Data)
}

var (
	errMaxRecursion = errors.New("max DNS recursion level hit")

	errDNSNameOffsetTooHigh    = errors.New("dns name offset too high")
	errDNSNameOffsetNegative   = errors.New("dns name offset is negative")
	errDNSPacketTooShort       = errors.New("DNS packet too short")
	errDNSNameTooLong          = errors.New("dns name is too long")
	errDNSNameInvalidIndex     = errors.New("dns name uncomputable: invalid index")
	errDNSPointerOffsetTooHigh = errors.New("dns offset pointer too high")
	errDNSIndexOutOfRange      = errors.New("dns index walked out of range")
	errDNSNameHasNoData        = errors.New("no dns data found for name")

	errCharStringMissData = errors.New("Insufficient data for a <character-string>")

	errDecodeRecordLength = errors.New("resource record length exceeds data")

	errDecodeQueryBadQDCount = errors.New("Invalid query decoding, not the right number of questions")
	errDecodeQueryBadANCount = errors.New("Invalid query decoding, not the right number of answers")
	errDecodeQueryBadNSCount = errors.New("Invalid query decoding, not the right number of authorities")
	errDecodeQueryBadARCount = errors.New("Invalid query decoding, not the right number of additionals info")
)
