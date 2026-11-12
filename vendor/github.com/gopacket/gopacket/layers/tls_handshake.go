// Copyright 2018 The GoPacket Authors. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"errors"

	"github.com/gopacket/gopacket"
)

// TLS Extensions http://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml
type TLSExtension uint16

const (
	TLSExtServerName           TLSExtension = 0
	TLSExtMaxFragLen           TLSExtension = 1
	TLSExtClientCertURL        TLSExtension = 2
	TLSExtTrustedCAKeys        TLSExtension = 3
	TLSExtTruncatedHMAC        TLSExtension = 4
	TLSExtStatusRequest        TLSExtension = 5
	TLSExtUserMapping          TLSExtension = 6
	TLSExtClientAuthz          TLSExtension = 7
	TLSExtServerAuthz          TLSExtension = 8
	TLSExtCertType             TLSExtension = 9
	TLSExtSupportedGroups      TLSExtension = 10
	TLSExtECPointFormats       TLSExtension = 11
	TLSExtSRP                  TLSExtension = 12
	TLSExtSignatureAlgs        TLSExtension = 13
	TLSxtUseSRTP               TLSExtension = 14
	TLSExtHeartbeat            TLSExtension = 15
	TLSExtALPN                 TLSExtension = 16
	TLSExtStatusRequestV2      TLSExtension = 17
	TLSExtSignedCertTS         TLSExtension = 18
	TLSExtClientCertType       TLSExtension = 19
	TLSExtServerCertType       TLSExtension = 20
	TLSExtPadding              TLSExtension = 21
	TLSExtEncryptThenMAC       TLSExtension = 22
	TLSExtExtendedMasterSecret TLSExtension = 23
	TLSExtSessionTicket        TLSExtension = 35
	TLSExtNPN                  TLSExtension = 13172
	TLSExtRenegotiationInfo    TLSExtension = 65281
)

/*refer to https://datatracker.ietf.org/doc/html/rfc5246#appendix-A.4*/
const (
	TLSHandshakeHelloRequest        = 0
	TLSHandshakeClientHello         = 1
	TLSHandshakeServerHello         = 2
	TLSHandsharkHelloVerirfyRequest = 3
	TLSHandshakeCertificate         = 11
	TLSHandshakeServerKeyExchange   = 12
	TLSHandshakeCertificateRequest  = 13
	TLSHandshakeServerHelloDone     = 14
	TLSHandshakeCertificateVerify   = 15
	TLSHandshakeClientKeyExchange   = 16
	TLSHandshakeFinished            = 20
)

var handShakeTypeMap = map[uint8]string{
	TLSHandshakeHelloRequest:        "Hello Request",
	TLSHandshakeClientHello:         "Client Hello",
	TLSHandshakeServerHello:         "Server Hello",
	TLSHandsharkHelloVerirfyRequest: "Hello Verify Request",
	TLSHandshakeCertificate:         "Certificate",
	TLSHandshakeServerKeyExchange:   "Server Key Exchange",
	TLSHandshakeCertificateRequest:  "Certificate Request",
	TLSHandshakeServerHelloDone:     "Server Hello Done",
	TLSHandshakeCertificateVerify:   "Certificate Verify",
	TLSHandshakeClientKeyExchange:   "Client Key Exchange",
	TLSHandshakeFinished:            "Finished",
}

type TLSHandshakeRecordClientHello struct {
	HandshakeType            uint8
	Length                   uint32
	ProtocolVersion          TLSVersion
	Random                   []uint8
	SessionIDLength          uint8
	SessionID                []uint8
	CipherSuitsLength        uint16
	CipherSuits              []uint8
	CompressionMethodsLength uint8
	CompressionMethods       []uint8
	ExtensionsLength         uint16
	Extensions               []uint8
	SNI                      []uint8
}

type TLSHandshakeRecordClientKeyChange struct {
}

// TLSHandshakeRecord defines the structure of a Handshare Record
type TLSHandshakeRecord struct {
	TLSRecordHeader
	ClientHello     TLSHandshakeRecordClientHello
	ClientKeyChange TLSHandshakeRecordClientKeyChange
}

const (
	// tlsRecordHeaderLen is a record header: type (1), version (2), length (2).
	tlsRecordHeaderLen = 5
	// tlsHandshakeHeaderLen is a handshake message header: type (1), length (3).
	tlsHandshakeHeaderLen = 4
)

// appendFragmentedClientHello handles a ClientHello that starts in body and
// continues in the handshake records at the start of rest, all in the same
// data:
//
//	[16 .. 00 40][01 00 00 81 ....] [16 .. 00 45][.... rest of hello]
//	      body, fragment 1                 rest, fragment 2
//
// It appends one entry per record, the first holding the decoded message and
// the others their header only, and returns the bytes taken from rest. It
// returns 0, appending nothing, when body does not start such a message,
// rest does not complete it, or the message does not decode: those inputs
// keep the result they had before, so nothing that decoded starts failing.
func (t *TLS) appendFragmentedClientHello(h TLSRecordHeader, body, rest []byte) int {
	msg, continuation := fragmentedClientHello(body, rest)
	if msg == nil {
		return 0
	}

	// The attempt must leave no trace, feedback included, when it fails.
	r := TLSHandshakeRecord{TLSRecordHeader: h}
	if err := r.ClientHello.decodeFromBytes(msg, gopacket.NilDecodeFeedback); err != nil {
		return 0
	}

	t.Handshake = append(t.Handshake, r)
	taken := 0
	for _, ch := range continuation {
		t.Handshake = append(t.Handshake, TLSHandshakeRecord{TLSRecordHeader: ch})
		taken += tlsRecordHeaderLen + int(ch.Length)
	}
	return taken
}

// fragmentedClientHello reassembles, into a new buffer, a ClientHello that
// body starts and the handshake records at the start of rest complete. It
// returns nil when body holds no such message or rest does not complete it.
func fragmentedClientHello(body, rest []byte) ([]byte, []TLSRecordHeader) {
	if len(body) < tlsHandshakeHeaderLen || body[0] != TLSHandshakeClientHello {
		return nil, nil
	}
	need := tlsHandshakeHeaderLen + (int(body[1])<<16 | int(body[2])<<8 | int(body[3]))

	// A message that fits its record is not fragmented; one longer than the
	// data cannot be completed here, and is not worth a buffer.
	if need <= len(body) || need > len(body)+len(rest) {
		return nil, nil
	}

	msg := append(make([]byte, 0, need), body...)
	var continuation []TLSRecordHeader
	for len(msg) < need {
		if len(rest) < tlsRecordHeaderLen || TLSType(rest[0]) != TLSHandshake {
			return nil, nil
		}
		h := TLSRecordHeader{
			ContentType: TLSType(rest[0]),
			Version:     TLSVersion(binary.BigEndian.Uint16(rest[1:3])),
			Length:      binary.BigEndian.Uint16(rest[3:5]),
		}
		end := tlsRecordHeaderLen + int(h.Length)
		if len(rest) < end {
			return nil, nil
		}

		msg = append(msg, rest[tlsRecordHeaderLen:end]...)
		rest = rest[end:]
		continuation = append(continuation, h)
	}

	// The last fragment may carry the start of the next message too.
	return msg[:need], continuation
}

func (t *TLSHandshakeRecordClientHello) decodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	// data is exactly the body of one handshake record (see decodeTLSRecords).
	// Never look past len(data): the backing array may hold the next record,
	// the rest of the frame, or a previous packet in a reused capture buffer.

	// Fixed prefix: type(1) + length(3) + version(2) + random(32) + sessionIDLen(1).
	if len(data) < 39 {
		df.SetTruncated()
		return errors.New("TLS ClientHello too short")
	}
	t.HandshakeType = data[0]
	d := make([]byte, 4)
	for k, v := range data[1:4] {
		d[k+1] = v
	}
	t.Length = binary.BigEndian.Uint32(d)
	t.ProtocolVersion = TLSVersion(binary.BigEndian.Uint16(data[4:6]))
	t.Random = data[6:38]
	t.SessionIDLength = data[38]

	// All subsequent offsets are computed in int to avoid uint16 overflow,
	// and each variable-length field is bounds-checked before it is read.
	pos := 39 + int(t.SessionIDLength)
	if len(data) < pos+2 {
		df.SetTruncated()
		return errors.New("TLS ClientHello truncated in session ID")
	}
	t.SessionID = data[39:pos]
	t.CipherSuitsLength = binary.BigEndian.Uint16(data[pos : pos+2])
	pos += 2

	if len(data) < pos+int(t.CipherSuitsLength)+1 {
		df.SetTruncated()
		return errors.New("TLS ClientHello truncated in cipher suites")
	}
	t.CipherSuits = data[pos : pos+int(t.CipherSuitsLength)]
	pos += int(t.CipherSuitsLength)
	t.CompressionMethodsLength = data[pos]
	pos++

	if len(data) < pos+int(t.CompressionMethodsLength)+2 {
		df.SetTruncated()
		return errors.New("TLS ClientHello truncated in compression methods")
	}
	t.CompressionMethods = data[pos : pos+int(t.CompressionMethodsLength)]
	pos += int(t.CompressionMethodsLength)
	t.ExtensionsLength = binary.BigEndian.Uint16(data[pos : pos+2])
	pos += 2

	// extract extension data
	if len(data) < pos+int(t.ExtensionsLength) {
		df.SetTruncated()
		return errors.New("TLS ClientHello truncated in extensions")
	}
	data = data[pos : pos+int(t.ExtensionsLength)]
	t.Extensions = data
	for len(data) > 0 {
		if len(data) < 4 {
			break
		}
		extensionType := binary.BigEndian.Uint16(data[:2])
		length := int(binary.BigEndian.Uint16(data[2:4]))
		if len(data) < 4+length {
			break
		}
		switch TLSExtension(extensionType) {
		case TLSExtServerName:
			if len(data) > 6 {
				serverNameExtensionLength := binary.BigEndian.Uint16(data[4:6])
				entryType := data[6]
				if serverNameExtensionLength > 0 && entryType == 0 && len(data) > 8 { // 0 = DNS hostname
					hostnameLength := int(binary.BigEndian.Uint16(data[7:9]))
					if len(data) >= 9+hostnameLength {
						t.SNI = data[9 : 9+hostnameLength]
					}
				}
			}
		}
		data = data[4+length:]
	}

	return nil
}
func (t *TLSHandshakeRecordClientKeyChange) decodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	/*TBD*/
	return nil
}

/**
 * Checks whether a handshake message seems encrypted and cannot be dissected.
 */
func (t TLSHandshakeRecord) isEncryptedHandshakeMessage(h TLSRecordHeader, data []byte) bool {
	if h.Length < 16 {
		/*
		 * Encrypted data has additional overhead. For TLS 1.0/1.1 with stream
		 * and block ciphers, there is at least a MAC which is at minimum 16
		 * bytes for MD5. In TLS 1.2, AEAD adds an explicit nonce and auth tag.
		 * For AES-GCM/CCM the auth tag is 16 bytes. AES_CCM_8 (RFC 6655) uses 8
		 * byte auth tags, but the explicit nonce is also 8 (sums up to 16).
		 *
		 * So anything smaller than 16 bytes is assumed to be plaintext.
		 */
		return false
	}
	maybeType := data[0]
	d := make([]byte, 4)
	for k, v := range data[1:4] {
		d[k+1] = v
	}
	if uint32(h.Length)-binary.BigEndian.Uint32(d) != 4 {
		return true
	}
	if _, ok := handShakeTypeMap[maybeType]; !ok {
		return true
	}
	return false
}

// DecodeFromBytes decodes the slice into the TLS struct.
func (t *TLSHandshakeRecord) decodeFromBytes(h TLSRecordHeader, data []byte, df gopacket.DecodeFeedback) error {
	// TLS Record Header
	t.ContentType = h.ContentType
	t.Version = h.Version
	t.Length = h.Length

	if t.isEncryptedHandshakeMessage(h, data) {
		return nil
	}
	if len(data) < 1 {
		df.SetTruncated()
		return errors.New("TLS handshake record too short")
	}
	handshakeType := data[0]
	switch handshakeType {
	case TLSHandshakeClientHello:
		return t.ClientHello.decodeFromBytes(data, df)
	case TLSHandshakeClientKeyExchange:
		t.ClientKeyChange.decodeFromBytes(data, df)
	default:
		return errors.New("Unknown TLS handshake type")
		// TODO
	}

	return nil
}
