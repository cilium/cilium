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

func (t *TLSHandshakeRecordClientHello) decodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	t.HandshakeType = data[0]
	d := make([]byte, 4)
	for k, v := range data[1:4] {
		d[k+1] = v
	}
	t.Length = binary.BigEndian.Uint32(d)
	t.ProtocolVersion = TLSVersion(binary.BigEndian.Uint16(data[4:6]))
	t.Random = data[6:38]
	t.SessionIDLength = data[38]
	t.SessionID = data[39 : 39+t.SessionIDLength]
	t.CipherSuitsLength = binary.BigEndian.Uint16(data[39+t.SessionIDLength : 39+t.SessionIDLength+2])
	t.CipherSuits = data[39+t.SessionIDLength+2 : (39 + uint16(t.SessionIDLength) + 2 + t.CipherSuitsLength)]
	t.CompressionMethodsLength = data[(39 + uint16(t.SessionIDLength) + 2 + t.CipherSuitsLength)]
	t.CompressionMethods = data[(39+uint16(t.SessionIDLength)+2+t.CipherSuitsLength)+1 : (39+uint16(t.SessionIDLength)+2+t.CipherSuitsLength)+1+uint16(t.CompressionMethodsLength)]
	t.ExtensionsLength = binary.BigEndian.Uint16(data[(39+uint16(t.SessionIDLength)+2+t.CipherSuitsLength)+1+uint16(t.CompressionMethodsLength) : (39+uint16(t.SessionIDLength)+2+t.CipherSuitsLength)+1+uint16(t.CompressionMethodsLength)+2])

	// extract extension data
	data = data[((39 + uint16(t.SessionIDLength) + 2 + t.CipherSuitsLength) + 1 + uint16(t.CompressionMethodsLength) + 2) : ((39+uint16(t.SessionIDLength)+2+t.CipherSuitsLength)+1+uint16(t.CompressionMethodsLength)+2)+t.ExtensionsLength]
	t.Extensions = data
	for len(data) > 0 {
		if len(data) < 4 {
			break
		}
		extensionType := binary.BigEndian.Uint16(data[:2])
		length := binary.BigEndian.Uint16(data[2:4])
		if len(data) < 4+int(length) {
			break
		}
		switch TLSExtension(extensionType) {
		case TLSExtServerName:
			if len(data) > 6 {
				serverNameExtensionLength := binary.BigEndian.Uint16(data[4:6])
				entryType := data[6]
				if serverNameExtensionLength > 0 && entryType == 0 && len(data) > 8 { // 0 = DNS hostname
					hostnameLength := binary.BigEndian.Uint16(data[7:9])
					if len(data) > int(8+hostnameLength) {
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
	handshakeType := data[0]
	switch handshakeType {
	case TLSHandshakeClientHello:
		t.ClientHello.decodeFromBytes(data, df)
	case TLSHandshakeClientKeyExchange:
		t.ClientKeyChange.decodeFromBytes(data, df)
	default:
		return errors.New("Unknown TLS handshake type")
		// TODO
	}

	return nil
}
