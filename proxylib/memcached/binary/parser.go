// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package binary

import (
	"bytes"
	"encoding/binary"
	"strconv"

	cilium "github.com/cilium/proxy/go/cilium/api"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/proxylib/memcached/meta"
	"github.com/cilium/cilium/proxylib/proxylib"
)

// ParserFactory implements proxylib.ParserFactory
type ParserFactory struct{}

// Create creates binary memcached parser
func (p *ParserFactory) Create(connection *proxylib.Connection) interface{} {
	logrus.Debugf("ParserFactory: Create: %v", connection)
	return &Parser{connection: connection, injectQueue: make([]queuedInject, 0)}
}

// compile time check for interface implementation
var _ proxylib.ParserFactory = &ParserFactory{}

// ParserFactoryInstance creates binary parser for unified parser
var ParserFactoryInstance *ParserFactory

// Parser implements proxylib.Parser
type Parser struct {
	connection *proxylib.Connection

	requestCount uint32
	replyCount   uint32
	injectQueue  []queuedInject
}

var _ proxylib.Parser = &Parser{}

const headerSize = 24

// OnData parses binary memcached data
func (p *Parser) OnData(reply, endStream bool, dataBuffers [][]byte) (proxylib.OpType, int) {
	if reply {
		if p.injectFromQueue() {
			return proxylib.INJECT, len(DeniedMsgBase)
		}
		if len(dataBuffers) == 0 {
			return proxylib.NOP, 0
		}
	}

	//TODO don't copy data from buffers
	data := bytes.Join(dataBuffers, []byte{})
	logrus.Debugf("Data length: %d", len(data))

	if headerSize > len(data) {
		headerMissing := headerSize - len(data)
		logrus.Debugf("Did not receive needed header data, need %d more bytes", headerMissing)
		return proxylib.MORE, headerMissing
	}

	bodyLength := binary.BigEndian.Uint32(data[8:12])

	keyLength := binary.BigEndian.Uint16(data[2:4])
	extrasLength := data[4]

	if keyLength > 0 {
		neededData := headerSize + int(keyLength) + int(extrasLength)
		if neededData > len(data) {
			keyMissing := neededData - len(data)
			logrus.Debugf("Did not receive enough bytes for key, need %d more bytes", keyMissing)
			return proxylib.MORE, keyMissing
		}
	}

	opcode, key, err := p.getOpcodeAndKey(data, extrasLength, keyLength)
	if err != 0 {
		return proxylib.ERROR, int(err)
	}

	logEntry := &cilium.LogEntry_GenericL7{
		GenericL7: &cilium.L7LogEntry{
			Proto: "binarymemcached",
			Fields: map[string]string{
				"opcode": strconv.Itoa(int(opcode)),
				"key":    string(key),
			},
		},
	}

	// we don't filter reply traffic
	if reply {
		logrus.Debugf("reply, passing %d bytes", len(data))
		p.connection.Log(cilium.EntryType_Response, logEntry)
		p.replyCount++
		return proxylib.PASS, int(bodyLength + headerSize)
	}

	p.requestCount++

	matches := p.connection.Matches(meta.MemcacheMeta{
		Opcode: opcode,
		Keys:   [][]byte{key},
	})
	if matches {
		p.connection.Log(cilium.EntryType_Request, logEntry)
		return proxylib.PASS, int(bodyLength + headerSize)
	}

	magic := ResponseMagic | data[0]

	// This is done to ensure in-order replies
	if p.requestCount == p.replyCount+1 {
		p.injectDeniedMessage(magic)
	} else {
		p.injectQueue = append(p.injectQueue, queuedInject{magic, p.requestCount})
	}

	p.injectQueue = append(p.injectQueue, queuedInject{magic, p.requestCount})

	p.connection.Log(cilium.EntryType_Denied, logEntry)
	return proxylib.DROP, int(bodyLength + headerSize)
}

type queuedInject struct {
	magic     byte
	requestID uint32
}

func (p *Parser) injectDeniedMessage(magic byte) {
	deniedMsg := make([]byte, len(DeniedMsgBase))
	copy(deniedMsg, DeniedMsgBase)

	deniedMsg[0] = magic

	p.connection.Inject(true, deniedMsg)
	p.replyCount++
}

func (p *Parser) injectFromQueue() bool {
	if len(p.injectQueue) > 0 {
		if p.injectQueue[0].requestID == p.replyCount+1 {
			p.injectDeniedMessage(p.injectQueue[0].magic)
			p.injectQueue = p.injectQueue[1:]
			return true
		}
	}
	return false
}

const (
	// RequestMagic says that memcache frame is a request
	RequestMagic = 0x80
	// ResponseMagic says that memcache frame is a response
	ResponseMagic = 0x81
)

func (p *Parser) getOpcodeAndKey(data []byte, extrasLength byte, keyLength uint16) (byte, []byte, proxylib.OpError) {
	if data[0]&RequestMagic != RequestMagic {
		logrus.Warnf("Direction bit is 'response', but memcached parser only parses requests")
		return 0, []byte{}, proxylib.ERROR_INVALID_FRAME_TYPE
	}

	opcode := data[1]
	key := getMemcacheKey(data, extrasLength, keyLength)

	return opcode, key, 0
}

func getMemcacheKey(packet []byte, extrasLength byte, keyLength uint16) []byte {
	if keyLength == 0 {
		return []byte{}
	}
	return packet[headerSize+int(extrasLength) : headerSize+int(extrasLength)+int(keyLength)]
}

// DeniedMsgBase is sent if policy denies the request. Exported for tests
var DeniedMsgBase = []byte{
	0x81, 0, 0, 0,
	0, 0, 0, 8,
	0, 0, 0, 0x0d,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	'a', 'c', 'c',
	'e', 's', 's',
	' ', 'd', 'e',
	'n', 'i', 'e',
	'd'}
