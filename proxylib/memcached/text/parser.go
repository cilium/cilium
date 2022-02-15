// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// text memcache protocol parser based on https://github.com/memcached/memcached/blob/master/doc/protocol.txt

package text

import (
	"bytes"
	"strconv"

	cilium "github.com/cilium/proxy/go/cilium/api"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/proxylib/memcached/meta"
	"github.com/cilium/cilium/proxylib/proxylib"
)

// ParserFactory implements proxylib.ParserFactory
type ParserFactory struct{}

// Create creates memcached parser
func (p *ParserFactory) Create(connection *proxylib.Connection) interface{} {
	logrus.Debugf("ParserFactory: Create: %v", connection)
	return &Parser{connection: connection, replyQueue: make([]*replyIntent, 0)}
}

// compile time check for interface implementation
var _ proxylib.ParserFactory = &ParserFactory{}

// ParserFactoryInstance creates text parser for unified memcached parser
var ParserFactoryInstance *ParserFactory

// Parser implements proxylib.Parser
type Parser struct {
	connection *proxylib.Connection

	replyQueue []*replyIntent

	//set to true when watch command is observed
	watching bool
}

type replyIntent struct {
	command []byte
	denied  bool
}

var _ proxylib.Parser = &Parser{}

// consts indicating number of tokens in memcache command that indicates noreply command
const (
	casWithNoreplyFields     = 7
	storageWithNoreplyFields = 6
	deleteWithNoreplyFields  = 3
	incrWithNoreplyFields    = 4
	touchWithNoreplyFields   = 4
)

// OnData parses text memcached data
func (p *Parser) OnData(reply, endStream bool, dataBuffers [][]byte) (proxylib.OpType, int) {
	if reply {
		injected := p.injectFromQueue()
		if injected > 0 {
			return proxylib.INJECT, injected
		}
		if len(dataBuffers) == 0 {
			return proxylib.NOP, 0
		}
	}

	// TODO: don't copy data to new slices
	data := (bytes.Join(dataBuffers, []byte{}))
	logrus.Debugf("Data length: %d", len(data))

	linefeed := bytes.Index(data, []byte("\r\n"))
	if linefeed < 0 {
		logrus.Debugf("Did not receive full first line")
		if len(data) > 0 && data[len(data)-1] == '\r' {
			return proxylib.MORE, 1
		}
		return proxylib.MORE, 2
	}

	// TODO: iterate over data without copying it to new slices
	// Tokenizing in memcached is done by spaces: https://github.com/memcached/memcached/blob/master/memcached.c#L2978
	tokens := bytes.Fields(data[:linefeed])

	if !reply {
		meta := meta.MemcacheMeta{
			Command: string(tokens[0]),
		}
		command := tokens[0]

		frameLength := linefeed + 2
		hasNoreply := false
		switch {
		case p.isCommandRetrieval(command):
			// get, gets, gat, gats
			if bytes.HasPrefix(command, []byte("get")) {
				meta.Keys = tokens[1:]
			} else if bytes.HasPrefix(command, []byte("gat")) {
				meta.Keys = tokens[2:]
			}
		case p.isCommandStorage(command):
			// storage commands
			meta.Keys = tokens[1:2]
			nBytes, err := strconv.Atoi(string(tokens[4]))
			if err != nil {
				logrus.Error("Failed to parse storage payload length")
				return proxylib.ERROR, 0
			}
			// 2 additional bytes for terminating linefeed
			frameLength += nBytes + 2

			if command[0] == 'c' { //storage command is "cas"
				hasNoreply = len(tokens) == casWithNoreplyFields
			} else {
				hasNoreply = len(tokens) == storageWithNoreplyFields
			}
		case p.isCommandDelete(command):
			meta.Keys = tokens[1:2]
			hasNoreply = len(tokens) == deleteWithNoreplyFields
		case p.isCommandIncrDecr(command):
			meta.Keys = tokens[1:2]
			hasNoreply = len(tokens) == incrWithNoreplyFields
		case bytes.Equal(command, []byte("touch")):
			meta.Keys = tokens[1:2]
			hasNoreply = len(tokens) == touchWithNoreplyFields
		case bytes.Equal(command, []byte("slabs")),
			bytes.Equal(command, []byte("lru")),
			bytes.Equal(command, []byte("lru_crawler")),
			bytes.Equal(command, []byte("stats")),
			bytes.Equal(command, []byte("version")),
			bytes.Equal(command, []byte("misbehave")):

			meta.Keys = [][]byte{}
		case bytes.Equal(command, []byte("flush_all")),
			bytes.Equal(command, []byte("cache_memlimit")):
			meta.Keys = [][]byte{}
			hasNoreply = bytes.Equal(tokens[len(tokens)-1], []byte("noreply"))
		case bytes.Equal(command, []byte("quit")):
			meta.Keys = [][]byte{}
			hasNoreply = true
		case bytes.Equal(command, []byte("watch")):
			meta.Keys = [][]byte{}
			p.watching = true
		default:
			logrus.Error("Could not parse text memcache frame")
			return proxylib.ERROR, 0
		}
		logEntry := &cilium.LogEntry_GenericL7{
			GenericL7: &cilium.L7LogEntry{
				Proto: "textmemcached",
				Fields: map[string]string{
					"command": meta.Command,
					"keys":    string(bytes.Join(meta.Keys, []byte(", "))),
				},
			},
		}

		r := &replyIntent{
			command: command,
		}

		matches := p.connection.Matches(meta)

		if matches {
			r.denied = false
			if !hasNoreply {
				p.replyQueue = append(p.replyQueue, r)
			}
			p.connection.Log(cilium.EntryType_Request, logEntry)
			return proxylib.PASS, frameLength
		}

		r.denied = true
		if !hasNoreply {
			if len(p.replyQueue) == 0 {
				p.injectDeniedMessage()
			} else {
				p.replyQueue = append(p.replyQueue, r)
			}
		}
		p.connection.Log(cilium.EntryType_Denied, logEntry)
		return proxylib.DROP, frameLength
	}

	//reply
	logrus.Debugf("reply, parsing to figure out if we have it all")

	intent := p.replyQueue[0]

	logEntry := &cilium.LogEntry_GenericL7{
		GenericL7: &cilium.L7LogEntry{
			Proto: "textmemcached",
			Fields: map[string]string{
				"command": string(intent.command),
			},
		},
	}
	if p.watching {
		// in watch mode we pass all replied lines
		return proxylib.PASS, linefeed + 2
	}

	switch {
	case p.isErrorReply(tokens[0]),
		p.isCommandStorage(intent.command),
		p.isCommandDelete(intent.command),
		p.isCommandIncrDecr(intent.command),
		bytes.Equal(intent.command, []byte("touch")),
		bytes.Equal(intent.command, []byte("slabs")),
		bytes.Equal(intent.command, []byte("lru")),
		bytes.Equal(intent.command, []byte("flush_all")),
		bytes.Equal(intent.command, []byte("cache_memlimit")),
		bytes.Equal(intent.command, []byte("version")),
		bytes.Equal(intent.command, []byte("misbehave")):

		// passing one line of reply
		p.connection.Log(cilium.EntryType_Response, logEntry)
		p.replyQueue = p.replyQueue[1:]
		return proxylib.PASS, linefeed + 2
	case p.isCommandRetrieval(intent.command),
		bytes.Equal(intent.command, []byte("stats")):
		t, nBytes := p.untilEnd(data)
		if t == proxylib.PASS {
			p.connection.Log(cilium.EntryType_Response, logEntry)
			p.replyQueue = p.replyQueue[1:]
		}
		return t, nBytes
	case bytes.Equal(intent.command, []byte("lru_crawler")):
		// check if it's response line
		if bytes.Equal(tokens[0], []byte("OK")) ||
			bytes.Equal(tokens[0], []byte("BUSY")) ||
			bytes.Equal(tokens[0], []byte("BADCLASS")) {
			p.connection.Log(cilium.EntryType_Response, logEntry)
			p.replyQueue = p.replyQueue[1:]
			return proxylib.PASS, linefeed + 2
		}

		t, nBytes := p.untilEnd(data)
		if t == proxylib.PASS {
			p.connection.Log(cilium.EntryType_Response, logEntry)
			p.replyQueue = p.replyQueue[1:]
		}
		return t, nBytes
	}
	logrus.Error("Could not parse text memcache frame")
	return proxylib.ERROR, 0
}

const payloadEnd = "\r\nEND\r\n"

func (p *Parser) untilEnd(data []byte) (proxylib.OpType, int) {
	// TODO: optimise this to not ask per byte, but take VALUES lines into account
	endIndex := bytes.Index(data, []byte(payloadEnd))
	if endIndex > 0 {
		return proxylib.PASS, endIndex + len(payloadEnd)
	}
	return proxylib.MORE, 1
}

func (p *Parser) isCommandRetrieval(cmd []byte) bool {
	return bytes.HasPrefix(cmd, []byte("get")) ||
		bytes.HasPrefix(cmd, []byte("gat"))
}

func (p *Parser) isCommandStorage(cmd []byte) bool {
	return bytes.Equal(cmd, []byte("set")) ||
		bytes.Equal(cmd, []byte("add")) ||
		bytes.Equal(cmd, []byte("replace")) ||
		bytes.Equal(cmd, []byte("append")) ||
		bytes.Equal(cmd, []byte("prepend")) ||
		bytes.Equal(cmd, []byte("cas"))
}

func (p *Parser) isCommandDelete(cmd []byte) bool {
	return bytes.Equal(cmd, []byte("delete"))
}

func (p *Parser) isCommandIncrDecr(cmd []byte) bool {
	return bytes.Equal(cmd, []byte("incr")) ||
		bytes.Equal(cmd, []byte("decr"))
}

func (p *Parser) isErrorReply(firstToken []byte) bool {
	return bytes.Equal(firstToken, []byte("ERROR")) ||
		bytes.Equal(firstToken, []byte("CLIENT_ERROR")) ||
		bytes.Equal(firstToken, []byte("SERVER_ERROR"))
}

// returns injected bytes
func (p *Parser) injectFromQueue() int {
	injected := 0
	for _, rep := range p.replyQueue {
		if rep.denied {
			injected++
			p.injectDeniedMessage()
		} else {
			break
		}

	}
	if injected > 0 {
		p.replyQueue = p.replyQueue[injected:]
	}
	return injected * len(DeniedMsg)
}

func (p *Parser) injectDeniedMessage() {
	p.connection.Inject(true, DeniedMsg)
}

// DeniedMsg is sent if policy denies the request. Exported for tests
var DeniedMsg = []byte("CLIENT_ERROR access denied\r\n")

// ErrorMsg is standard memcached error line
var ErrorMsg = []byte("ERROR\r\n")
