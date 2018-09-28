// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// text memcache protocol parser based on https://github.com/memcached/memcached/blob/master/doc/protocol.txt

package text

import (
	"bytes"
	"strconv"

	"github.com/cilium/cilium/pkg/envoy/cilium"
	"github.com/cilium/cilium/proxylib/memcached/meta"
	"github.com/cilium/cilium/proxylib/proxylib"

	log "github.com/sirupsen/logrus"
)

// ParserFactory implements proxylib.ParserFactory
type ParserFactory struct{}

// Create creates binary memcached parser
func (p *ParserFactory) Create(connection *proxylib.Connection) proxylib.Parser {
	log.Infof("ParserFactory: Create: %v", connection)
	return &Parser{connection: connection, replyQueue: make([]*replyIntent, 0)}
}

// compile time check for interface implementation
var _ proxylib.ParserFactory = &ParserFactory{}

// ParserFactory creates text parser for unified memcached parser
var ParserFactoryInstance *ParserFactory

// Parser implements proxylib.Parser
type Parser struct {
	connection *proxylib.Connection

	requestCount uint32
	replyCount   uint32
	replyQueue   []*replyIntent
}

type replyIntent struct {
	command   []byte
	requestID uint32
	denied    bool
}

var _ proxylib.Parser = &Parser{}

// OnData parses binary memcached data
func (p *Parser) OnData(reply, endStream bool, dataBuffers [][]byte, offset int) (proxylib.OpType, int) {
	log.Infof("Text memcached OnData with offset %d", offset)

	if reply {
		if p.injectFromQueue() {
			return proxylib.INJECT, len(DeniedMsg)
		}
		if len(dataBuffers) == 0 {
			return proxylib.NOP, 0
		}
	}

	// TODO: don't copy data to new slices
	data := (bytes.Join(dataBuffers, []byte{}))[offset:]
	log.Infof("Data length: %d", len(data))

	linefeed := bytes.Index(data, []byte("\r\n"))
	if linefeed < 0 {
		log.Infof("Did not receive full first line, asking for 1 byte more")
		return proxylib.MORE, 1
	}

	// TODO: iterate over data without copying it to new slices
	// Tokenizing in memcached is done by spaces: https://github.com/memcached/memcached/blob/master/memcached.c#L2978
	tokens := bytes.Fields(data[:linefeed])

	if !reply {
		meta := meta.MemcacheMeta{
			Command:  tokens[0],
			IsBinary: false,
		}

		frameLength := 0
		noreply := false
		if p.isCommandRetrieval(meta.Command) {
			// get, gets, gat, gats
			if bytes.HasPrefix(meta.Command, []byte("get")) {
				meta.Keys = tokens[1:]
			} else if bytes.HasPrefix(meta.Command, []byte("gat")) {
				meta.Keys = tokens[2:]
			}
			frameLength = linefeed + 2
		} else if p.isCommandStorage(meta.Command) {
			// storage commands
			meta.Keys = tokens[1:2]
			nBytes, err := strconv.Atoi(string(tokens[4]))
			if err != nil {
				log.Error("Failed to parse storage payload length")
				return proxylib.ERROR, 0
			}
			// 2 additional bytes for terminating linefeed
			frameLength = linefeed + 2 + nBytes + 2

			if meta.Command[0] == 'c' { //storage command is "cas"
				noreply = len(tokens) == 7
			} else {
				noreply = len(tokens) == 6
			}
		} else if p.isCommandDelete(meta.Command) {
			meta.Keys = tokens[1:2]
			noreply = len(tokens) == 3
			frameLength = linefeed + 2
		} else if p.isCommandIncrDecr(meta.Command) {
			meta.Keys = tokens[1:2]
			noreply = len(tokens) == 4
			frameLength = linefeed + 2
		} else if bytes.Equal(meta.Command, []byte("touch")) {
			meta.Keys = tokens[1:2]
			noreply = len(tokens) == 4
			frameLength = linefeed + 2
		} else if bytes.Equal(meta.Command, []byte("slabs")) ||
			bytes.Equal(meta.Command, []byte("lru")) ||
			bytes.Equal(meta.Command, []byte("lru_crawler")) ||
			bytes.Equal(meta.Command, []byte("stats")) ||
			bytes.Equal(meta.Command, []byte("version")) ||
			bytes.Equal(meta.Command, []byte("misbehave")) {

			meta.Keys = [][]byte{}
			frameLength = linefeed + 2
		} else if bytes.Equal(meta.Command, []byte("flush_all")) ||
			bytes.Equal(meta.Command, []byte("cache_memlimit")) {
			meta.Keys = [][]byte{}
			noreply = bytes.Equal(tokens[len(tokens)-1], []byte("noreply"))
			frameLength = linefeed + 2
		} else if bytes.Equal(meta.Command, []byte("quit")) {
			meta.Keys = [][]byte{}
			noreply = true
			frameLength = linefeed + 2
		} else {
			log.Error("Could not parse text memcache frame")
			return proxylib.ERROR, 0
		}
		logEntry := &cilium.LogEntry_GenericL7{
			&cilium.L7LogEntry{
				Proto: "textmemcached",
				Fields: map[string]string{
					"command": string(meta.Command),
					"keys":    string(bytes.Join(meta.Keys, []byte(", "))),
				},
			},
		}

		p.requestCount++
		r := &replyIntent{
			requestID: p.requestCount,
			command:   meta.Command,
		}

		matches := p.connection.Matches(meta)

		if matches {
			r.denied = false
			p.replyQueue = append(p.replyQueue, r)
			p.connection.Log(cilium.EntryType_Request, logEntry)
			return proxylib.PASS, frameLength
		}

		r.denied = true
		if !noreply {
			p.injectDeniedMessage()
			if p.requestCount == p.replyCount+1 {
			} else {
				p.replyQueue = append(p.replyQueue, r)
			}
		}
		p.connection.Log(cilium.EntryType_Denied, logEntry)
		return proxylib.DROP, frameLength
	}
	//reply
	log.Debugf("reply, parsing to figure out if we have it all")

	intent := p.replyQueue[0]

	logEntry := &cilium.LogEntry_GenericL7{
		&cilium.L7LogEntry{
			Proto: "textmemcached",
			Fields: map[string]string{
				"command": string(intent.command),
			},
		},
	}

	if p.isErrorReply(tokens[0]) ||
		p.isCommandStorage(intent.command) ||
		p.isCommandDelete(intent.command) ||
		p.isCommandIncrDecr(intent.command) ||
		bytes.Equal(intent.command, []byte("touch")) ||
		bytes.Equal(intent.command, []byte("slabs")) ||
		bytes.Equal(intent.command, []byte("lru")) ||
		bytes.Equal(intent.command, []byte("flush_all")) ||
		bytes.Equal(intent.command, []byte("cache_memlimit")) ||
		bytes.Equal(intent.command, []byte("version")) ||
		bytes.Equal(intent.command, []byte("misbehave")) {

		// passing one line of reply
		p.connection.Log(cilium.EntryType_Response, logEntry)
		return proxylib.PASS, linefeed + 2
	} else if p.isCommandRetrieval(intent.command) ||
		bytes.Equal(intent.command, []byte("stats")) {
		t, nBytes := p.untilEnd(data)
		if t == proxylib.PASS {
			p.connection.Log(cilium.EntryType_Response, logEntry)
			p.replyQueue = p.replyQueue[1:]
		}
		return t, nBytes
	} else if bytes.Equal(intent.command, []byte("lru_crawler")) {
		// check if it's response line
		if bytes.Equal(tokens[0], []byte("OK")) ||
			bytes.Equal(tokens[0], []byte("BUSY")) ||
			bytes.Equal(tokens[0], []byte("BADCLASS")) {
			p.connection.Log(cilium.EntryType_Response, logEntry)
			return proxylib.PASS, linefeed + 2
		}

		t, nBytes := p.untilEnd(data)
		if t == proxylib.PASS {
			p.connection.Log(cilium.EntryType_Response, logEntry)
			p.replyQueue = p.replyQueue[1:]
		}
		return t, nBytes
	}
	log.Error("Could not parse text memcache frame")
	return proxylib.ERROR, 0
}

func (p *Parser) untilEnd(data []byte) (proxylib.OpType, int) {
	// TODO: optimise this to not ask per byte, but take VALUES lines into account
	endIndex := bytes.Index(data, []byte("END\r\n"))
	if endIndex > 0 {
		return proxylib.PASS, endIndex + 5
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

func (p *Parser) injectFromQueue() bool {
	if len(p.replyQueue) > 0 {
		if p.replyQueue[0].requestID == p.replyCount+1 && p.replyQueue[0].denied {
			p.injectDeniedMessage()
			p.replyQueue = p.replyQueue[1:]
			return true
		}
	}
	return false
}

func (p *Parser) injectDeniedMessage() {
	p.connection.Inject(true, DeniedMsg)
	p.replyCount++
}

// DeniedMsg is sent if policy denies the request. Exported for tests
var DeniedMsg = []byte("CLIENT_ERROR access denied\r\n")

// ErrorMsg is standard memcached error line
var ErrorMsg = []byte("ERROR\r\n")
