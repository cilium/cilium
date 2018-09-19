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

package textmemcache

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"

	"github.com/cilium/cilium/pkg/envoy/cilium"
	"github.com/cilium/cilium/proxylib/proxylib"

	log "github.com/sirupsen/logrus"
)

// TextMemcacheRule matches against memcached requests
type TextMemcacheRule struct {
	// opCode group name
	command string

	keyExact  string
	keyPrefix string
	keyRegex  string

	// allowed commands
	commands memcacheCommandSet
	// compiled regex
	keyExactBytes  []byte
	keyPrefixBytes []byte
	regex          *regexp.Regexp
}

type textMemcacheMeta struct {
	command []byte
	keys    [][]byte
}

// Matches returns true if the TextMemcacheRule matches
func (rule *TextMemcacheRule) Matches(data interface{}) bool {
	log.Infof("textmemcache checking rule %v", *rule)

	packetMeta := data.(textMemcacheMeta)

	if !rule.matchCommand(string(packetMeta.command)) {
		return false
	}

	if rule.keyExact != "" {
		for _, key := range packetMeta.keys {
			if !bytes.Equal(rule.keyExactBytes, key) {
				return false
			}
		}
		return true
	}

	if rule.keyPrefix != "" {
		for _, key := range packetMeta.keys {
			if !bytes.HasPrefix(key, rule.keyPrefixBytes) {
				return false
			}
		}
		return true
	}

	if rule.keyRegex != "" {
		for _, key := range packetMeta.keys {
			if !rule.regex.Match(key) {
				return false
			}
		}
		return true
	}

	log.Infof("No key rule specified, matching by opcode")
	return true
}

func (rule *TextMemcacheRule) matchCommand(cmd string) bool {
	_, ok := rule.commands[cmd]
	return ok
}

// L7TextMemcacheRuleParser parses protobuf L7 rules to and array of TextMemcacheRule
// May panic
func L7TextMemcacheRuleParser(rule *cilium.PortNetworkPolicyRule) []proxylib.L7NetworkPolicyRule {
	l7Rules := rule.GetL7Rules()
	if l7Rules == nil {
		proxylib.ParseError("Can't get L7 rules", rule)
	}
	var rules []proxylib.L7NetworkPolicyRule
	for _, l7Rule := range l7Rules.GetL7Rules() {
		var br TextMemcacheRule
		for k, v := range l7Rule.Rule {
			switch k {
			case "command":
				br.command = v
				br.commands = MemcacheOpCodeMap[v]
			case "keyExact":
				br.keyExact = v
				br.keyExactBytes = []byte(v)
			case "keyPrefix":
				br.keyPrefix = v
				br.keyPrefixBytes = []byte(v)
			case "keyRegex":
				br.keyRegex = v
				br.regex = regexp.MustCompile(v)
			default:
				proxylib.ParseError(fmt.Sprintf("Unsupported key: %s", k), rule)
			}
		}
		if br.command == "" {
			proxylib.ParseError("command not specified", rule)
		}
		log.Infof("Parsed TextMemcacheRule pair: %v", br)
		rules = append(rules, &br)
	}
	return rules
}

// TextMemcacheParserFactory implements proxylib.ParserFactory
type TextMemcacheParserFactory struct{}

// Create creates binary memcached parser
func (p *TextMemcacheParserFactory) Create(connection *proxylib.Connection) proxylib.Parser {
	log.Infof("TextMemcacheParserFactory: Create: %v", connection)
	return &TextMemcacheParser{connection: connection, replyQueue: make([]*replyIntent, 0)}
}

// compile time check for interface implementation
var _ proxylib.ParserFactory = &TextMemcacheParserFactory{}

var textMemcacheParserFactory *TextMemcacheParserFactory

const (
	parserName = "textmemcache"
)

func init() {
	log.Info("init(): Registering textMemcacheParserFactory")
	proxylib.RegisterParserFactory(parserName, textMemcacheParserFactory)
	proxylib.RegisterL7RuleParser(parserName, L7TextMemcacheRuleParser)
}

// TextMemcacheParser implements proxylib.Parser
type TextMemcacheParser struct {
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

var _ proxylib.Parser = &TextMemcacheParser{}

// OnData parses binary memcached data
func (p *TextMemcacheParser) OnData(reply, endStream bool, dataBuffers [][]byte, offset int) (proxylib.OpType, int) {
	log.Infof("OnData with offset %d", offset)

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
		meta := textMemcacheMeta{
			command: tokens[0],
		}

		frameLength := 0
		noreply := false
		if p.isCommandRetrieval(meta.command) {
			// get, gets, gat, gats
			if bytes.HasPrefix(meta.command, []byte("get")) {
				meta.keys = tokens[1:]
			} else if bytes.HasPrefix(meta.command, []byte("gat")) {
				meta.keys = tokens[2:]
			}
			frameLength = linefeed + 2
		} else if p.isCommandStorage(meta.command) {
			// storage commands
			meta.keys = tokens[1:2]
			nBytes, err := strconv.Atoi(string(tokens[4]))
			if err != nil {
				log.Error("Failed to parse storage payload length")
				return proxylib.ERROR, 0
			}
			// 2 additional bytes for terminating linefeed
			frameLength = linefeed + 2 + nBytes + 2

			if meta.command[0] == 'c' { //storage command is "cas"
				noreply = len(tokens) == 7
			} else {
				noreply = len(tokens) == 6
			}
		} else if p.isCommandDelete(meta.command) {
			meta.keys = tokens[1:2]
			noreply = len(tokens) == 3
			frameLength = linefeed + 2
		} else if p.isCommandIncrDecr(meta.command) {
			meta.keys = tokens[1:2]
			noreply = len(tokens) == 4
			frameLength = linefeed + 2
		} else if bytes.Equal(meta.command, []byte("touch")) {
			meta.keys = tokens[1:2]
			noreply = len(tokens) == 4
			frameLength = linefeed + 2
		} else if bytes.Equal(meta.command, []byte("slabs")) ||
			bytes.Equal(meta.command, []byte("lru")) ||
			bytes.Equal(meta.command, []byte("lru_crawler")) ||
			bytes.Equal(meta.command, []byte("stats")) ||
			bytes.Equal(meta.command, []byte("version")) ||
			bytes.Equal(meta.command, []byte("misbehave")) {

			meta.keys = [][]byte{}
			frameLength = linefeed + 2
		} else if bytes.Equal(meta.command, []byte("flush_all")) ||
			bytes.Equal(meta.command, []byte("cache_memlimit")) {
			meta.keys = [][]byte{}
			noreply = bytes.Equal(tokens[len(tokens)-1], []byte("noreply"))
			frameLength = linefeed + 2
		} else if bytes.Equal(meta.command, []byte("quit")) {
			meta.keys = [][]byte{}
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
					"command": string(meta.command),
					"keys":    string(bytes.Join(meta.keys, []byte(", "))),
				},
			},
		}

		p.requestCount++
		r := &replyIntent{
			requestID: p.requestCount,
			command:   meta.command,
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
	} else {
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
}

func (p *TextMemcacheParser) untilEnd(data []byte) (proxylib.OpType, int) {
	// TODO: optimise this to not ask per byte, but take VALUES lines into account
	endIndex := bytes.Index(data, []byte("END\r\n"))
	if endIndex > 0 {
		return proxylib.PASS, endIndex + 5
	} else {
		return proxylib.MORE, 1
	}
}

func (p *TextMemcacheParser) isCommandRetrieval(cmd []byte) bool {
	return bytes.HasPrefix(cmd, []byte("get")) ||
		bytes.HasPrefix(cmd, []byte("gat"))
}

func (p *TextMemcacheParser) isCommandStorage(cmd []byte) bool {
	return bytes.Equal(cmd, []byte("set")) ||
		bytes.Equal(cmd, []byte("add")) ||
		bytes.Equal(cmd, []byte("replace")) ||
		bytes.Equal(cmd, []byte("append")) ||
		bytes.Equal(cmd, []byte("prepend")) ||
		bytes.Equal(cmd, []byte("cas"))
}

func (p *TextMemcacheParser) isCommandDelete(cmd []byte) bool {
	return bytes.Equal(cmd, []byte("delete"))
}

func (p *TextMemcacheParser) isCommandIncrDecr(cmd []byte) bool {
	return bytes.Equal(cmd, []byte("incr")) ||
		bytes.Equal(cmd, []byte("decr"))
}

func (p *TextMemcacheParser) isErrorReply(firstToken []byte) bool {
	return bytes.Equal(firstToken, []byte("ERROR")) ||
		bytes.Equal(firstToken, []byte("CLIENT_ERROR")) ||
		bytes.Equal(firstToken, []byte("SERVER_ERROR"))
}

func (p *TextMemcacheParser) injectFromQueue() bool {
	if len(p.replyQueue) > 0 {
		if p.replyQueue[0].requestID == p.replyCount+1 && p.replyQueue[0].denied {
			p.injectDeniedMessage()
			p.replyQueue = p.replyQueue[1:]
			return true
		}
	}
	return false
}

func (p *TextMemcacheParser) injectDeniedMessage() {
	p.connection.Inject(true, DeniedMsg)
	p.replyCount++
}

// DeniedMsg is sent if policy denies the request. Exported for tests
var DeniedMsg = []byte("CLIENT_ERROR access denied\r\n")

var ErrorMsg = []byte("ERROR\r\n")

type memcacheCommandSet map[string]struct{}
type e struct{}

// MemcacheOpCodeMap maps human-readable names of memcached operations and groups to opcodes
var MemcacheOpCodeMap = map[string]memcacheCommandSet{
	"add":     memcacheCommandSet{"add": e{}},
	"set":     memcacheCommandSet{"set": e{}},
	"replace": memcacheCommandSet{"replace": e{}},
	"append":  memcacheCommandSet{"append": e{}},
	"prepend": memcacheCommandSet{"prepend": e{}},
	"cas":     memcacheCommandSet{"cas": e{}},

	"get":  memcacheCommandSet{"get": e{}},
	"gets": memcacheCommandSet{"gets": e{}},

	"delete": memcacheCommandSet{"delete": e{}},

	"incr": memcacheCommandSet{"incr": e{}},
	"decr": memcacheCommandSet{"decr": e{}},

	"touch": memcacheCommandSet{"touch": e{}},

	"gat":  memcacheCommandSet{"gat": e{}},
	"gats": memcacheCommandSet{"gats": e{}},

	"slabs": memcacheCommandSet{"slabs": e{}},

	"lru": memcacheCommandSet{"lru": e{}},

	"lru_crawler": memcacheCommandSet{"lru_crawler": e{}},

	// TODO: figure out how to handle connections in watch mode
	"watch": memcacheCommandSet{"watch": e{}},

	"stats": memcacheCommandSet{"stats": e{}},

	"flush_all": memcacheCommandSet{"flush_all": e{}},

	"cache_memlimit": memcacheCommandSet{"cache_memlimit": e{}},

	"version": memcacheCommandSet{"version": e{}},

	"quit": memcacheCommandSet{"quit": e{}},

	"misbehave": memcacheCommandSet{"misbehave": e{}},
}
