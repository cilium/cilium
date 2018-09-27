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

package memcache

import (
	"bytes"
	"fmt"
	"regexp"

	"github.com/cilium/cilium/pkg/envoy/cilium"
	"github.com/cilium/cilium/proxylib/proxylib"

	"github.com/cilium/cilium/proxylib/memcached/binary"
	"github.com/cilium/cilium/proxylib/memcached/meta"
	"github.com/cilium/cilium/proxylib/memcached/text"

	log "github.com/sirupsen/logrus"
)

// MemcacheRule matches against memcached requests
type MemcacheRule struct {
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

// Matches returns true if the MemcacheRule matches
func (rule *MemcacheRule) Matches(data interface{}) bool {
	log.Debugf("memcache checking rule %v", *rule)

	packetMeta, ok := data.(meta.MemcacheMeta)

	if !ok {
		log.Debugf("Wrong type supplied to MemcacheRule.Matches")
		return false
	}

	if packetMeta.IsBinary {
		if !rule.matchOpcode(packetMeta.Opcode) {
			return false
		}
	} else {
		if !rule.matchCommand(string(packetMeta.Command)) {
			return false
		}
	}

	if rule.keyExact != "" {
		for _, key := range packetMeta.Keys {
			if !bytes.Equal(rule.keyExactBytes, key) {
				return false
			}
		}
		return true
	}

	if rule.keyPrefix != "" {
		for _, key := range packetMeta.Keys {
			if !bytes.HasPrefix(key, rule.keyPrefixBytes) {
				return false
			}
		}
		return true
	}

	if rule.keyRegex != "" {
		for _, key := range packetMeta.Keys {
			if !rule.regex.Match(key) {
				return false
			}
		}
		return true
	}

	log.Debugf("No key rule specified, matching by command")
	return true
}

func (rule *MemcacheRule) matchCommand(cmd string) bool {
	_, ok := rule.commands.text[cmd]
	return ok
}

func (rule *MemcacheRule) matchOpcode(code byte) bool {
	_, ok := rule.commands.binary[code]
	return ok
}

// L7MemcacheRuleParser parses protobuf L7 rules to and array of MemcacheRule
// May panic
func L7MemcacheRuleParser(rule *cilium.PortNetworkPolicyRule) []proxylib.L7NetworkPolicyRule {
	l7Rules := rule.GetL7Rules()
	if l7Rules == nil {
		proxylib.ParseError("Can't get L7 rules", rule)
	}
	var rules []proxylib.L7NetworkPolicyRule
	for _, l7Rule := range l7Rules.GetL7Rules() {
		var br MemcacheRule
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
		log.Debugf("Parsed MemcacheRule pair: %v", br)
		rules = append(rules, &br)
	}
	return rules
}

// MemcacheParserFactory implements proxylib.ParserFactory
type MemcacheParserFactory struct{}

// Create creates memcached parser
func (p *MemcacheParserFactory) Create(connection *proxylib.Connection) proxylib.Parser {
	log.Debugf("MemcacheParserFactory: Create: %v", connection)
	return &MemcacheParser{
		connection:   connection,
		textParser:   text.TextMemcacheParserFactoryInstance.Create(connection),
		binaryParser: binary.BinaryMemcacheParserFactoryInstance.Create(connection),
	}
}

// compile time check for interface implementation
var _ proxylib.ParserFactory = &MemcacheParserFactory{}

var memcacheParserFactory *MemcacheParserFactory

const (
	parserName = "memcache"
)

func init() {
	log.Info("init(): Registering memcacheParserFactory")
	proxylib.RegisterParserFactory(parserName, memcacheParserFactory)
	proxylib.RegisterL7RuleParser(parserName, L7MemcacheRuleParser)
}

// MemcacheParser implements proxylib.Parser
type MemcacheParser struct {
	connection   *proxylib.Connection
	textParser   proxylib.Parser
	binaryParser proxylib.Parser
	isBinary     *bool
}

var _ proxylib.Parser = &MemcacheParser{}
var t = true
var f = false

// OnData parses binary memcached data
func (p *MemcacheParser) OnData(reply, endStream bool, dataBuffers [][]byte, offset int) (proxylib.OpType, int) {
	if p.isBinary == nil {
		remainingOffset := offset
		var magicByte byte

		for _, buf := range dataBuffers {
			if len(buf) > remainingOffset {
				magicByte = buf[remainingOffset]
				break
			} else {
				remainingOffset = remainingOffset - len(buf)
			}
		}
		if magicByte >= 128 {
			p.isBinary = &t

		} else {
			p.isBinary = &f
		}
	}
	if *p.isBinary {
		return p.binaryParser.OnData(reply, endStream, dataBuffers, offset)
	}
	return p.textParser.OnData(reply, endStream, dataBuffers, offset)
}

type memcacheCommandSet struct {
	text   map[string]struct{}
	binary map[byte]struct{}
}

// empty var for filling map below which will be used as set
var e struct{} = struct{}{}

// MemcacheOpCodeMap maps human-readable names of memcached operations and groups to opcodes
var MemcacheOpCodeMap = map[string]memcacheCommandSet{
	"add": memcacheCommandSet{
		text:   map[string]struct{}{"add": e},
		binary: map[byte]struct{}{2: e, 18: e},
	},
	"set": memcacheCommandSet{
		text:   map[string]struct{}{"set": e},
		binary: map[byte]struct{}{1: e, 17: e},
	},
	"replace": memcacheCommandSet{
		text:   map[string]struct{}{"replace": e},
		binary: map[byte]struct{}{3: e, 19: e},
	},
	"append": memcacheCommandSet{
		text:   map[string]struct{}{"append": e},
		binary: map[byte]struct{}{14: e, 25: e},
	},
	"prepend": memcacheCommandSet{
		text:   map[string]struct{}{"prepend": e},
		binary: map[byte]struct{}{15: e, 26: e},
	},
	"cas": memcacheCommandSet{
		text:   map[string]struct{}{"cas": e},
		binary: map[byte]struct{}{},
	},
	"incr": memcacheCommandSet{
		text:   map[string]struct{}{"incr": e},
		binary: map[byte]struct{}{5: e, 21: {}},
	},
	"decr": memcacheCommandSet{
		text:   map[string]struct{}{"decr": e},
		binary: map[byte]struct{}{6: e, 22: {}},
	},
	"storage": memcacheCommandSet{
		text: map[string]struct{}{
			"add":     e,
			"set":     e,
			"replace": e,
			"append":  e,
			"prepend": e,
			"cas":     e,
			"incr":    e,
			"decr":    e,
		},
		binary: map[byte]struct{}{
			1:  e,
			2:  e,
			3:  e,
			5:  e,
			6:  e,
			17: e,
			18: e,
			19: e,
			21: e,
			22: e,
			25: e,
			26: e,
		},
	},

	"get": memcacheCommandSet{
		text: map[string]struct{}{"get": e, "gets": e},
		binary: map[byte]struct{}{
			0:  e,
			9:  e,
			12: e,
			13: e,
		},
	},

	"delete": memcacheCommandSet{
		text: map[string]struct{}{"delete": e},
		binary: map[byte]struct{}{
			4:  e,
			20: e,
		},
	},

	"touch": memcacheCommandSet{
		text:   map[string]struct{}{"touch": e},
		binary: map[byte]struct{}{28: e},
	},

	"gat": memcacheCommandSet{
		text:   map[string]struct{}{"gat": e, "gats": e},
		binary: map[byte]struct{}{29: e, 30: e},
	},

	"writeGroup": memcacheCommandSet{
		text: map[string]struct{}{
			"add":     e,
			"set":     e,
			"replace": e,
			"append":  e,
			"prepend": e,
			"cas":     e,
			"incr":    e,
			"decr":    e,
			"delete":  e,
			"touch":   e,
		},
		binary: map[byte]struct{}{
			1:  e,
			2:  e,
			3:  e,
			4:  e,
			5:  e,
			6:  e,
			17: e,
			18: e,
			19: e,
			20: e,
			21: e,
			22: e,
			25: e,
			26: e,
			28: e,
		},
	},

	"slabs": memcacheCommandSet{
		text:   map[string]struct{}{"slabs": e},
		binary: map[byte]struct{}{},
	},

	"lru": memcacheCommandSet{
		text:   map[string]struct{}{"lru": e},
		binary: map[byte]struct{}{},
	},

	"lru_crawler": memcacheCommandSet{
		text:   map[string]struct{}{"lru_crawler": e},
		binary: map[byte]struct{}{},
	},

	// TODO: figure out how to handle connections in watch mode
	"watch": memcacheCommandSet{
		text:   map[string]struct{}{"watch": e},
		binary: map[byte]struct{}{},
	},

	"stats": memcacheCommandSet{
		text:   map[string]struct{}{"stats": e},
		binary: map[byte]struct{}{16: e},
	},

	"flush_all": memcacheCommandSet{
		text:   map[string]struct{}{"flush_all": e},
		binary: map[byte]struct{}{8: e, 24: e},
	},

	"cache_memlimit": memcacheCommandSet{
		text:   map[string]struct{}{"cache_memlimit": e},
		binary: map[byte]struct{}{},
	},

	"version": memcacheCommandSet{
		text:   map[string]struct{}{"version": e},
		binary: map[byte]struct{}{11: e},
	},

	"misbehave": memcacheCommandSet{
		text:   map[string]struct{}{"misbehave": e},
		binary: map[byte]struct{}{},
	},

	"quit": memcacheCommandSet{
		text:   map[string]struct{}{"quit": e},
		binary: map[byte]struct{}{7: e, 23: e},
	},

	"noop": memcacheCommandSet{
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{10: e},
	},
	"verbosity": memcacheCommandSet{
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{27: e},
	},
	"sasl-list-mechs": memcacheCommandSet{
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{32: e},
	},
	"sasl-auth": memcacheCommandSet{
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{33: e}},
	"sasl-step": memcacheCommandSet{
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{34: e}},
	"rget": memcacheCommandSet{
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{48: e}},
	"rset": memcacheCommandSet{
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{49: e}},
	"rsetq": memcacheCommandSet{
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{50: e}},
	"rappend": memcacheCommandSet{
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{51: e}},
	"rappendq": memcacheCommandSet{
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{52: e}},
	"rprepend": memcacheCommandSet{
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{53: e}},
	"rprependq": memcacheCommandSet{
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{54: e}},
	"rdelete": memcacheCommandSet{
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{55: e}},
	"rdeleteq": memcacheCommandSet{
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{56: e}},
	"rincr": memcacheCommandSet{
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{57: e}},
	"rincrq": memcacheCommandSet{
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{58: e}},
	"rdecr": memcacheCommandSet{
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{59: e}},
	"rdecrq": memcacheCommandSet{
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{60: e}},
	"set-vbucket": memcacheCommandSet{
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{61: e}},
	"get-vbucket": memcacheCommandSet{
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{62: e}},
	"del-vbucket": memcacheCommandSet{
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{63: e}},
	"tap-connect": memcacheCommandSet{
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{64: e}},
	"tap-mutation": memcacheCommandSet{
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{65: e}},
	"tap-delete": memcacheCommandSet{
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{66: e}},
	"tap-flush": memcacheCommandSet{
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{67: e}},
	"tap-opaque": memcacheCommandSet{
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{68: e}},
	"tap-vbucket-set": memcacheCommandSet{
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{69: e}},
	"tap-checkpoint-start": memcacheCommandSet{
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{70: e}},
	"tap-checkpoint-end": memcacheCommandSet{
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{71: e}},
}
