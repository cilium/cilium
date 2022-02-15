// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// text memcache protocol parser based on https://github.com/memcached/memcached/blob/master/doc/protocol.txt

package memcache

import (
	"bytes"
	"fmt"
	"regexp"

	cilium "github.com/cilium/proxy/go/cilium/api"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/proxylib/memcached/binary"
	"github.com/cilium/cilium/proxylib/memcached/meta"
	"github.com/cilium/cilium/proxylib/memcached/text"
	"github.com/cilium/cilium/proxylib/proxylib"
)

// Rule matches against memcached requests
type Rule struct {
	// allowed commands
	commands memcacheCommandSet
	// compiled regex
	keyExact  []byte
	keyPrefix []byte
	regex     *regexp.Regexp

	empty bool
}

// Matches returns true if the Rule matches
func (rule *Rule) Matches(data interface{}) bool {
	logrus.Debugf("memcache checking rule %v", *rule)

	packetMeta, ok := data.(meta.MemcacheMeta)

	if !ok {
		logrus.Debugf("Wrong type supplied to Rule.Matches")
		return false
	}

	if rule.empty {
		return true
	}

	if packetMeta.IsBinary() {
		if !rule.matchOpcode(packetMeta.Opcode) {
			return false
		}
	} else {
		if !rule.matchCommand(packetMeta.Command) {
			return false
		}
	}

	if len(rule.keyExact) > 0 {
		for _, key := range packetMeta.Keys {
			if !bytes.Equal(rule.keyExact, key) {
				return false
			}
		}
		return true
	}

	if len(rule.keyPrefix) > 0 {
		for _, key := range packetMeta.Keys {
			if !bytes.HasPrefix(key, rule.keyPrefix) {
				return false
			}
		}
		return true
	}

	if rule.regex != nil {
		for _, key := range packetMeta.Keys {
			if !rule.regex.Match(key) {
				return false
			}
		}
		return true
	}

	logrus.Debugf("No key rule specified, accepted by command match")
	return true
}

func (rule *Rule) matchCommand(cmd string) bool {
	_, ok := rule.commands.text[cmd]
	return ok
}

func (rule *Rule) matchOpcode(code byte) bool {
	_, ok := rule.commands.binary[code]
	return ok
}

// L7RuleParser parses protobuf L7 rules to and array of Rule
// May panic
func L7RuleParser(rule *cilium.PortNetworkPolicyRule) []proxylib.L7NetworkPolicyRule {
	l7Rules := rule.GetL7Rules()
	if l7Rules == nil {
		return nil
	}

	allowRules := l7Rules.GetL7AllowRules()
	rules := make([]proxylib.L7NetworkPolicyRule, 0, len(allowRules))
	for _, l7Rule := range allowRules {
		var br Rule
		var commandFound = false
		for k, v := range l7Rule.Rule {
			switch k {
			case "command":
				br.commands, commandFound = MemcacheOpCodeMap[v]
			case "keyExact":
				br.keyExact = []byte(v)
			case "keyPrefix":
				br.keyPrefix = []byte(v)
			case "keyRegex":
				br.regex = regexp.MustCompile(v)
			default:
				proxylib.ParseError(fmt.Sprintf("Unsupported key: %s", k), rule)
			}
		}
		if !commandFound {
			if len(br.keyExact) > 0 || len(br.keyPrefix) > 0 || br.regex != nil {
				proxylib.ParseError("command not specified but key was provided", rule)
			} else {
				br.empty = true
			}
		}
		logrus.Debugf("Parsed Rule pair: %v", br)
		rules = append(rules, &br)
	}
	return rules
}

// ParserFactory implements proxylib.ParserFactory
type ParserFactory struct{}

// Create creates memcached parser
func (p *ParserFactory) Create(connection *proxylib.Connection) interface{} {
	logrus.Debugf("ParserFactory: Create: %v", connection)
	return &Parser{
		connection: connection,
	}
}

// compile time check for interface implementation
var _ proxylib.ParserFactory = &ParserFactory{}

var memcacheParserFactory *ParserFactory

const (
	parserName = "memcache"
)

func init() {
	logrus.Debug("init(): Registering memcacheParserFactory")
	proxylib.RegisterParserFactory(parserName, memcacheParserFactory)
	proxylib.RegisterL7RuleParser(parserName, L7RuleParser)
}

// Parser implements proxylib.Parser
type Parser struct {
	connection *proxylib.Connection
	parser     proxylib.Parser
}

var _ proxylib.Parser = &Parser{}

// OnData parses memcached data
func (p *Parser) OnData(reply, endStream bool, dataBuffers [][]byte) (proxylib.OpType, int) {
	if p.parser == nil {
		var magicByte byte
		if len(dataBuffers) > 0 && len(dataBuffers[0]) > 0 {
			magicByte = dataBuffers[0][0]
		} else {
			return proxylib.NOP, 0
		}

		if magicByte >= 128 {
			p.parser = binary.ParserFactoryInstance.Create(p.connection).(proxylib.Parser)
		} else {
			p.parser = text.ParserFactoryInstance.Create(p.connection).(proxylib.Parser)
		}
	}
	return p.parser.OnData(reply, endStream, dataBuffers)
}

type memcacheCommandSet struct {
	text   map[string]struct{}
	binary map[byte]struct{}
}

// empty var for filling map below which will be used as set
var e = struct{}{}

// MemcacheOpCodeMap maps operation names and groups used in policy rules to sets of operation names and opcodes that are allowed in such a policy rule.
// for more information on protocol check https://github.com/memcached/memcached/wiki/Protocols
var MemcacheOpCodeMap = map[string]memcacheCommandSet{
	"add": {
		text:   map[string]struct{}{"add": e},
		binary: map[byte]struct{}{2: e, 18: e},
	},
	"set": {
		text:   map[string]struct{}{"set": e},
		binary: map[byte]struct{}{1: e, 17: e},
	},
	"replace": {
		text:   map[string]struct{}{"replace": e},
		binary: map[byte]struct{}{3: e, 19: e},
	},
	"append": {
		text:   map[string]struct{}{"append": e},
		binary: map[byte]struct{}{14: e, 25: e},
	},
	"prepend": {
		text:   map[string]struct{}{"prepend": e},
		binary: map[byte]struct{}{15: e, 26: e},
	},
	"cas": {
		text:   map[string]struct{}{"cas": e},
		binary: map[byte]struct{}{},
	},
	"incr": {
		text:   map[string]struct{}{"incr": e},
		binary: map[byte]struct{}{5: e, 21: e},
	},
	"decr": {
		text:   map[string]struct{}{"decr": e},
		binary: map[byte]struct{}{6: e, 22: e},
	},
	"storage": {
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

	"get": {
		text: map[string]struct{}{"get": e, "gets": e},
		binary: map[byte]struct{}{
			0:  e,
			9:  e,
			12: e,
			13: e,
		},
	},

	"delete": {
		text: map[string]struct{}{"delete": e},
		binary: map[byte]struct{}{
			4:  e,
			20: e,
		},
	},

	"touch": {
		text:   map[string]struct{}{"touch": e},
		binary: map[byte]struct{}{28: e},
	},

	"gat": {
		text:   map[string]struct{}{"gat": e, "gats": e},
		binary: map[byte]struct{}{29: e, 30: e},
	},

	"writeGroup": {
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

	"slabs": {
		text:   map[string]struct{}{"slabs": e},
		binary: map[byte]struct{}{},
	},

	"lru": {
		text:   map[string]struct{}{"lru": e},
		binary: map[byte]struct{}{},
	},

	"lru_crawler": {
		text:   map[string]struct{}{"lru_crawler": e},
		binary: map[byte]struct{}{},
	},

	"watch": {
		text:   map[string]struct{}{"watch": e},
		binary: map[byte]struct{}{},
	},

	"stats": {
		text:   map[string]struct{}{"stats": e},
		binary: map[byte]struct{}{16: e},
	},

	"flush_all": {
		text:   map[string]struct{}{"flush_all": e},
		binary: map[byte]struct{}{8: e, 24: e},
	},

	"cache_memlimit": {
		text:   map[string]struct{}{"cache_memlimit": e},
		binary: map[byte]struct{}{},
	},

	"version": {
		text:   map[string]struct{}{"version": e},
		binary: map[byte]struct{}{11: e},
	},

	"misbehave": {
		text:   map[string]struct{}{"misbehave": e},
		binary: map[byte]struct{}{},
	},

	"quit": {
		text:   map[string]struct{}{"quit": e},
		binary: map[byte]struct{}{7: e, 23: e},
	},

	"noop": {
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{10: e},
	},
	"verbosity": {
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{27: e},
	},
	"sasl-list-mechs": {
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{32: e},
	},
	"sasl-auth": {
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{33: e}},
	"sasl-step": {
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{34: e}},
	"rget": {
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{48: e}},
	"rset": {
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{49: e}},
	"rsetq": {
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{50: e}},
	"rappend": {
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{51: e}},
	"rappendq": {
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{52: e}},
	"rprepend": {
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{53: e}},
	"rprependq": {
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{54: e}},
	"rdelete": {
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{55: e}},
	"rdeleteq": {
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{56: e}},
	"rincr": {
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{57: e}},
	"rincrq": {
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{58: e}},
	"rdecr": {
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{59: e}},
	"rdecrq": {
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{60: e}},
	"set-vbucket": {
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{61: e}},
	"get-vbucket": {
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{62: e}},
	"del-vbucket": {
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{63: e}},
	"tap-connect": {
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{64: e}},
	"tap-mutation": {
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{65: e}},
	"tap-delete": {
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{66: e}},
	"tap-flush": {
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{67: e}},
	"tap-opaque": {
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{68: e}},
	"tap-vbucket-set": {
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{69: e}},
	"tap-checkpoint-start": {
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{70: e}},
	"tap-checkpoint-end": {
		text:   map[string]struct{}{},
		binary: map[byte]struct{}{71: e}},
}
