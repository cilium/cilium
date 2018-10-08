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

package redis

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"

	"github.com/cilium/cilium/pkg/envoy/cilium"
	. "github.com/cilium/cilium/proxylib/proxylib"

	log "github.com/sirupsen/logrus"
)

//
// Redis Parser (RESP protocol, Redis 2.0+)
//
// https://redis.io/topics/protocol

// Current Redis parser supports filtering the text-based redis protocol messages.
//
// Current visibiity / policy mode focus on exact match
// Examples:
// cmd = 'get'      (any key for this command)
// key = 'users.*'  (any cmd for this key)
// cmd = 'get', key = 'users.*' (this cmd for this key)
//
// Note:  key regex is only supported for commands that accept a key as
// their first argument.   There are some commands that support multiple keys
// or keys not as their first argument.  Currently, such requests can only be
// matched using the 'cmd' field, and an un-specified key regex.

// map to test whether a 'cmd' is valid or not
// and whether we should expect it to have a key

const cmdInvalid = 0
const cmdSingleKeyFirst = 1
const cmdNoKey = 2
const cmdSpecialKey = 3

// list of commands based on https://redis.io/commands

var cmdMap = map[string]int{
	"append":            cmdSingleKeyFirst,
	"auth":              cmdNoKey,
	"bgrewriteaof":      cmdNoKey,
	"bgsave":            cmdNoKey,
	"bitcount":          cmdSingleKeyFirst,
	"bitfield":          cmdSingleKeyFirst,
	"bitop":             cmdSpecialKey,
	"bitpos":            cmdSingleKeyFirst,
	"blpop":             cmdSpecialKey,
	"brpop":             cmdSpecialKey,
	"brpoplpush":        cmdNoKey,
	"bzpopmin":          cmdSpecialKey,
	"bzpopmax":          cmdSpecialKey,
	"client":            cmdNoKey, // group all client cmds together
	"cluster":           cmdNoKey, // group all cluster cmds together
	"command":           cmdNoKey, // group all command cmds together
	"config":            cmdNoKey, // group all config cmds together
	"dbsize":            cmdNoKey,
	"debug":             cmdNoKey, // group all debug cmds together
	"decr":              cmdSingleKeyFirst,
	"decrby":            cmdSingleKeyFirst,
	"del":               cmdSingleKeyFirst,
	"discard":           cmdNoKey,
	"dump":              cmdSingleKeyFirst,
	"echo":              cmdNoKey,
	"eval":              cmdSpecialKey,
	"evalsha":           cmdSpecialKey,
	"exec":              cmdNoKey,
	"exists":            cmdSpecialKey,
	"expire":            cmdSingleKeyFirst,
	"expireat":          cmdSingleKeyFirst,
	"flushall":          cmdNoKey,
	"flushdb":           cmdNoKey,
	"geoadd":            cmdSingleKeyFirst,
	"geohash":           cmdSingleKeyFirst,
	"geopos":            cmdSingleKeyFirst,
	"geodist":           cmdSingleKeyFirst,
	"georadius":         cmdSingleKeyFirst,
	"georadiusbymember": cmdSingleKeyFirst,
	"get":               cmdSingleKeyFirst,
	"getbit":            cmdSingleKeyFirst,
	"getrange":          cmdSingleKeyFirst,
	"getset":            cmdSingleKeyFirst,
	"hdel":              cmdSingleKeyFirst,
	"hexists":           cmdSingleKeyFirst,
	"hget":              cmdSingleKeyFirst,
	"hgetall":           cmdSingleKeyFirst,
	"hincrby":           cmdSingleKeyFirst,
	"hincrbyfloat":      cmdSingleKeyFirst,
	"hkeys":             cmdSingleKeyFirst,
	"hlen":              cmdSingleKeyFirst,
	"hmget":             cmdSingleKeyFirst,
	"hmset":             cmdSingleKeyFirst,
	"hset":              cmdSingleKeyFirst,
	"hsetnx":            cmdSingleKeyFirst,
	"hstrlen":           cmdSingleKeyFirst,
	"hvals":             cmdSingleKeyFirst,
	"incr":              cmdSingleKeyFirst,
	"incrby":            cmdSingleKeyFirst,
	"incrbyfloat":       cmdSingleKeyFirst,
	"info":              cmdNoKey,
	"keys":              cmdNoKey,
	"lastsave":          cmdNoKey,
	"lindex":            cmdSingleKeyFirst,
	"linsert":           cmdSingleKeyFirst,
	"llen":              cmdSingleKeyFirst,
	"lpop":              cmdSingleKeyFirst,
	"lpush":             cmdSingleKeyFirst,
	"lpushx":            cmdSingleKeyFirst,
	"lrange":            cmdSingleKeyFirst,
	"lrem":              cmdSingleKeyFirst,
	"lset":              cmdSingleKeyFirst,
	"ltrim":             cmdSingleKeyFirst,
	"memory":            cmdNoKey, // group all debug cmds together
	"mget":              cmdSpecialKey,
	"migrate":           cmdNoKey,
	"monitor":           cmdNoKey,
	"move":              cmdSingleKeyFirst,
	"mset":              cmdSpecialKey,
	"msetnx":            cmdSpecialKey,
	"multi":             cmdNoKey,
	"object":            cmdNoKey,
	"persist":           cmdSingleKeyFirst,
	"pexpire":           cmdSingleKeyFirst,
	"pexpireat":         cmdSingleKeyFirst,
	"pfadd":             cmdSingleKeyFirst,
	"pfcount":           cmdSpecialKey,
	"pfmerge":           cmdSpecialKey,
	"ping":              cmdNoKey,
	"psetex":            cmdSingleKeyFirst,
	"psubscribe":        cmdNoKey, //TODO: consider adding matching on channel regex?
	"pubsub":            cmdNoKey,
	"pttl":              cmdSingleKeyFirst,
	"publish":           cmdNoKey,
	"punsubscribe":      cmdNoKey,
	"quit":              cmdNoKey,
	"randomkey":         cmdNoKey,
	"readonly":          cmdNoKey,
	"readwrite":         cmdNoKey,
	"rename":            cmdSingleKeyFirst,
	"renamenx":          cmdSingleKeyFirst,
	"restore":           cmdSingleKeyFirst,
	"role":              cmdNoKey,
	"rpop":              cmdSingleKeyFirst,
	"rpoplpush":         cmdNoKey,
	"rpush":             cmdSingleKeyFirst,
	"rpushx":            cmdSingleKeyFirst,
	"sadd":              cmdSingleKeyFirst,
	"save":              cmdNoKey,
	"scard":             cmdSingleKeyFirst,
	"script":            cmdNoKey, // group all script cmds together
	"sdiff":             cmdSingleKeyFirst,
	"sdiffstore":        cmdSpecialKey,
	"select":            cmdNoKey,
	"set":               cmdSingleKeyFirst,
	"setbit":            cmdSingleKeyFirst,
	"setex":             cmdSingleKeyFirst,
	"setnx":             cmdSingleKeyFirst,
	"setrange":          cmdSingleKeyFirst,
	"shutdown":          cmdNoKey,
	"sinter":            cmdSpecialKey,
	"sinterstore":       cmdSpecialKey,
	"sismember":         cmdSingleKeyFirst,
	"slaveof":           cmdNoKey,
	"replicaof":         cmdNoKey,
	"slowlog":           cmdNoKey,
	"smembers":          cmdSingleKeyFirst,
	"smove":             cmdNoKey,
	"sort":              cmdSingleKeyFirst,
	"spop":              cmdSingleKeyFirst,
	"srandmember":       cmdSingleKeyFirst,
	"srem":              cmdSingleKeyFirst,
	"strlen":            cmdSingleKeyFirst,
	"subscribe":         cmdNoKey,
	"sunion":            cmdSpecialKey,
	"sunionstore":       cmdSpecialKey,
	"swapdb":            cmdNoKey,
	"sync":              cmdNoKey,
	"time":              cmdNoKey,
	"touch":             cmdSpecialKey,
	"ttl":               cmdSingleKeyFirst,
	"type":              cmdSingleKeyFirst,
	"unsubscribe":       cmdNoKey,
	"unlink":            cmdSpecialKey,
	"unwatch":           cmdNoKey,
	"wait":              cmdNoKey,
	"watch":             cmdSpecialKey,
	"zadd":              cmdSingleKeyFirst,
	"zcard":             cmdSingleKeyFirst,
	"zcount":            cmdSingleKeyFirst,
	"zincrby":           cmdSingleKeyFirst,
	"zinterstore":       cmdSpecialKey,
	"zlexcount":         cmdSingleKeyFirst,
	"zpopmax":           cmdSingleKeyFirst,
	"zpopmin":           cmdSingleKeyFirst,
	"zrange":            cmdSingleKeyFirst,
	"zrangebylex":       cmdSingleKeyFirst,
	"zrevrangebylex":    cmdSingleKeyFirst,
	"zrangebyscore":     cmdSingleKeyFirst,
	"zrank":             cmdSingleKeyFirst,
	"zrem":              cmdSingleKeyFirst,
	"zremrangebylex":    cmdSingleKeyFirst,
	"zremrangebyrank":   cmdSingleKeyFirst,
	"zremrangebyscore":  cmdSingleKeyFirst,
	"zrevrange":         cmdSingleKeyFirst,
	"zrevrangebyscore":  cmdSingleKeyFirst,
	"zrevrank":          cmdSingleKeyFirst,
	"zscore":            cmdSingleKeyFirst,
	"zunionstore":       cmdSpecialKey,
	"scan":              cmdNoKey,
	"sscan":             cmdNoKey,
	"hscan":             cmdNoKey,
	"zscan":             cmdNoKey,
	"xinfo":             cmdNoKey,
	"xadd":              cmdSingleKeyFirst,
	"xtrim":             cmdSingleKeyFirst,
	"xdel":              cmdSingleKeyFirst,
	"xrange":            cmdSingleKeyFirst,
	"xrevrange":         cmdSingleKeyFirst,
	"xlen":              cmdSingleKeyFirst,
	"xread":             cmdNoKey,
	"xgroup":            cmdSpecialKey,
	"xreadgroup":        cmdNoKey,
	"xack":              cmdSingleKeyFirst,
	"xclaim":            cmdSingleKeyFirst,
	"xpending":          cmdSingleKeyFirst,
}

type RedisRule struct {
	cmdExact         string
	keyRegexCompiled *regexp.Regexp
}

func (rule *RedisRule) Matches(data interface{}) bool {
	// Cast 'data' to the type we give to 'Matches()'

	fullCmd, ok := data.(Command)
	if !ok {
		log.Warning("Matches() called with type other than redis.Command")
		return false
	}
	regexStr := ""
	if rule.keyRegexCompiled != nil {
		regexStr = rule.keyRegexCompiled.String()
	}

	log.Infof("Rule: cmd = '%s', key '%s'", rule.cmdExact, regexStr)

	cmd := strings.ToLower(string(fullCmd.Args[0]))

	if rule.cmdExact != "" && rule.cmdExact != cmd {
		log.Infof("RedisRule: key mismatch %v, %s", rule.cmdExact, cmd)
		return false
	}

	// TODO:  move some of this logic so it happens only once per
	//        per request, not once per policy rule.
	cmdType := cmdMap[cmd]
	switch cmdType {
	case cmdInvalid:
		log.Infof("Unknown redis command '%s', rejecting rule", cmd)
		return false
	case cmdSingleKeyFirst:
		if len(fullCmd.Args) > 1 {
			key := strings.ToLower(string(fullCmd.Args[1]))
			if rule.keyRegexCompiled != nil && !rule.keyRegexCompiled.MatchString(key) {
				log.Infof("RedisRule: key_regex mismatch '%v', '%s'", rule.keyRegexCompiled, key)
				return false
			}
		} else {
			log.Infof("Could not parse key for command '%s', rejecting", cmd)
			return false
		}
	case cmdSpecialKey:
		// TODO:  fixme to properly parse multi-key commands.
		//        for now, just reject if there is a key regex specified
		if len(regexStr) > 0 {
			log.Warnf("Failed to match special-key cmd '%s' due to key-regex", cmd)
			return false
		}
	case cmdNoKey:
		break
	}

	return true
}

// RedisRuleParser parses protobuf L7 rules to enforcement objects
// May panic
func RedisRuleParser(rule *cilium.PortNetworkPolicyRule) []L7NetworkPolicyRule {
	l7Rules := rule.GetL7Rules()
	if l7Rules == nil {
		ParseError("Can't get L7 rules.", rule)
	}
	var rules []L7NetworkPolicyRule
	for _, l7Rule := range l7Rules.GetL7Rules() {
		var rr RedisRule
		for k, v := range l7Rule.Rule {
			switch k {
			case "cmd":
				rr.cmdExact = strings.ToLower(v)
			case "key":
				if v != "" {
					rr.keyRegexCompiled = regexp.MustCompile(strings.ToLower(v))
				}
			default:
				ParseError(fmt.Sprintf("Unsupported key: %s", k), rule)
			}
		}

		// ensure that 'cmd' value is a valid cmd and that key is
		// only provided in scenarios when it makes sense.

		if len(rr.cmdExact) > 0 {
			// ensure this is a valid cmd
			res := cmdMap[rr.cmdExact]
			if res == cmdInvalid {
				ParseError(fmt.Sprintf("Unable to parse L7 redis rule with invalid cmd: '%s'",
					rr.cmdExact), rule)
			} else if res == cmdNoKey && rr.keyRegexCompiled != nil {
				ParseError(fmt.Sprintf("key regex not allowed for rule with cmd '%s'", rr.cmdExact), rule)
			} else if res == cmdSpecialKey && rr.keyRegexCompiled != nil {
				// this is temporary, as in the future we will properly parse a list of keys
				// from these commands, and potentially allow a list of keys to match
				ParseError(fmt.Sprintf("key regex not allowed for rule with cmd '%s'", rr.cmdExact), rule)
			}

		}

		log.Debugf("Parsed RedisRule pair: %v", rr)
		rules = append(rules, &rr)
	}
	return rules
}

type RedisParserFactory struct{}

var redisParserFactory *RedisParserFactory

func init() {
	log.Info("init(): Registering redisParserFactory")
	RegisterParserFactory("redis", redisParserFactory)
	RegisterL7RuleParser("redis", RedisRuleParser)
}

type RedisParser struct {
	connection *Connection
	inserted   bool
}

/*
type RedisRequestInfo struct {
	cmd string
	keys []string
}
*/

const accessDeniedStr = "-Error Access Denied\r\n"

func (pf *RedisParserFactory) Create(connection *Connection) Parser {
	log.Debugf("RedisParserFactory: Create: %v", connection)

	p := RedisParser{connection: connection}
	return &p
}

func (p *RedisParser) OnData(reply, endStream bool, dataArray [][]byte) (OpType, int) {

	// inefficient, but simple for now
	data := bytes.Join(dataArray, []byte{})
	if len(data) == 0 {
		return MORE, 1
	}

	if reply {
		// We currently only look at the request stream, not the reply
		// stream.  So technically we could "PASS" with a much higher number
		// here to improve efficiency.  At least at this point, we will keep
		// pass the data here for visibility.
		log.Infof("OnData: <== '%s'", data)
		return PASS, len(data)
	}

	log.Debugf("OnData: ==> '%s'", data)

	var consumed int
	cmd, err := readSingleCommand(data, &consumed)
	if err != nil {
		log.Infof("Parse error: %v", err)
		return ERROR, int(ERROR_INVALID_FRAME_LENGTH)
	}
	log.Infof("consumed = %d", consumed)
	if consumed == 0 {
		return MORE, 1
	}
	// if consumed is greater than zero, then we should
	// have at least one command
	if len(cmd.Args) == 0 {
		log.Infof("Consumed %d bytes, but have zero length cmd array", consumed)
		return ERROR, int(ERROR_INVALID_FRAME_LENGTH)
	}
	log.Infof("CMD Args = %v", cmd.Args)

	access_log_entry_type := cilium.EntryType_Request
	parser_action := PASS

	if !p.connection.Matches(cmd) {
		access_log_entry_type = cilium.EntryType_Denied
		parser_action = DROP
		p.connection.Inject(true, []byte(accessDeniedStr))
	}

	//
	key := ""
	if len(cmd.Args) > 1 {
		key = strings.ToLower(string(cmd.Args[1]))
	}
	p.connection.Log(access_log_entry_type,
		&cilium.LogEntry_GenericL7{
			GenericL7: &cilium.L7LogEntry{
				Proto: "redis",
				Fields: map[string]string{
					"cmd": strings.ToLower(string(cmd.Args[0])),
					"key": key,
				},
			},
		})

	return parser_action, consumed
}
