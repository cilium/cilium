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

package binary

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/cilium/cilium/pkg/envoy/cilium"
	"github.com/cilium/cilium/proxylib/proxylib"

	log "github.com/sirupsen/logrus"
)

// BinaryMemcacheRule matches against memcached requests
type BinaryMemcacheRule struct {
	// opCode group name
	opCode string

	keyExact  string
	keyPrefix string
	keyRegex  string

	// allowed opcodes
	opCodes []byte
	// compiled regex
	regex *regexp.Regexp
}

type binaryMemcacheMeta struct {
	opCode byte
	key    string
}

// Matches returns true if the BinaryMemcacheRule matches
func (rule *BinaryMemcacheRule) Matches(data interface{}) bool {
	log.Debugf("binarymemcache checking rule %v", *rule)

	packetMeta, ok := data.(binaryMemcacheMeta)
	if !ok {
		log.Warnf("BinaryMemcacheRule.Matches called with type other than binaryMemcacheMeta, failing to match")
		return false
	}

	if !rule.matchOpcode(packetMeta.opCode) {
		return false
	}

	if rule.keyExact != "" {
		return rule.keyExact == packetMeta.key
	}

	if rule.keyPrefix != "" {
		return strings.HasPrefix(packetMeta.key, rule.keyPrefix)
	}

	if rule.keyRegex != "" {
		return rule.regex.MatchString(packetMeta.key)
	}

	log.Debugf("No key rule specified, matching by opcode")
	return true
}

func (rule *BinaryMemcacheRule) matchOpcode(oc byte) bool {
	// this matches give opcode against a slice of allowed opcodes, which allows
	// to implement named opcode groups in rules
	return bytes.Contains(rule.opCodes, []byte{oc})
}

// L7BinaryMemcacheRuleParser parses protobuf L7 rules to and array of BinaryMemcacheRule
// May panic
func L7BinaryMemcacheRuleParser(rule *cilium.PortNetworkPolicyRule) []proxylib.L7NetworkPolicyRule {
	l7Rules := rule.GetL7Rules()
	if l7Rules == nil {
		proxylib.ParseError("Can't get L7 rules", rule)
	}
	var rules []proxylib.L7NetworkPolicyRule
	for _, l7Rule := range l7Rules.GetL7Rules() {
		var br BinaryMemcacheRule
		for k, v := range l7Rule.Rule {
			switch k {
			case "opCode":
				br.opCode = v
				br.opCodes = MemcacheOpCodeMap[v]
			case "keyExact":
				br.keyExact = v
			case "keyPrefix":
				br.keyPrefix = v
			case "keyRegex":
				br.keyRegex = v
				br.regex = regexp.MustCompile(v)
			default:
				proxylib.ParseError(fmt.Sprintf("Unsupported key: %s", k), rule)
			}
		}
		if br.opCode == "" {
			proxylib.ParseError("opCode not specified", rule)
		}
		log.Debugf("Parsed BinaryMemcacheRule pair: %v", br)
		rules = append(rules, &br)
	}
	return rules
}

// BinaryMemcacheParserFactory implements proxylib.ParserFactory
type BinaryMemcacheParserFactory struct{}

// Create creates binary memcached parser
func (p *BinaryMemcacheParserFactory) Create(connection *proxylib.Connection) proxylib.Parser {
	log.Infof("BinaryMemcacheParserFactory: Create: %v", connection)
	return &BinaryMemcacheParser{connection: connection, injectQueue: make([]queuedInject, 0)}
}

// compile time check for interface implementation
var _ proxylib.ParserFactory = &BinaryMemcacheParserFactory{}

var binaryMemcacheParserFactory *BinaryMemcacheParserFactory

const (
	parserName = "binarymemcache"
)

func init() {
	log.Info("init(): Registering binaryMemcacheParserFactory")
	proxylib.RegisterParserFactory(parserName, binaryMemcacheParserFactory)
	proxylib.RegisterL7RuleParser(parserName, L7BinaryMemcacheRuleParser)
}

// BinaryMemcacheParser implements proxylib.Parser
type BinaryMemcacheParser struct {
	connection *proxylib.Connection

	requestCount uint32
	replyCount   uint32
	injectQueue  []queuedInject
}

var _ proxylib.Parser = &BinaryMemcacheParser{}

const headerSize = 24

// OnData parses binary memcached data
func (p *BinaryMemcacheParser) OnData(reply, endStream bool, dataBuffers [][]byte) (proxylib.OpType, int) {
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
	log.Debugf("Data length: %d", len(data))

	if headerSize > len(data) {
		headerMissing := headerSize - len(data)
		log.Debugf("Did not receive needed header data, need %d more bytes", headerMissing)
		return proxylib.MORE, headerMissing
	}

	bodyLength := binary.BigEndian.Uint32(data[8:12])

	keyLength := binary.BigEndian.Uint16(data[2:4])
	extrasLength := data[4]

	if keyLength > 0 {
		neededData := headerSize + int(keyLength) + int(extrasLength)
		if neededData > len(data) {
			keyMissing := neededData - len(data)
			log.Debugf("Did not receive enough bytes for key, need %d more bytes", keyMissing)
			return proxylib.MORE, keyMissing
		}
	}

	opcode, key, err := p.getOpcodeAndKey(data, extrasLength, keyLength)
	if err != 0 {
		return proxylib.ERROR, int(err)
	}

	logEntry := &cilium.LogEntry_GenericL7{
		&cilium.L7LogEntry{
			Proto: "binarymemcached",
			Fields: map[string]string{
				"opcode": strconv.Itoa(int(opcode)),
				"key":    key,
			},
		},
	}

	// we don't filter reply traffic
	if reply {
		log.Debugf("reply, passing %d bytes", len(data))
		p.connection.Log(cilium.EntryType_Response, logEntry)
		p.replyCount++
		return proxylib.PASS, int(bodyLength + headerSize)
	}

	p.requestCount++

	matches := p.connection.Matches(binaryMemcacheMeta{opcode, key})
	if matches {
		p.connection.Log(cilium.EntryType_Request, logEntry)
		return proxylib.PASS, int(bodyLength + headerSize)
	}

	magic := responseMagic | data[0]

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

func (p *BinaryMemcacheParser) injectDeniedMessage(magic byte) {
	deniedMsg := make([]byte, len(DeniedMsgBase))
	copy(deniedMsg, DeniedMsgBase)

	deniedMsg[0] = magic

	p.connection.Inject(true, deniedMsg)
	p.replyCount++
}

func (p *BinaryMemcacheParser) injectFromQueue() bool {
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
	requestMagic  = 0x80
	responseMagic = 0x81
)

func (p *BinaryMemcacheParser) getOpcodeAndKey(data []byte, extrasLength byte, keyLength uint16) (byte, string, proxylib.OpError) {
	if data[0]&requestMagic != requestMagic {
		log.Warnf("Direction bit is 'response', but memcached parser only parses requests")
		return 0, "", proxylib.ERROR_INVALID_FRAME_TYPE
	}

	opcode := data[1]
	key := getMemcacheKey(data, extrasLength, keyLength)

	return opcode, key, 0
}

func getMemcacheKey(packet []byte, extrasLength byte, keyLength uint16) string {
	if keyLength == 0 {
		return ""
	}
	return string(packet[headerSize+int(extrasLength) : headerSize+int(extrasLength)+int(keyLength)])
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

// MemcacheOpCodeMap maps human-readable names of memcached operations and groups to opcodes
var MemcacheOpCodeMap = map[string][]byte{
	"get":                  {0},
	"set":                  {1},
	"add":                  {2},
	"replace":              {3},
	"delete":               {4},
	"increment":            {5},
	"decrement":            {6},
	"quit":                 {7},
	"flush":                {8},
	"getq":                 {9},
	"noop":                 {10},
	"version":              {11},
	"getk":                 {12},
	"getkq":                {13},
	"append":               {14},
	"prepend":              {15},
	"stat":                 {16},
	"setq":                 {17},
	"addq":                 {18},
	"replaceq":             {19},
	"deleteq":              {20},
	"incrementq":           {21},
	"decrementq":           {22},
	"quitq":                {23},
	"flushq":               {24},
	"appendq":              {25},
	"prependq":             {26},
	"verbosity":            {27},
	"touch":                {28},
	"gat":                  {29},
	"gatq":                 {30},
	"sasl-list-mechs":      {32},
	"sasl-auth":            {33},
	"sasl-step":            {34},
	"rget":                 {48},
	"rset":                 {49},
	"rsetq":                {50},
	"rappend":              {51},
	"rappendq":             {52},
	"rprepend":             {53},
	"rprependq":            {54},
	"rdelete":              {55},
	"rdeleteq":             {56},
	"rincr":                {57},
	"rincrq":               {58},
	"rdecr":                {59},
	"rdecrq":               {60},
	"set-vbucket":          {61},
	"get-vbucket":          {62},
	"del-vbucket":          {63},
	"tap-connect":          {64},
	"tap-mutation":         {65},
	"tap-delete":           {66},
	"tap-flush":            {67},
	"tap-opaque":           {68},
	"tap-vbucket-set":      {69},
	"tap-checkpoint-start": {70},
	"tap-checkpoint-end":   {71},

	"readGroup":  {0, 9, 12, 13},
	"writeGroup": {1, 2, 3, 4, 5, 6, 14, 15, 17, 18, 19, 20, 21, 22, 25, 26, 28, 29, 30},
}
