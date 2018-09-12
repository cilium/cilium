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

//
// Accompanying file `headerparser.policy` contains an example policy
// for this protocol. Install it with:
// $ cilium policy import proxylib/testparsers/headerparser.policy
//

package binarymemcached

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

// Matches returns true if the BinaryMemcacheRule matches
func (rule *BinaryMemcacheRule) Matches(data interface{}) bool {
	log.Infof("binarymemcache checking rule %v", *rule)

	packet := data.([]byte)
	key, err := getMemcacheKey(packet)

	if err != nil {
		log.Errorf("error retrieving binary memcached key: %s", err)
	}

	opcode := packet[1]

	if rule.keyExact == "" && rule.keyPrefix == "" && rule.keyRegex == "" {
		return rule.matchOpcode(opcode)
	}

	if rule.keyExact != "" && rule.keyExact == key {
		return rule.matchOpcode(opcode)
	}
	log.Infof("binary memcached exact key %s does not match %s", rule.keyExact, key)

	if rule.keyPrefix != "" && strings.HasPrefix(key, rule.keyPrefix) {
		return rule.matchOpcode(opcode)
	}
	log.Infof("binary memcached key prefix %s does not match %s", rule.keyExact, key)

	if rule.keyRegex != "" {
		return rule.matchOpcode(opcode) && rule.regex.MatchString(key)
	}
	log.Infof("binary memcached key regex %s does not match %s", rule.keyExact, key)

	return false
}

func (rule *BinaryMemcacheRule) matchOpcode(oc byte) bool {
	return bytes.Contains(rule.opCodes, []byte{oc})
}

func getMemcacheKey(packet []byte) (string, error) {
	var keyLength uint16
	keyBuf := bytes.NewReader(packet[2:4])
	err := binary.Read(keyBuf, binary.BigEndian, &keyLength)
	if err != nil {
		return "", err
	}
	var extrasLength uint8
	extrasLength = packet[4]

	return string(packet[24+extrasLength : 24+uint16(extrasLength)+keyLength]), nil
}

// L7BinaryMemcacheRuleParser parses protobuf L7 rules to and array of BinaryMemcacheRule
// May panic
func L7BinaryMemcacheRuleParser(rule *cilium.PortNetworkPolicyRule) []proxylib.L7NetworkPolicyRule {
	l7Rules := rule.GetL7Rules()
	if l7Rules == nil {
		panic(fmt.Errorf("Can't get L7 rules."))
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
				panic(fmt.Errorf("Unsupported key: %s", k))
			}
		}
		log.Infof("Parsed BinaryMemcacheRule pair: %v", br)
		rules = append(rules, &br)
	}
	return rules
}

type BinaryMemcacheParserFactory struct{}

func (p *BinaryMemcacheParserFactory) Create(connection *proxylib.Connection) proxylib.Parser {
	log.Infof("BinaryMemcacheParserFactory: Create: %v", connection)
	return &BinaryMemcacheParser{connection: connection}
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

type BinaryMemcacheParser struct {
	connection *proxylib.Connection
}

var _ proxylib.Parser = &BinaryMemcacheParser{}

const headerSize = 24

func (p *BinaryMemcacheParser) OnData(reply, endStream bool, str_data []string, offset uint32) (proxylib.OpType, uint32) {
	log.Infof("OnData with offset %d", offset)

	//TODO: make this more performant
	data := ([]byte(strings.Join(str_data, "")))[offset:]
	log.Infof("Data length: %d", len(data))

	headerMissing := headerSize - len(data)

	if headerMissing > 0 {
		log.Infof("Did not receive full header, need %d more bytes", headerMissing)
		return proxylib.MORE, uint32(headerMissing)
	}

	bodyLength := binary.BigEndian.Uint32(data[8:12])

	dataMissing := headerSize + int(bodyLength) - len(data)
	if dataMissing > 0 {
		log.Infof("Did not receive full request, need %d more bytes", dataMissing)
		return proxylib.MORE, uint32(dataMissing)
	}

	// we don't parse reply traffic for now
	if reply {
		if len(data) == 0 {
			log.Infof("ignoring zero length reply call to onData")
			return proxylib.NOP, 0
		} else {
			log.Infof("reply, passing %d bytes", uint32(len(data)))
			return proxylib.PASS, uint32(len(data))
		}
	}

	opcode, key, err := p.parse(data)
	if err != 0 {
		return proxylib.ERROR, uint32(err)
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

	matches := p.connection.Matches(data)
	if matches {
		p.connection.Log(cilium.EntryType_Request, logEntry)
		return proxylib.PASS, bodyLength + headerSize
	} else {
		p.connection.Log(cilium.EntryType_Denied, logEntry)

		deniedMsg := make([]byte, len(DeniedMsgBase))
		copy(deniedMsg, DeniedMsgBase)

		deniedMsg[0] = 0x81 | data[0]

		p.connection.Inject(true, deniedMsg)

		return proxylib.DROP, bodyLength + headerSize
	}
}

func (p *BinaryMemcacheParser) parse(data []byte) (byte, string, proxylib.OpError) {
	if data[0]&0x80 != 0x80 {
		log.Infof("Direction bit is 'response', but memcached parser only parses requests")
		return 0, "", proxylib.ERROR_INVALID_FRAME_TYPE
	}

	opcode := data[1]
	key, err := getMemcacheKey(data)
	if err != nil {
		return 0, "", proxylib.ERROR_INVALID_FRAME_LENGTH
	}

	return opcode, key, 0
}

var DeniedMsgBase = []byte{
	0x81, 0, 0, 0,
	0, 0, 0, 0x24,
	0, 0, 0, 0x0d,
	0, 0, 0, 0,
	0, 0, 0, 0,
	0, 0, 0, 0,
	'a', 'c', 'c',
	'e', 's', 's',
	' ', 'd', 'e',
	'n', 'i', 'e',
	'd'}

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
