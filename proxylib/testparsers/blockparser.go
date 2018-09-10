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

package testparsers

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/cilium/cilium/pkg/envoy/cilium"
	. "github.com/cilium/cilium/proxylib/proxylib"

	log "github.com/sirupsen/logrus"
)

//
// Block parser used for testing
//

type BlockParserFactory struct{}

var blockParserFactory *BlockParserFactory

func init() {
	log.Info("init(): Registering blockParserFactory")
	RegisterParserFactory("test.blockparser", blockParserFactory)
}

type BlockParser struct {
	connection *Connection
	inserted   bool
}

func (p *BlockParserFactory) Create(connection *Connection) Parser {
	log.Infof("BlockParserFactory: Create: %v", connection)
	return &BlockParser{connection: connection}
}

func getBlock(data []string, offset uint32) (string, uint32, uint32, error) {
	var block string

	block_len := uint32(0)
	have_length := false
	missing := uint32(0)

	for _, s := range data {
		if !have_length {
			index := strings.IndexByte(s[offset:], ':')
			if index < 0 {
				block += s[offset:]
				if len(block) > 0 {
					missing = 1 // require at least one more if something was received
				}
			} else {
				block += s[offset : offset+uint32(index)]
				offset += uint32(index)

				// Now 'block' contains everything before the ':', parse it as a decimal number
				// indicating the length of the frame AFTER the ':'
				len64, err := strconv.ParseUint(block, 10, 64)
				if err != nil {
					return block, 0, 0, err
				}
				block_len = uint32(len64)
				if block_len <= uint32(len(block)) {
					return block, 0, 0, fmt.Errorf("Block length too short")
				}
				have_length = true
				missing = block_len - uint32(len(block))
			}
		}
		if have_length {
			s_len := uint32(len(s)) - offset

			if missing <= s_len {
				block += s[offset : offset+missing]
				return block, block_len, 0, nil
			} else {
				block += s[offset:]
				missing -= s_len
			}
		}
		offset = 0
	}

	return block, block_len, missing, nil
}

//
// Parses individual blocks that must start with one of:
// "PASS" the block is passed
// "DROP" the block is dropped
// "INJECT" the block is injected in reverse direction
// "INSERT" the block is injected in current direction
//
func (p *BlockParser) OnData(reply, endStream bool, data []string, offset uint32) (OpType, uint32) {
	block, block_len, missing, err := getBlock(data, offset)
	if err != nil {
		log.WithError(err).Warnf("BlockParser: Invalid frame length")
		return ERROR, uint32(ERROR_INVALID_FRAME_LENGTH)
	}

	if p.inserted {
		p.inserted = false
		return DROP, block_len
	}

	if !reply {
		log.Infof("BlockParser: Request: %s", block)
	} else {
		log.Infof("BlockParser: Response: %s", block)
	}

	if missing == 0 && block_len == 0 {
		// Nothing received, don't know if more will be coming; do nothing
		return NOP, 0
	}

	log.Infof("BlockParser: missing: %d", missing)

	if strings.Contains(block, "PASS") {
		p.connection.Log(cilium.EntryType_Request, &cilium.LogEntry_Http{&cilium.HttpLogEntry{Status: 200}})
		return PASS, block_len
	}
	if strings.Contains(block, "DROP") {
		p.connection.Log(cilium.EntryType_Denied, &cilium.LogEntry_Http{&cilium.HttpLogEntry{Status: 201}})
		return DROP, block_len
	}

	if missing > 0 {
		// Partial block received, ask for more
		return MORE, missing
	}

	if strings.Contains(block, "INJECT") {
		// Inject block in the reverse direction
		p.connection.Inject(!reply, []byte(block))
		// Drop the INJECT block in the current direction
		return DROP, block_len
	}
	if strings.Contains(block, "INSERT") {
		// Inject the block in the current direction
		p.connection.Inject(reply, []byte(block))
		// Drop the INJECT block in the current direction
		p.inserted = true
		return INJECT, block_len
	}

	return ERROR, uint32(ERROR_INVALID_FRAME_TYPE)
}
