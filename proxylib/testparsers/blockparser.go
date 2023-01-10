// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package testparsers

import (
	"bytes"
	"fmt"
	"math"
	"strconv"

	cilium "github.com/cilium/proxy/go/cilium/api"
	"github.com/sirupsen/logrus"

	. "github.com/cilium/cilium/proxylib/proxylib"
)

//
// Block parser used for testing
//

type BlockParserFactory struct{}

var blockParserFactory *BlockParserFactory

const (
	blockParserName = "test.blockparser"
)

func init() {
	logrus.Debug("init(): Registering blockParserFactory")
	RegisterParserFactory(blockParserName, blockParserFactory)
}

type BlockParser struct {
	connection *Connection
	inserted   int
}

func (p *BlockParserFactory) Create(connection *Connection) interface{} {
	logrus.Debugf("BlockParserFactory: Create: %v", connection)
	return &BlockParser{connection: connection}
}

func getBlock(data [][]byte) ([]byte, int, int, error) {
	var block bytes.Buffer

	offset := 0
	blockLen := 0
	haveLength := false
	missing := 0

	for _, s := range data {
		if !haveLength {
			index := bytes.IndexByte(s[offset:], ':')
			if index < 0 {
				block.Write(s[offset:])
				if block.Len() > 0 {
					missing = 1 // require at least one more if something was received
				}
			} else {
				block.Write(s[offset : offset+index])
				offset += index

				// Now 'block' contains everything before the ':', parse it as a decimal number
				// indicating the length of the frame AFTER the ':'
				if lenUint64, err := strconv.ParseUint(block.String(), 10, 64); err != nil {
					return block.Bytes(), 0, 0, err
				} else if lenUint64 > math.MaxInt {
					return block.Bytes(), 0, 0, fmt.Errorf("block length overflow")
				} else {
					blockLen = int(lenUint64)
				}
				if blockLen <= block.Len() {
					return block.Bytes(), 0, 0, fmt.Errorf("block length too short")
				}
				haveLength = true
				missing = blockLen - block.Len()
			}
		}
		if haveLength {
			s_len := len(s) - offset

			if missing <= s_len {
				block.Write(s[offset : offset+missing])
				return block.Bytes(), blockLen, 0, nil
			} else {
				block.Write(s[offset:])
				missing -= s_len
			}
		}
		offset = 0
	}

	return block.Bytes(), blockLen, missing, nil
}

// Parses individual blocks that must start with one of:
// "PASS" the block is passed
// "DROP" the block is dropped
// "INJECT" the block is injected in reverse direction
// "INSERT" the block is injected in current direction
func (p *BlockParser) OnData(reply, endStream bool, data [][]byte) (OpType, int) {
	block, block_len, missing, err := getBlock(data)
	if err != nil {
		logrus.WithError(err).Warnf("BlockParser: Invalid frame length")
		return ERROR, int(ERROR_INVALID_FRAME_LENGTH)
	}

	if p.inserted > 0 {
		if p.inserted == block_len {
			p.inserted = 0
			return DROP, block_len
		}
		// partial insert in progress
		n := p.connection.Inject(reply, []byte(block)[p.inserted:])
		// Drop the INJECT block in the current direction
		p.inserted += n
		return INJECT, n
	}

	if !reply {
		logrus.Debugf("BlockParser: Request: %s", block)
	} else {
		logrus.Debugf("BlockParser: Response: %s", block)
	}

	if missing == 0 && block_len == 0 {
		// Nothing received, don't know if more will be coming; do nothing
		return NOP, 0
	}

	logrus.Debugf("BlockParser: missing: %d", missing)

	if bytes.Contains(block, []byte("PASS")) {
		p.connection.Log(cilium.EntryType_Request, &cilium.LogEntry_GenericL7{
			GenericL7: &cilium.L7LogEntry{
				Proto: blockParserName,
				Fields: map[string]string{
					"status": "200",
				},
			},
		})
		return PASS, block_len
	}
	if bytes.Contains(block, []byte("DROP")) {
		p.connection.Log(cilium.EntryType_Denied, &cilium.LogEntry_GenericL7{
			GenericL7: &cilium.L7LogEntry{
				Proto: blockParserName,
				Fields: map[string]string{
					"status": "503",
				},
			},
		})
		return DROP, block_len
	}

	if missing > 0 {
		// Partial block received, ask for more
		return MORE, missing
	}

	if bytes.Contains(block, []byte("INJECT")) {
		// Inject block in the reverse direction
		p.connection.Inject(!reply, []byte(block))
		// Drop the INJECT block in the current direction
		return DROP, block_len
	}
	if bytes.Contains(block, []byte("INSERT")) {
		// Inject the block in the current direction
		n := p.connection.Inject(reply, []byte(block))
		// Drop the INJECT block in the current direction
		p.inserted = n
		return INJECT, n
	}

	return ERROR, int(ERROR_INVALID_FRAME_TYPE)
}
