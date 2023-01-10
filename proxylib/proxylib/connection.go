// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxylib

import (
	"fmt"
	"net"
	"strconv"
	"time"

	cilium "github.com/cilium/proxy/go/cilium/api"
	"github.com/sirupsen/logrus"
)

// A parser sees data from the underlying stream in both directions
// (original, connection open direction and the opposite, the reply
// direction). Each call to the filter returns an ordered set of
// operations to be performed on the data in that direction. Any data
// left over after the returned operations must be buffered by the
// caller and passed in again when more data has been received on the
// connection.

// InjectBuf is a pointer to a slice header for an inject buffer allocated by
// the proxylib caller. As data is placed into the buffer, the length
// of the buffer in the slice header is increased correspondingly. To make
// the the injected data visible to the caller we need to pass the slice header
// by reference rather than by value, hence the pointer in the type.
// As the caller is typically in a differnent memory management domain (not
// subject to Go runtime garbage collection), the underlying buffer may never
// be expanded or otherwise reallocated.
type InjectBuf *[]byte

// Connection holds the connection metadata that is used both for
// policy enforcement and access logging.
type Connection struct {
	Instance   *Instance // Holder of Policy protocol and access logging clients
	Id         uint64    // Unique connection ID allocated by the caller
	Ingress    bool      // 'true' for ingress, 'false' for egress
	SrcId      uint32    // Source security ID, may be mapped from the source IP address
	DstId      uint32    // Destination security ID, may be mapped from the destination IP address
	SrcAddr    string    // Source IP address in "a.b.c.d:port" or "[A:...:C]:port" format
	DstAddr    string    // Original destination IP address
	PolicyName string    // Identifies which policy instance applies to this connection
	Port       uint32    // (original) destination port number in numeric format

	ParserName string      // Name of the parser
	Parser     interface{} // Parser instance used on this connection
	Reader     Reader
	OrigBuf    InjectBuf // Buffer for injected frames in original direction
	ReplyBuf   InjectBuf // Buffer for injected frames in reply direction
}

func NewConnection(instance *Instance, proto string, connectionId uint64, ingress bool, srcId, dstId uint32, srcAddr, dstAddr, policyName string, origBuf, replyBuf *[]byte) (error, *Connection) {
	// Find the parser for the proto
	parserFactory := GetParserFactory(proto)
	if parserFactory == nil {
		return UNKNOWN_PARSER, nil
	}
	_, port, err := net.SplitHostPort(dstAddr)
	if err != nil {
		return INVALID_ADDRESS, nil
	}
	dstPort, err := strconv.ParseUint(port, 10, 32)
	if err != nil || dstPort == 0 {
		return INVALID_ADDRESS, nil
	}

	connection := &Connection{
		Instance:   instance,
		Id:         connectionId,
		Ingress:    ingress,
		SrcId:      srcId,
		DstId:      dstId,
		SrcAddr:    srcAddr,
		DstAddr:    dstAddr,
		Port:       uint32(dstPort),
		PolicyName: policyName,
		ParserName: proto,
		OrigBuf:    origBuf,
		ReplyBuf:   replyBuf,
	}
	connection.Parser = parserFactory.Create(connection)
	if connection.Parser == nil {
		// Parser rejected the new connection based on the connection metadata
		return POLICY_DROP, nil
	}

	return nil, connection
}

// Skip bytes in input, or exhaust the input.
func advanceInput(input [][]byte, bytes int) [][]byte {
	for bytes > 0 && len(input) > 0 {
		rem := len(input[0]) // this much data left in the first slice
		if bytes < rem {
			input[0] = input[0][bytes:] // skip 'bytes' bytes
			bytes = 0
		} else { // go to the beginning of the next unit
			bytes -= rem
			input = input[1:] // may result in an empty slice
		}
	}
	return input
}

func (connection *Connection) OnData(reply, endStream bool, data *[][]byte, filterOps *[][2]int64) (res FilterResult) {
	defer func() {
		// Recover from any possible parser datapath panics
		if r := recover(); r != nil {
			// Log the Panic into accesslog
			connection.Log(cilium.EntryType_Denied,
				&cilium.LogEntry_GenericL7{
					GenericL7: &cilium.L7LogEntry{
						Proto: connection.ParserName,
						Fields: map[string]string{
							// "status" is shown in Cilium monitor
							"status": fmt.Sprintf("Panic: %s", r),
						},
					},
				})
			res = PARSER_ERROR // Causes the connection to be dropped
		}
	}()

	if parser, ok := connection.Parser.(Parser); ok {
		input := *data
		// Loop until `filterOps` becomes full, or parser is done with the data.
		for len(*filterOps) < cap(*filterOps) {
			op, bytes := parser.OnData(reply, endStream, input)
			if op == NOP {
				break // No operations after NOP
			}
			if bytes == 0 {
				return PARSER_ERROR
			}
			*filterOps = append(*filterOps, [2]int64{int64(op), int64(bytes)})

			if op == MORE {
				// Need more data before can parse ahead.
				// Parser will see the unused data again in the next call, which will take place
				// after there are at least 'bytes' of additional data to parse.
				break
			}

			if op == PASS || op == DROP {
				input = advanceInput(input, bytes)
				// Loop back to parser even if have no more data to allow the parser to
				// inject frames at the end of the input.
			}

			// Injection does not advance input data, but instructs the datapath to
			// send data the parser has placed in the inject buffer. We need to stop processing
			// if inject buffer becomes full as the parser in this case can't inject any more
			// data.
			if op == INJECT && connection.IsInjectBufFull(reply) {
				// return if inject buffer becomes full
				break
			}
		}
	} else if parser, ok := connection.Parser.(ReaderParser); ok {
		connection.Reader = NewReader(*data, endStream)
		// Loop until `filterOps` becomes full, or parser is done with the data.
		for len(*filterOps) < cap(*filterOps) {
			op, bytes := parser.OnData(reply, &connection.Reader)
			if op == NOP {
				break // No operations after NOP
			}
			if bytes == 0 {
				return PARSER_ERROR
			}
			*filterOps = append(*filterOps, [2]int64{int64(op), int64(bytes)})

			if op == MORE {
				// Need more data before can parse ahead.
				// Parser will see the unused data again in the next call, which will take place
				// after there are at least 'bytes' of additional data to parse.
				break
			}

			// Get the current read count && reset for the next round
			read := connection.Reader.Reset()

			if op == PASS || op == DROP {
				// Andvance input if needed
				if bytes > read {
					connection.Reader.AdvanceInput(bytes - read)
				}
				// Loop back to parser even if have no more data to allow the parser to
				// inject frames at the end of the input.
			}

			// Injection does not advance input data, but instructs the datapath to
			// send data the parser has placed in the inject buffer. We need to stop processing
			// if inject buffer becomes full as the parser in this case can't inject any more
			// data.
			if op == INJECT && connection.IsInjectBufFull(reply) {
				// return if inject buffer becomes full
				break
			}
		}
	}
	return OK
}

func (connection *Connection) Matches(l7 interface{}) bool {
	logrus.Debugf("proxylib: Matching policy on connection %v", connection)
	remoteID := connection.DstId
	if connection.Ingress {
		remoteID = connection.SrcId
	}
	return connection.Instance.PolicyMatches(connection.PolicyName, connection.Ingress, connection.Port, remoteID, l7)
}

// getInjectBuf return the pointer to the inject buffer slice header for the indicated direction
func (connection *Connection) getInjectBuf(reply bool) InjectBuf {
	if reply {
		return connection.ReplyBuf
	}
	return connection.OrigBuf
}

// inject buffers data to be injected into the connection at the point of INJECT
func (connection *Connection) Inject(reply bool, data []byte) int {
	buf := connection.getInjectBuf(reply)
	// append data to C-provided buffer
	offset := len(*buf)
	n := copy((*buf)[offset:cap(*buf)], data)
	*buf = (*buf)[:offset+n] // update the buffer length

	logrus.Debugf("proxylib: Injected %d bytes: %s (given: %s)", n, string((*buf)[offset:offset+n]), string(data))

	// return the number of bytes injected. This may be less than the length of `data` is
	// the buffer becomes full.
	// Parser may opt dropping the connection via parser error in this case!
	return n
}

// isInjectBufFull return true if the inject buffer for the indicated direction is full
func (connection *Connection) IsInjectBufFull(reply bool) bool {
	buf := connection.getInjectBuf(reply)
	return len(*buf) == cap(*buf)
}

func (conn *Connection) Log(entryType cilium.EntryType, l7 cilium.IsLogEntry_L7) {
	pblog := &cilium.LogEntry{
		Timestamp:             uint64(time.Now().UnixNano()),
		IsIngress:             conn.Ingress,
		EntryType:             entryType,
		PolicyName:            conn.PolicyName,
		SourceSecurityId:      conn.SrcId,
		DestinationSecurityId: conn.DstId,
		SourceAddress:         conn.SrcAddr,
		DestinationAddress:    conn.DstAddr,
		L7:                    l7,
	}
	conn.Instance.Log(pblog)
}
