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

package main

/*
#include "proxylib/types.h"
*/
import "C"

import (
	"net"
	"strconv"

	"github.com/cilium/cilium/proxylib/accesslog"
	_ "github.com/cilium/cilium/proxylib/memcached/binary"
	"github.com/cilium/cilium/proxylib/npds"
	. "github.com/cilium/cilium/proxylib/proxylib"
	_ "github.com/cilium/cilium/proxylib/testparsers"

	"github.com/cilium/cilium/pkg/lock"
	log "github.com/sirupsen/logrus"
)

var (
	// mutex protects connections
	mutex lock.RWMutex
	// Key uint64 is a connection ID allocated by Envoy, practically a monotonically increasing number
	connections map[uint64]*Connection = make(map[uint64]*Connection)
)

func init() {
	log.Debug("proxylib: Initializing library")
}

// Copy value string from C-memory to Go-memory.
// Go strings are immutable, but byte slices are not. Converting to a byte slice will thus
// copy the memory.
func strcpy(str string) string {
	return string(([]byte(str))[0:])
}

//export OnNewConnection
func OnNewConnection(instanceId uint64, proto string, connectionId uint64, ingress bool, srcId, dstId uint32, srcAddr, dstAddr, policyName string, origBuf, replyBuf *[]byte) C.FilterResult {
	instance := FindInstance(instanceId)
	if instance == nil {
		return C.FILTER_INVALID_INSTANCE
	}
	// Find the parser for the proto
	parserFactory := GetParserFactory(proto)
	if parserFactory == nil {
		return C.FILTER_UNKNOWN_PARSER
	}
	_, port, err := net.SplitHostPort(dstAddr)
	if err != nil {
		return C.FILTER_INVALID_ADDRESS
	}
	dstPort, err := strconv.ParseUint(port, 10, 32)
	if err != nil || dstPort == 0 {
		return C.FILTER_INVALID_ADDRESS
	}
	// Note: Strings passed as arguments from C must be copied to Go memory to keep them valid after this function
	// returns
	connection := &Connection{
		Instance:   instance,
		Id:         connectionId,
		Ingress:    ingress,
		SrcId:      srcId,
		DstId:      dstId,
		SrcAddr:    strcpy(srcAddr),
		DstAddr:    strcpy(dstAddr),
		Port:       uint32(dstPort),
		PolicyName: strcpy(policyName),
		Orig:       Direction{InjectBuf: origBuf},
		Reply:      Direction{InjectBuf: replyBuf},
	}
	connection.Parser = parserFactory.Create(connection)
	if connection.Parser == nil {
		// Parser rejected the new connection based on the connection metadata
		return C.FILTER_POLICY_DROP
	}

	mutex.Lock()
	connections[connectionId] = connection
	mutex.Unlock()

	return C.FILTER_OK
}

// Each connection is assumed to be called from a single thread, so accessing connection metadata
// does not need protection.
//
// OnData gets all the unparsed data the datapath has received so far. The data is provided to the parser
// associated with the connection, and the parser is expected to find if the data frame contains enough data
// to make a PASS/DROP decision for the whole data frame. Note that the whole data frame need not be received,
// if the decision including the length of the data frame in bytes can be determined based on the beginning of
// the data frame only (e.g., headers including the length of the data frame). The parser returns a decision
// with the number of bytes on which the decision applies. If more data is available, then the parser will be
// called again with the remaining data. Parser needs to return MORE if a decision can't be made with
// the available data, including the minimum number of additional bytes that is needed before the parser is
// called again.
//
// The parser can also inject at arbitrary points in the data stream. This is indecated by an INJECT operation
// with the number of bytes to be injected. The actual bytes to be injected are provided via an Inject()
// callback prior to returning the INJECT operation. The Inject() callback operates on a limited size buffer
// provided by the datapath, and multiple INJECT operations may be needed to inject large amounts of data.
// Since we get the data on one direction at a time, any frames to be injected in the reverse direction
// are placed in the reverse direction buffer, from where the datapath injects the data before calling
// us again for the reverse direction input.
//
//export OnData
func OnData(connectionId uint64, reply, endStream bool, data *[][]byte, filterOps *[]C.FilterOp) C.FilterResult {
	// Find the connection
	mutex.RLock()
	connection, ok := connections[connectionId]
	mutex.RUnlock()
	if !ok {
		return C.FILTER_UNKNOWN_CONNECTION
	}

	unit := 0
	offset := 0

	// Loop until `filterOps` becomes full, or parser is done with the data.
	for len(*filterOps) < cap(*filterOps) {
		op, bytes := connection.Parser.OnData(reply, endStream, (*data)[unit:], offset)
		if op == NOP {
			break // No operations after NOP
		}
		if bytes == 0 {
			return C.FILTER_PARSER_ERROR
		}
		*filterOps = append(*filterOps, C.FilterOp{C.uint64_t(op), C.int64_t(bytes)})

		if op == MORE {
			// Need more data before can parse ahead.
			// Parser will see the unused data again in the next call, which will take place
			// after there are at least 'bytes' of additional data to parse.
			break
		}

		if op == PASS || op == DROP {
			// Skip bytes in input, or exhaust the input.
			for bytes > 0 && unit < len(*data) {
				rem := len((*data)[unit]) - offset // this much data left in unit
				if bytes < rem {                   // more than 'bytes' bytes in unit
					offset += bytes
					bytes = 0
				} else { // go to the beginning of the next unit
					bytes -= rem
					unit++
					offset = 0
				}
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
	return C.FILTER_OK
}

// Make this more general connection event callback
//export Close
func Close(connectionId uint64) {
	mutex.Lock()
	delete(connections, connectionId)
	mutex.Unlock()
}

// OpenModule is called before any other APIs.
// Called concurrently by different filter instances.
// Returns a library instance ID that must be passed to all other API calls.
// Calls with the same parameters will return the same instance.
// Zero return value indicates an error.
//export OpenModule
func OpenModule(params [][2]string, debug bool) uint64 {
	accessLogPath, xdsPath := "", ""
	for i := range params {
		key := params[i][0]
		value := params[i][1]

		switch key {
		case "access-log-path":
			accessLogPath = value
		case "xds-path":
			xdsPath = value
		default:
			return 0
		}
	}

	if debug {
		mutex.Lock()
		log.SetLevel(log.DebugLevel)
		mutex.Unlock()
	}
	// Copy strings from C-memory to Go-memory so that the string remains valid
	// also after this function returns
	return OpenInstance(strcpy(xdsPath), npds.NewClient, strcpy(accessLogPath), accesslog.NewClient)
}

//export CloseModule
func CloseModule(id uint64) {
	CloseInstance(id)
}

// Must have empty main
func main() {}
