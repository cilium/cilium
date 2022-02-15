// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxylib

import (
	"github.com/sirupsen/logrus"
)

// A parser instance is used for each connection. OnData will be called from a single thread only.
type Parser interface {
	// OnData() is called when input is available on the underlying connection. The Parser
	// instance is only ever used for processing data of a single connection, which allows
	// the parser instance to keep connection specific state. All OnData() calls for a
	// single connection (both directions) are made from a single thread, so that
	// no locking is needed for the parser instance if no other goroutines need to access
	// the parser instance. (Note that any L7 policy protocol rule parsing happens in
	// other goroutine so any such parsing should not access parser instances directly.)
	//
	// OnData() parameters are as follows:
	// 'reply' is 'false' for original direction of the connection, 'true' otherwise.
	// 'endStream' is true if there is no more data after 'data' in this direction.
	// 'data' is the available data in the current direction. The datapath buffers
	//        partial frames as instructed by the operations returned by the parser
	//        so that the 'data' always starts on a frame boundary. That is, whenever
	//        the parser returns `MORE` indicating it needs more input, the bytes
	//        not 'PASS'ed or 'DROP'ped are retained in a datapath buffer and those
	//        same bytes are passed to the parser again when more input is available.
	//        'data' may be an empty slice, but the slices contained are never empty.
	//
	// OnData() returns an operation and the number of bytes ('N') the operation applies.
	// The possible values for 'op' are:
	// 'MORE' -   Data currently in 'data' is to be retained by the datapath and passed
	//            again to OnData() after 'N' bytes more data is available.
	// 'PASS' -   Allow 'N' bytes.
	// 'DROP' -   Drop 'N' bytes and call OnData() again for the remaining data.
	// 'INJECT' - Insert 'N' bytes of data placed into the inject buffer in to the
	//            data stream in this direction.
	// 'NOP' -    Do nothing, to be used when it is known if no more input
	//            is to be expected.
	// 'ERROR' -  Protocol parsing failed and the connection should be closed.
	//
	// OnData() is called again after 'PASS', 'DROP', and 'INJECT' with the remaining
	// data even if none remains.
	OnData(reply, endStream bool, data [][]byte) (op OpType, N int)
}

// An alternate parser instance is used for each connection. OnData will be called from a single thread only.
type ReaderParser interface {
	// OnData() is called when input is available on the underlying connection. The Parser
	// instance is only ever used for processing data of a single connection, which allows
	// the parser instance to keep connection specific state. All OnData() calls for a
	// single connection (both directions) are made from a single thread, so that
	// no locking is needed for the parser instance if no other goroutines need to access
	// the parser instance. (Note that any L7 policy protocol rule parsing happens in
	// other goroutine so any such parsing should not access parser instances directly.)
	//
	// OnData() parameters are as follows:
	// 'reply' is 'false' for original direction of the connection, 'true' otherwise.
	// 'endStream' is true if there is no more data after 'data' in this direction.
	// 'data' is the available data in the current direction. The datapath buffers
	//        partial frames as instructed by the operations returned by the parser
	//        so that the 'data' always starts on a frame boundary. That is, whenever
	//        the parser returns `MORE` indicating it needs more input, the bytes
	//        not 'PASS'ed or 'DROP'ped are retained in a datapath buffer and those
	//        same bytes are passed to the parser again when more input is available.
	//        'data' may be an empty slice, but the slices contained are never empty.
	//
	// OnData() returns an operation and the number of bytes ('N') the operation applies.
	// The possible values for 'op' are:
	// 'MORE' -   Data currently in 'data' is to be retained by the datapath and passed
	//            again to OnData() after 'N' bytes more data is available.
	// 'PASS' -   Allow 'N' bytes.
	// 'DROP' -   Drop 'N' bytes and call OnData() again for the remaining data.
	// 'INJECT' - Insert 'N' bytes of data placed into the inject buffer in to the
	//            data stream in this direction.
	// 'NOP' -    Do nothing, to be used when it is known if no more input
	//            is to be expected.
	// 'ERROR' -  Protocol parsing failed and the connection should be closed.
	//
	// OnData() is called again after 'PASS', 'DROP', and 'INJECT' with the remaining
	// data even if none remains.
	OnData(reply bool, reader *Reader) (op OpType, N int)
}

type ParserFactory interface {
	Create(connection *Connection) interface{} // must be thread safe!
}

// const after initialization
var parserFactories map[string]ParserFactory = make(map[string]ParserFactory)

// RegisterParserFactory adds a protocol parser factory to the map of known parsers.
// This is called from parser init() functions while we are still single-threaded
func RegisterParserFactory(name string, parserFactory ParserFactory) {
	logrus.Debugf("proxylib: Registering L7 parser: %v", name)
	parserFactories[name] = parserFactory
}

func GetParserFactory(name string) ParserFactory {
	return parserFactories[name]
}
