package main

//
// typedef enum {
//   FILTEROP_MORE,   // Need more data
//   FILTEROP_PASS,   // Pass N bytes
//   FILTEROP_DROP,   // Drop N bytes
//   FILTEROP_INJECT, // Inject N>0 bytes
//   FILTEROP_ERROR,  // Protocol parsing error
// } FilterOpType;
//
// typedef enum {
//   FILTEROP_ERROR_INVALID_OP_LENGTH = 1,   // Parser returned invalid operation length
//   FILTEROP_ERROR_INVALID_FRAME_TYPE,
//   FILTEROP_ERROR_INVALID_FRAME_LENGTH,
// } FilterOpError;
//
// typedef struct {
//   FilterOpType op;
//   unsigned int n_bytes; // >0
// } FilterOp;
//
// typedef enum {
//   FILTER_OK,                 // Operation was successful
//   FILTER_POLICY_DROP,        // Connection needs to be dropped due to (L3/L4) policy
//   FILTER_PARSER_ERROR,       // Connection needs to be dropped due to parser error
//   FILTER_UNKNOWN_PARSER,     // Connection needs to be dropped due to unknown parser
//   FILTER_UNKNOWN_CONNECTION, // Connection needs to be dropped due to it being unknown
// } FilterResult;
import "C"

import (
	"github.com/cilium/cilium/pkg/lock"

	log "github.com/sirupsen/logrus"
)

type FilterOpType int
type FilterOpError uint

const (
	FILTEROP_MORE   FilterOpType = C.FILTEROP_MORE
	FILTEROP_PASS   FilterOpType = C.FILTEROP_PASS
	FILTEROP_DROP   FilterOpType = C.FILTEROP_DROP
	FILTEROP_INJECT FilterOpType = C.FILTEROP_INJECT
	FILTEROP_ERROR  FilterOpType = C.FILTEROP_ERROR
	// Internal types not exposed to Caller
	FILTEROP_NOP FilterOpType = -1

	FILTEROP_ERROR_INVALID_OP_LENGTH    FilterOpError = C.FILTEROP_ERROR_INVALID_OP_LENGTH
	FILTEROP_ERROR_INVALID_FRAME_TYPE   FilterOpError = C.FILTEROP_ERROR_INVALID_FRAME_TYPE
	FILTEROP_ERROR_INVALID_FRAME_LENGTH FilterOpError = C.FILTEROP_ERROR_INVALID_FRAME_LENGTH
)

// Filter sees data from the underlying stream in both directions
// (original, connection open direction and the opposite, the reply
// direction). Each call to the filter returns an ordered set of
// operations to be performed on the data in that direction. Any data
// left over after the returned operations must be buffered by the
// caller and passed in again when more data has been received on the
// connection.

type Direction struct {
	injectBuf *[]byte
}

type Connection struct {
	Id      uint64
	Ingress bool
	SrcId   uint32
	DstId   uint32
	SrcAddr string
	DstAddr string

	parser Parser
	orig   Direction
	reply  Direction
}

var mutex lock.Mutex
var connections map[uint64]*Connection

// A parser instance is used for each connection. OnData will be called from a single thread only.
type Parser interface {
	OnData(reply, endStream bool, data []string, offset uint) (FilterOpType, uint)
}

type ParserFactory interface {
	Create(connection *Connection) Parser // must be thread safe!
}

var parserFactories map[string]ParserFactory // const after initialization

func init() {
	log.Info("init(): Initializing go_filter")
	connections = make(map[uint64]*Connection)
}

// RegisterParserFactory adds a protocol parser factory to the map of known parsers.
// This is called from parser init() functions while we are still single-threaded
func RegisterParserFactory(name string, parserFactory ParserFactory) {
	if parserFactories == nil { // init on first call
		parserFactories = make(map[string]ParserFactory)
	}
	log.Infof("RegisterParserFactory: Registering: %v", name)
	parserFactories[name] = parserFactory
}

// getInjectBuf return the pointer to the inject buffer slice header for the indicated direction
func (connection *Connection) getInjectBuf(reply bool) *[]byte {
	if reply {
		return connection.reply.injectBuf
	}
	return connection.orig.injectBuf
}

// inject buffers data to be injected into the connection at the point of FILTEROP_INJECT
func (connection *Connection) Inject(reply bool, data []byte) int {
	buf := connection.getInjectBuf(reply)
	// append data to C-provided buffer
	offset := len(*buf)
	n := copy((*buf)[offset:cap(*buf)], data)
	*buf = (*buf)[:offset+n] // update the buffer length

	log.Infof("Connection.Inject(): Injected: %s,%v", data, buf)

	// return the number of bytes injected. This may be less than the length of `data` is
	// the buffer becomes full.
	return n
}

// isInjectBufFull return true if the inject buffer for the indicated direction is full
func (connection *Connection) isInjectBufFull(reply bool) bool {
	buf := connection.getInjectBuf(reply)
	return len(*buf) == cap(*buf)
}

// onData gets all the unparsed data the datapath has received so far. The data is provided to the parser
// associated with the connection, and the parser is expected to find if the data frame contains enough data
// to make a PASS/DROP decision for the whole data frame. Note that the whole data frame need not be received,
// if the decision including the length of the data frame in bytes can be determined based on the beginning of
// the data frame only (e.g., headers including the length of the data frame). The parser returns a decision
// with the number of bytes on which the decision applies. If more data is available, then the parser will be
// called again with the remaining data. Parser needs to return FILTEROP_MORE if a decision can't be made with
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
func (connection *Connection) onData(reply, endStream bool, data *[]string, filterOps *[]C.FilterOp) C.FilterResult {
	unit := 0
	offset := uint(0)

	// Loop until `filterOps` becomes full, or parser is done with the data.
	for len(*filterOps) < cap(*filterOps) {
		op, bytes := connection.parser.OnData(reply, endStream, (*data)[unit:], offset)
		if op == FILTEROP_NOP {
			break // No operations after NOP
		}
		if bytes == 0 {
			return C.FILTER_PARSER_ERROR
		}
		*filterOps = append(*filterOps, C.FilterOp{C.FilterOpType(op), C.uint(bytes)})

		if op == FILTEROP_MORE {
			// Need more data before can parse ahead.
			// Parser will see the unused data again in the next call, which will take place
			// after there are at least 'bytes' of additional data to parse.
			break
		}

		if op == FILTEROP_PASS || op == FILTEROP_DROP {
			// Skip bytes in input, or exhaust the input.
			for bytes > 0 && unit < len(*data) {
				rem := uint(len((*data)[unit])) - offset // this much data left in unit
				if bytes < rem {                         // more than 'bytes' bytes in unit
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
		if op == FILTEROP_INJECT && connection.isInjectBufFull(reply) {
			// return if inject buffer becomes full
			break
		}
	}
	return C.FILTER_OK
}

//export OnNewConnection
func OnNewConnection(proto string, connectionId uint64, ingress bool, srcId, dstId uint32, srcAddr, dstAddr string, origBuf, replyBuf *[]byte) C.FilterResult {
	// Find the parser for the proto
	parserFactory := parserFactories[proto]
	if parserFactory == nil {
		return C.FILTER_UNKNOWN_PARSER
	}
	connection := &Connection{
		Id:      connectionId,
		Ingress: ingress,
		SrcId:   srcId,
		DstId:   dstId,
		SrcAddr: srcAddr,
		DstAddr: dstAddr,
		orig:    Direction{injectBuf: origBuf},
		reply:   Direction{injectBuf: replyBuf},
	}
	connection.parser = parserFactory.Create(connection)
	if connection.parser == nil {
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
//export OnData
func OnData(connectionId uint64, reply, endStream bool, data *[]string, filterOps *[]C.FilterOp) C.FilterResult {
	// Find the connection
	mutex.Lock()
	connection, ok := connections[connectionId]
	mutex.Unlock()
	if !ok {
		return C.FILTER_UNKNOWN_CONNECTION
	}
	return connection.onData(reply, endStream, data, filterOps)
}

// Make this more general connection event callback
//export Close
func Close(connectionId uint64) {
	mutex.Lock()
	delete(connections, connectionId)
	mutex.Unlock()
}

// Must have empty main
func main() {}
