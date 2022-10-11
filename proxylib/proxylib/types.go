// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxylib

import "fmt"

// OpType mirrors enum FilterOpType in types.h.
type OpType int64

const (
	MORE OpType = iota
	PASS
	DROP
	INJECT
	ERROR

	// Internal types not exposed to Caller
	NOP OpType = 256
)

// OpError mirrors enum FilterOpError in types.h.
type OpError int64

const (
	ERROR_INVALID_OP_LENGTH OpError = iota + 1
	ERROR_INVALID_FRAME_TYPE
	ERROR_INVALID_FRAME_LENGTH
)

func (op OpType) String() string {
	switch op {
	case MORE:
		return "MORE"
	case PASS:
		return "PASS"
	case DROP:
		return "DROP"
	case INJECT:
		return "INJECT"
	case ERROR:
		return "ERROR"
	case NOP:
		return "NOP"
	}
	return "UNKNOWN_OP"
}

func (opErr OpError) String() string {
	switch opErr {
	case ERROR_INVALID_OP_LENGTH:
		return "ERROR_INVALID_OP_LENGTH"
	case ERROR_INVALID_FRAME_TYPE:
		return "ERROR_INVALID_FRAME_TYPE"
	case ERROR_INVALID_FRAME_LENGTH:
		return "ERROR_INVALID_FRAME_LENGTH"
	}
	return "UNKNOWN_OP_ERROR"
}

// FilterResult mirrors enum FilterResult in types.h.
type FilterResult int

const (
	OK FilterResult = iota
	POLICY_DROP
	PARSER_ERROR
	UNKNOWN_PARSER
	UNKNOWN_CONNECTION
	INVALID_ADDRESS
	INVALID_INSTANCE
	UNKNOWN_ERROR
)

// Error() implements the error interface for FilterResult
func (r FilterResult) Error() string {
	switch r {
	case OK:
		return "OK"
	case POLICY_DROP:
		return "POLICY_DROP"
	case PARSER_ERROR:
		return "PARSER_ERROR"
	case UNKNOWN_PARSER:
		return "UNKNOWN_PARSER"
	case UNKNOWN_CONNECTION:
		return "UNKNOWN_CONNECTION"
	case INVALID_ADDRESS:
		return "INVALID_ADDRESS"
	case INVALID_INSTANCE:
		return "INVALID_INSTANCE"
	case UNKNOWN_ERROR:
		return "UNKNOWN_ERROR"
	}

	return fmt.Sprintf("%d", r)
}
