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

package proxylib

/*
#include "types.h"
*/
import "C"

// Mirror C types to be able to use them in other Go files and tests.

type OpType uint32
type OpError uint32
type Op struct {
	op      uint32
	n_bytes uint32 // The number of bytes of data the operation 'op' applies to.
}

const (
	MORE   OpType = C.FILTEROP_MORE
	PASS   OpType = C.FILTEROP_PASS
	DROP   OpType = C.FILTEROP_DROP
	INJECT OpType = C.FILTEROP_INJECT
	ERROR  OpType = C.FILTEROP_ERROR
	// Internal types not exposed to Caller
	NOP OpType = 256

	ERROR_INVALID_OP_LENGTH    OpError = C.FILTEROP_ERROR_INVALID_OP_LENGTH
	ERROR_INVALID_FRAME_TYPE   OpError = C.FILTEROP_ERROR_INVALID_FRAME_TYPE
	ERROR_INVALID_FRAME_LENGTH OpError = C.FILTEROP_ERROR_INVALID_FRAME_LENGTH
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

type Result int

const (
	OK                 Result = C.FILTER_OK
	POLICY_DROP        Result = C.FILTER_POLICY_DROP
	PARSER_ERROR       Result = C.FILTER_PARSER_ERROR
	UNKNOWN_PARSER     Result = C.FILTER_UNKNOWN_PARSER
	UNKNOWN_CONNECTION Result = C.FILTER_UNKNOWN_CONNECTION
	INVALID_ADDRESS    Result = C.FILTER_INVALID_ADDRESS
	INVALID_INSTANCE   Result = C.FILTER_INVALID_INSTANCE
)

func (r Result) String() string {
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
	}
	return "UNKNOWN_ERROR"
}
