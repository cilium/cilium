/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright Authors of Cilium */

#ifndef PROXYLIB_TYPES_H
#define PROXYLIB_TYPES_H

#include <stdint.h>

typedef enum {
  FILTEROP_MORE,   // Need more data
  FILTEROP_PASS,   // Pass N bytes
  FILTEROP_DROP,   // Drop N bytes
  FILTEROP_INJECT, // Inject N>0 bytes
  FILTEROP_ERROR,  // Protocol parsing error
} FilterOpType;

typedef enum {
  FILTEROP_ERROR_INVALID_OP_LENGTH = 1,   // Parser returned invalid operation length
  FILTEROP_ERROR_INVALID_FRAME_TYPE,
  FILTEROP_ERROR_INVALID_FRAME_LENGTH,
} FilterOpError;

typedef struct {
  uint64_t op;      // FilterOpType
  int64_t  n_bytes; // >0
} FilterOp;

typedef enum {
  FILTER_OK,                 // Operation was successful
  FILTER_POLICY_DROP,        // Connection needs to be dropped due to (L3/L4) policy
  FILTER_PARSER_ERROR,       // Connection needs to be dropped due to parser error
  FILTER_UNKNOWN_PARSER,     // Connection needs to be dropped due to unknown parser
  FILTER_UNKNOWN_CONNECTION, // Connection needs to be dropped due to it being unknown
  FILTER_INVALID_ADDRESS,    // Destination address in invalid format
  FILTER_INVALID_INSTANCE,   // Destination address in invalid format
  FILTER_UNKNOWN_ERROR,      // Error type could not be cast to an error code
} FilterResult;

#endif
