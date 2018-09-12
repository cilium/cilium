/*
 * Copyright 2018 Authors of Cilium
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
  uint32_t op;      // FilterOpType
  uint32_t n_bytes; // >0
} FilterOp;

typedef enum {
  FILTER_OK,                 // Operation was successful
  FILTER_POLICY_DROP,        // Connection needs to be dropped due to (L3/L4) policy
  FILTER_PARSER_ERROR,       // Connection needs to be dropped due to parser error
  FILTER_UNKNOWN_PARSER,     // Connection needs to be dropped due to unknown parser
  FILTER_UNKNOWN_CONNECTION, // Connection needs to be dropped due to it being unknown
  FILTER_INVALID_ADDRESS,    // Destination address in invalid format
} FilterResult;

#endif
