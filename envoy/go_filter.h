/* Created by "go tool cgo" - DO NOT EDIT. */

/* package command-line-arguments */


#line 1 "cgo-builtin-prolog"

#include <stddef.h> /* for ptrdiff_t below */

#ifndef GO_CGO_EXPORT_PROLOGUE_H
#define GO_CGO_EXPORT_PROLOGUE_H

typedef struct { const char *p; ptrdiff_t n; } _GoString_;

#endif

/* Start of preamble from import "C" comments.  */


#line 3 "/home/vagrant/go/src/github.com/cilium/cilium/envoy/goparsers/go_filter.go"

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
} FilterResult;

#line 1 "cgo-generated-wrapper"


/* End of preamble from import "C" comments.  */


/* Start of boilerplate cgo prologue.  */
#line 1 "cgo-gcc-export-header-prolog"

#ifndef GO_CGO_PROLOGUE_H
#define GO_CGO_PROLOGUE_H

typedef signed char GoInt8;
typedef unsigned char GoUint8;
typedef short GoInt16;
typedef unsigned short GoUint16;
typedef int GoInt32;
typedef unsigned int GoUint32;
typedef long long GoInt64;
typedef unsigned long long GoUint64;
typedef GoInt64 GoInt;
typedef GoUint64 GoUint;
typedef __SIZE_TYPE__ GoUintptr;
typedef float GoFloat32;
typedef double GoFloat64;
typedef float _Complex GoComplex64;
typedef double _Complex GoComplex128;

/*
  static assertion to make sure the file is being used on architecture
  at least with matching size of GoInt.
*/
typedef char _check_for_64_bit_pointer_matching_GoInt[sizeof(void*)==64/8 ? 1:-1];

typedef _GoString_ GoString;
typedef void *GoMap;
typedef void *GoChan;
typedef struct { void *t; void *v; } GoInterface;
typedef struct { void *data; GoInt len; GoInt cap; } GoSlice;

#endif

/* End of boilerplate cgo prologue.  */

#ifdef __cplusplus
extern "C" {
#endif


extern GoInt OnNewConnection(GoString p0, GoUint64 p1, GoUint8 p2, GoUint32 p3, GoUint32 p4, GoString p5, GoString p6, GoString p7, GoSlice* p8, GoSlice* p9);

// Each connection is assumed to be called from a single thread, so accessing connection metadata
// does not need protection.

extern GoInt OnData(GoUint64 p0, GoUint8 p1, GoUint8 p2, GoSlice* p3, GoSlice* p4);

// Make this more general connection event callback

extern void Close(GoUint64 p0);

// called before any other APIs

extern GoUint8 InitModule(GoString p0);

#ifdef __cplusplus
}
#endif
