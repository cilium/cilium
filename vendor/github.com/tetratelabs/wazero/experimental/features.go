package experimental

import "github.com/tetratelabs/wazero/api"

// CoreFeaturesThreads enables threads instructions ("threads").
//
// # Notes
//
//   - The instruction list is too long to enumerate in godoc.
//     See https://github.com/WebAssembly/threads/blob/main/proposals/threads/Overview.md
//   - Atomic operations are guest-only until api.Memory or otherwise expose them to host functions.
//   - On systems without mmap available, the memory will pre-allocate to the maximum size. Many
//     binaries will use a theroetical maximum like 4GB, so if using such a binary on a system
//     without mmap, consider editing the binary to reduce the max size setting of memory.
const CoreFeaturesThreads = api.CoreFeatureSIMD << 1

// CoreFeaturesTailCall enables tail call instructions ("tail-call").
const CoreFeaturesTailCall = api.CoreFeatureSIMD << 2

// CoreFeaturesExtendedConst enables extended constant expressions.
//
// # Notes
//
//   - Enables i32.add/sub/mul and i64.add/sub/mul in constant expressions.
//   - Enables references to any previous global index in constant expressions,
//     instead of just imported globals.
//
// See https://github.com/WebAssembly/extended-const for further details.
const CoreFeaturesExtendedConst = api.CoreFeatureSIMD << 3

// CoreFeaturesExceptionHandling enables exception handling instructions.
//
// See https://github.com/WebAssembly/exception-handling for further details.
const CoreFeaturesExceptionHandling = api.CoreFeatureSIMD << 4

// CoreFeaturesTypedFunctionReferences enables typed function references.
//
// See https://github.com/WebAssembly/function-references for further details.
const CoreFeaturesTypedFunctionReferences = api.CoreFeatureSIMD << 5
