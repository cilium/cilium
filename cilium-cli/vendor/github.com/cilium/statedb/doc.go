// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// The statedb package provides a transactional in-memory database with per-table locking.
// The database indexes objects using Persistive Adaptive Radix Trees.
// (https://db.in.tum.de/~leis/papers/ART.pdf)
//
// As this is built around an immutable data structure and objects may have lockless readers
// the stored objects MUST NOT be mutated, but instead a copy must be made prior to mutation
// and insertion.
//
// See 'example/' for an example how to construct an application that uses this library.
package statedb
