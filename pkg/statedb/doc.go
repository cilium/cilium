// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// The statedb package provides an extendable in-memory database built on the go-memdb library which uses
// immutable radix trees (https://en.wikipedia.org/wiki/Radix_tree) that supports any number of readers
// without locking but only a single writer at a time.
//
// As this is built around an immutable data structure, any objects stored must never be mutated and a
// copy must be made prior to modifications.
//
// See pkg/statedb/example for an example how to construct an application that uses this library.
package statedb
