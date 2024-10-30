// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package timeafter defines an Analyzer that checks for the use of time.After
// in loops on Go versions before 1.23
//
// # Analyzer timeafter
//
// timeafter: check for use of time.After().
//
// The underlining Timer is not recovered by the garbage collector until the
// timer fires.
package timeafter
