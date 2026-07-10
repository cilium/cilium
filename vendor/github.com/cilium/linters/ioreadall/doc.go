// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package ioreadall defines an Analyzer that checks for the use of
// (io|ioutil).ReadAll.
//
// # Analyzer ioreadall
//
// ioreadall: check for use of io.ReadAll().
//
// The ioreadall checker looks for calls to ReadAll() from the io and ioutil
// packages. If misused, it the function can be used as a possible attack
// vector (e.g. an attacker gets the program to read a very large file which
// fills up memory leader to a denial of service attack). Users are encouraged
// to use alternative constructs such as making use of io.LimitReader.
package ioreadall
