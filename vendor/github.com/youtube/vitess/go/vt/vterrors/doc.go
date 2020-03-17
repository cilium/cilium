// Package vterrors provides helpers for propagating internal errors
// through the Vitess system (including across RPC boundaries) in a
// structured way.
package vterrors

/*

Vitess uses canonical error codes for error reporting. This is based
on years of industry experience with error reporting. This idea is
that errors should be classified into a small set of errors (10 or so)
with very specific meaning. Each error has a code, and a message. When
errors are passed around (even through RPCs), the code is
propagated. To handle errors, only the code should be looked at (and
not string-matching on the error message).

Vitess defines the error codes in /proto/vtrpc.proto. Along with an
RPCError message that can be used to transmit errors through RPCs, in
the message payloads. These codes match the names and numbers defined
by gRPC.

Vitess also defines a standardized error implementation that allows
you to build an error with an associated canonical code.

While sending an error through gRPC, these codes are transmitted
using gRPC's error propagation mechanism and decoded back to
the original code on the other end.

*/
