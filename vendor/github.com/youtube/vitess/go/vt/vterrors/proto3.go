// Copyright 2012, Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vterrors

import (
	vtrpcpb "github.com/youtube/vitess/go/vt/proto/vtrpc"
)

// This file contains the necessary methods to send and receive errors
// as payloads of proto3 structures. It converts vtError to and from
// *vtrpcpb.RPCError. Use these methods when a RPC call can return both
// data and an error.

// FromVTRPC recovers a vtError from a *vtrpcpb.RPCError (which is how vtError
// is transmitted across proto3 RPC boundaries).
func FromVTRPC(rpcErr *vtrpcpb.RPCError) error {
	if rpcErr == nil {
		return nil
	}
	code := rpcErr.Code
	if code == vtrpcpb.Code_OK {
		code = LegacyErrorCodeToCode(rpcErr.LegacyCode)
	}
	return New(code, rpcErr.Message)
}

// ToVTRPC converts from vtError to a vtrpcpb.RPCError.
func ToVTRPC(err error) *vtrpcpb.RPCError {
	if err == nil {
		return nil
	}
	code := Code(err)
	return &vtrpcpb.RPCError{
		LegacyCode: CodeToLegacyErrorCode(code),
		Code:       code,
		Message:    err.Error(),
	}
}
