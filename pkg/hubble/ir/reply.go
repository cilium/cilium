// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package ir

import "google.golang.org/protobuf/types/known/wrapperspb"

const (
	ReplyUnknown Reply = iota
	ReplyYes
	ReplyNo
)

// Reply tracks flow reply information.
type Reply uint8

func (r Reply) isEmpty() bool {
	return r == ReplyUnknown
}

func (r Reply) toProto() *wrapperspb.BoolValue {
	if r.isEmpty() {
		return nil
	}

	if r == ReplyYes {
		return &wrapperspb.BoolValue{Value: true}
	}

	return &wrapperspb.BoolValue{Value: false}
}

// ProtoToReply converts a protobuf BoolValue to an internal representation.
func ProtoToReply(r *wrapperspb.BoolValue) Reply {
	if r == nil {
		return ReplyUnknown
	}

	if r.Value {
		return ReplyYes
	}

	return ReplyNo
}
