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

// IsEmpty returns true if the Reply value is unknown.
func (r Reply) IsEmpty() bool {
	return r == ReplyUnknown
}

// ToBool converts the Reply value to a boolean, treating unknown as false.
func (r Reply) ToBool() bool {
	return r == ReplyYes
}

func (r Reply) toProto() *wrapperspb.BoolValue {
	if r.IsEmpty() {
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
