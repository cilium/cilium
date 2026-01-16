// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package ir

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestProtoToReply(t *testing.T) {
	uu := map[string]struct {
		in *wrapperspb.BoolValue
		e  Reply
	}{
		"nil": {
			e: ReplyUnknown,
		},

		"reply": {
			in: wrapperspb.Bool(true),
			e:  ReplyYes,
		},

		"no-reply": {
			in: wrapperspb.Bool(false),
			e:  ReplyNo,
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, u.e, ProtoToReply(u.in))
		})
	}
}

func TestReplyIsEmpty(t *testing.T) {
	uu := map[string]struct {
		in Reply
		e  bool
	}{
		"unset": {
			in: ReplyUnknown,
			e:  true,
		},

		"yes": {
			in: ReplyYes,
		},

		"no": {
			in: ReplyNo,
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, u.e, u.in.IsEmpty())
		})
	}
}

func TestReply_toProto(t *testing.T) {
	uu := map[string]struct {
		in Reply
		e  *wrapperspb.BoolValue
	}{
		"unset": {
			in: ReplyUnknown,
		},

		"reply": {
			in: ReplyYes,
			e:  wrapperspb.Bool(true),
		},

		"no-reply": {
			in: ReplyNo,
			e:  wrapperspb.Bool(false),
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, u.e, u.in.toProto())
		})
	}
}
