// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ir

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/api/v1/flow"
)

func TestProtoToIPTraceID(t *testing.T) {
	uu := map[string]struct {
		in *flow.IPTraceID
		e  IPTraceID
	}{
		"empty": {
			in: nil,
		},

		"full": {
			in: &flow.IPTraceID{
				TraceId:      12345,
				IpOptionType: 10,
			},
			e: IPTraceID{
				TraceID:      12345,
				IPOptionType: 10,
			},
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, u.e, ProtoToIPTraceID(u.in))
		})
	}
}

func TestIPTrace_isEmpty(t *testing.T) {
	uu := map[string]struct {
		t IPTraceID
		e bool
	}{
		"empty": {
			e: true,
		},

		"partial": {
			t: IPTraceID{
				TraceID: 12345,
			},
		},

		"full": {
			t: IPTraceID{
				TraceID:      12345,
				IPOptionType: 10,
			},
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, u.e, u.t.isEmpty())
		})
	}
}

func TestIPTrace_toProto(t *testing.T) {
	uu := map[string]struct {
		t   IPTraceID
		out *flow.IPTraceID
	}{
		"empty": {},

		"full": {
			t: IPTraceID{
				TraceID:      12345,
				IPOptionType: 10,
			},
			out: &flow.IPTraceID{
				TraceId:      12345,
				IpOptionType: 10,
			},
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, u.out, u.t.toProto())
		})
	}
}
