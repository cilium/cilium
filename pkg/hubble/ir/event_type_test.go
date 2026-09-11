// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ir

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/api/v1/flow"
)

func TestProtoToEventType(t *testing.T) {
	uu := map[string]struct {
		in *flow.CiliumEventType
		e  CiliumEventType
	}{
		"empty": {
			in: nil,
		},

		"full": {
			in: &flow.CiliumEventType{
				Type:    1,
				SubType: 2,
			},
			e: CiliumEventType{
				Type:    1,
				SubType: 2,
			},
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, u.e, ProtoToEventType(u.in))
		})
	}
}

func TestEventTypeIsEmpty(t *testing.T) {
	uu := map[string]struct {
		e    CiliumEventType
		want bool
	}{
		"empty": {
			want: true,
		},

		"partial": {
			e: CiliumEventType{
				Type: 1,
			},
		},

		"full": {
			e: CiliumEventType{
				Type:    1,
				SubType: 2,
			},
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, u.want, u.e.IsEmpty())
		})
	}
}

func TestEventType_toProto(t *testing.T) {
	uu := map[string]struct {
		e   CiliumEventType
		out *flow.CiliumEventType
	}{
		"empty": {},

		"full": {
			e: CiliumEventType{
				Type:    1,
				SubType: 2,
			},
			out: &flow.CiliumEventType{
				Type:    1,
				SubType: 2,
			},
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, u.out, u.e.toProto())
		})
	}
}
