// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ir

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/api/v1/flow"
)

func TestProtoToTraceContext(t *testing.T) {
	uu := map[string]struct {
		in *flow.TraceContext
		e  TraceContext
	}{
		"empty": {},

		"full": {
			in: &flow.TraceContext{
				Parent: &flow.TraceParent{
					TraceId: "p1",
				},
			},
			e: TraceContext{
				Parent: TraceParent{
					TraceID: "p1",
				},
			},
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, u.e, ProtoToTraceContext(u.in))
		})
	}
}

func TestTraceContext_toProto(t *testing.T) {
	uu := map[string]struct {
		in TraceContext
		e  *flow.TraceContext
	}{
		"empty": {},

		"full": {
			in: TraceContext{
				Parent: TraceParent{
					TraceID: "p1",
				},
			},
			e: &flow.TraceContext{
				Parent: &flow.TraceParent{
					TraceId: "p1",
				},
			},
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, u.e, u.in.toProto())
		})
	}
}

func TestTraceContext_isEmpty(t *testing.T) {
	uu := map[string]struct {
		in TraceContext
		e  bool
	}{
		"empty": {
			e: true,
		},

		"full": {
			in: TraceContext{
				Parent: TraceParent{
					TraceID: "p1",
				},
			},
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, u.e, u.in.isEmpty())
		})
	}
}
