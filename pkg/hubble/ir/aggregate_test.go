// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ir

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/api/v1/flow"
)

func TestIsEmpty(t *testing.T) {
	uu := map[string]struct {
		in Emitter
		e  bool
	}{
		"empty": {
			e: true,
		},

		"partial": {
			in: Emitter{
				Version: "emitter-version",
			},
		},

		"full": {
			in: Emitter{
				Name:    "emitter-name",
				Version: "emitter-version",
			},
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, u.e, u.in.IsEmpty())
		})
	}
}

func TestAggregate_toProto(t *testing.T) {
	uu := map[string]struct {
		ag Aggregate
		e  *flow.Aggregate
	}{
		"empty": {},

		"partial": {
			ag: Aggregate{
				IngressFlowCount: 1,
				EgressFlowCount:  2,
			},
			e: &flow.Aggregate{
				IngressFlowCount: 1,
				EgressFlowCount:  2,
			},
		},

		"full": {
			ag: Aggregate{
				IngressFlowCount:          1,
				EgressFlowCount:           2,
				UnknownDirectionFlowCount: 3,
			},
			e: &flow.Aggregate{
				IngressFlowCount:          1,
				EgressFlowCount:           2,
				UnknownDirectionFlowCount: 3,
			},
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, u.e, u.ag.toProto())
		})
	}
}

func TestProtoToAggregate(t *testing.T) {
	uu := map[string]struct {
		in *flow.Aggregate
		e  Aggregate
	}{
		"empty": {},

		"partial": {
			in: &flow.Aggregate{
				IngressFlowCount: 1,
				EgressFlowCount:  2,
			},
			e: Aggregate{
				IngressFlowCount: 1,
				EgressFlowCount:  2,
			},
		},

		"full": {
			in: &flow.Aggregate{
				IngressFlowCount:          1,
				EgressFlowCount:           2,
				UnknownDirectionFlowCount: 3,
			},
			e: Aggregate{
				IngressFlowCount:          1,
				EgressFlowCount:           2,
				UnknownDirectionFlowCount: 3,
			},
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, u.e, ProtoToAggregate(u.in))
		})
	}
}
