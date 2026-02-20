// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ir

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/api/v1/flow"
)

func Test_protoToEmitter(t *testing.T) {
	uu := map[string]struct {
		in *flow.Emitter
		e  Emitter
	}{
		"empty": {
			in: nil,
		},

		"full": {
			in: &flow.Emitter{
				Name:    "emitter-name",
				Version: "emitter-version",
			},
			e: Emitter{
				Name:    "emitter-name",
				Version: "emitter-version",
			},
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, u.e, protoToEmitter(u.in))
		})
	}
}

func TestEmitter_toProto(t *testing.T) {
	uu := map[string]struct {
		e   Emitter
		out *flow.Emitter
	}{
		"empty": {},

		"full": {
			e: Emitter{
				Name:    "emitter-name",
				Version: "emitter-version",
			},
			out: &flow.Emitter{
				Name:    "emitter-name",
				Version: "emitter-version",
			},
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, u.out, u.e.toProto())
		})
	}
}

func TestEmitter_isEmpty(t *testing.T) {
	uu := map[string]struct {
		em Emitter
		e  bool
	}{
		"empty": {
			em: Emitter{},
			e:  true,
		},

		"name only": {
			em: Emitter{Name: "emitter-name"},
			e:  false,
		},

		"version only": {
			em: Emitter{Version: "emitter-version"},
			e:  false,
		},

		"full": {
			em: Emitter{Name: "emitter-name", Version: "emitter-version"},
			e:  false,
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, u.e, u.em.isEmpty())
		})
	}
}
