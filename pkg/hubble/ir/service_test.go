// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package ir

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/api/v1/flow"
)

func TestProtoToService(t *testing.T) {
	uu := map[string]struct {
		in *flow.Service
		e  Service
	}{
		"none": {
			e: Service{},
		},

		"full": {
			in: &flow.Service{
				Name:      "svc1",
				Namespace: "ns1",
			},
			e: Service{
				Name:      "svc1",
				Namespace: "ns1",
			},
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, u.e, ProtoToService(u.in))
		})
	}
}

func TestService_toProto(t *testing.T) {
	uu := map[string]struct {
		in Service
		e  *flow.Service
	}{
		"empty": {},

		"full": {
			in: Service{
				Name:      "svc1",
				Namespace: "ns1",
			},
			e: &flow.Service{
				Name:      "svc1",
				Namespace: "ns1",
			},
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, u.e, u.in.toProto())
		})
	}
}

func TestService_isEmpty(t *testing.T) {
	uu := map[string]struct {
		in Service
		e  bool
	}{
		"empty": {
			e: true,
		},

		"full": {
			in: Service{
				Name:      "svc1",
				Namespace: "ns1",
			},
		},
	}

	for name, u := range uu {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, u.e, u.in.isEmpty())
		})
	}
}
