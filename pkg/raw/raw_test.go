// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package raw

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"

	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/maps/crap"
)

func TestMatchesPodLabels(t *testing.T) {
	tests := []struct {
		name      string
		selector  map[string]string
		podLabels map[string]string
		want      bool
	}{
		{
			name:      "exact match",
			selector:  map[string]string{"app": "web"},
			podLabels: map[string]string{"app": "web"},
			want:      true,
		},
		{
			name:      "selector is subset",
			selector:  map[string]string{"app": "web"},
			podLabels: map[string]string{"app": "web", "env": "prod"},
			want:      true,
		},
		{
			name:      "value mismatch",
			selector:  map[string]string{"app": "web"},
			podLabels: map[string]string{"app": "api"},
			want:      false,
		},
		{
			name:      "empty selector",
			selector:  map[string]string{},
			podLabels: map[string]string{"app": "web"},
			want:      false,
		},
		{
			name:      "nil selector",
			selector:  nil,
			podLabels: map[string]string{"app": "web"},
			want:      false,
		},
		{
			name:      "selector superset of pod labels",
			selector:  map[string]string{"app": "web", "env": "prod"},
			podLabels: map[string]string{"app": "web"},
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &serviceMetadata{labels: tt.selector}
			assert.Equal(t, tt.want, svc.matchesPodLabels(tt.podLabels))
		})
	}
}

func TestGetServiceMetadata(t *testing.T) {
	svc := &slim_corev1.Service{
		ObjectMeta: slim_metav1.ObjectMeta{
			UID: types.UID("service-1"),
		},
		Spec: slim_corev1.ServiceSpec{
			Selector:    map[string]string{"app": "web"},
			ExternalIPs: []string{"192.0.2.10", "not-an-ip", "192.0.2.11"},
		},
	}

	meta, err := getServiceMetadata(svc)
	require.NoError(t, err)
	require.Len(t, meta.vip, 2)
	assert.Equal(t, serviceID("service-1"), meta.id)
	assert.Equal(t, map[string]string{"app": "web"}, meta.labels)
	assert.Equal(t, netip.MustParseAddr("192.0.2.10"), meta.vip[0])
	assert.Equal(t, netip.MustParseAddr("192.0.2.11"), meta.vip[1])
}

func TestBuildRules(t *testing.T) {
	ep1 := &endpointMetadata{
		id:     endpointID("endpoint-1"),
		ip:     netip.MustParseAddr("10.0.0.10"),
		labels: map[string]string{"app": "web"},
	}
	ep2 := &endpointMetadata{
		id:     endpointID("endpoint-2"),
		ip:     netip.MustParseAddr("10.0.0.20"),
		labels: map[string]string{"app": "api"},
	}

	tests := []struct {
		name      string
		eps       map[endpointID]*endpointMetadata
		svcs      map[serviceID]*serviceMetadata
		wantRules map[crap.CrapKey]crap.CrapVal
	}{
		{
			name: "matching service with multiple VIPs",
			eps:  map[endpointID]*endpointMetadata{ep1.id: ep1, ep2.id: ep2},
			svcs: map[serviceID]*serviceMetadata{
				serviceID("svc-1"): {
					id:     serviceID("svc-1"),
					labels: map[string]string{"app": "web"},
					vip:    []netip.Addr{netip.MustParseAddr("203.0.113.1"), netip.MustParseAddr("203.0.113.2")},
				},
			},
			wantRules: map[crap.CrapKey]crap.CrapVal{
				crap.NewKey(netip.MustParseAddr("203.0.113.1")): crap.NewVal(ep1.ip),
				crap.NewKey(netip.MustParseAddr("203.0.113.2")): crap.NewVal(ep1.ip),
			},
		},
		{
			name: "no matching endpoint produces no rules",
			eps:  map[endpointID]*endpointMetadata{ep2.id: ep2},
			svcs: map[serviceID]*serviceMetadata{
				serviceID("svc-1"): {
					id:     serviceID("svc-1"),
					labels: map[string]string{"app": "web"},
					vip:    []netip.Addr{netip.MustParseAddr("203.0.113.1")},
				},
			},
			wantRules: map[crap.CrapKey]crap.CrapVal{},
		},
		{
			name: "empty selector matches nothing",
			eps:  map[endpointID]*endpointMetadata{ep1.id: ep1},
			svcs: map[serviceID]*serviceMetadata{
				serviceID("svc-1"): {
					id:     serviceID("svc-1"),
					labels: map[string]string{},
					vip:    []netip.Addr{netip.MustParseAddr("203.0.113.1")},
				},
			},
			wantRules: map[crap.CrapKey]crap.CrapVal{},
		},
		{
			name:      "no services produces no rules",
			eps:       map[endpointID]*endpointMetadata{ep1.id: ep1},
			svcs:      map[serviceID]*serviceMetadata{},
			wantRules: map[crap.CrapKey]crap.CrapVal{},
		},
		{
			name: "no endpoints produces no rules",
			eps:  map[endpointID]*endpointMetadata{},
			svcs: map[serviceID]*serviceMetadata{
				serviceID("svc-1"): {
					id:     serviceID("svc-1"),
					labels: map[string]string{"app": "web"},
					vip:    []netip.Addr{netip.MustParseAddr("203.0.113.1")},
				},
			},
			wantRules: map[crap.CrapKey]crap.CrapVal{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildRules(tt.eps, tt.svcs)
			assert.Equal(t, tt.wantRules, got)
		})
	}
}
