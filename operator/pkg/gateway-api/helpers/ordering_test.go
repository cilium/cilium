// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestCompareCreationTimeThenNamespacedName(t *testing.T) {
	older := metav1.NewTime(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))
	newer := metav1.NewTime(time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC))

	obj := func(ns, name string, ts metav1.Time) *gatewayv1.HTTPRoute {
		return &gatewayv1.HTTPRoute{
			ObjectMeta: metav1.ObjectMeta{
				Namespace:         ns,
				Name:              name,
				CreationTimestamp: ts,
			},
		}
	}

	tests := []struct {
		name     string
		a        *gatewayv1.HTTPRoute
		b        *gatewayv1.HTTPRoute
		expected int
	}{
		{
			name:     "older timestamp sorts first",
			a:        obj("ns", "alpha", older),
			b:        obj("ns", "zebra", newer),
			expected: -1,
		},
		{
			name:     "newer timestamp sorts after",
			a:        obj("ns", "alpha", newer),
			b:        obj("ns", "zebra", older),
			expected: 1,
		},
		{
			name:     "alphabetically earlier namespace sorts first",
			a:        obj("a-ns", "alpha", older),
			b:        obj("z-ns", "zebra", older),
			expected: -1,
		},
		{
			name:     "alphabetically later namespace sorts after",
			a:        obj("z-ns", "alpha", older),
			b:        obj("a-ns", "zebra", older),
			expected: 1,
		},
		{
			name:     "alphabetically earlier name sorts first",
			a:        obj("ns", "alpha", older),
			b:        obj("ns", "zebra", older),
			expected: -1,
		},
		{
			name:     "alphabetically later name sorts after",
			a:        obj("ns", "zebra", older),
			b:        obj("ns", "alpha", older),
			expected: 1,
		},
		// This should never happen though.
		{
			name:     "identical timestamp, namespace and name",
			a:        obj("ns", "route", older),
			b:        obj("ns", "route", older),
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, CompareCreationTimeThenNamespacedName(tt.a.ObjectMeta, tt.b.ObjectMeta))
		})
	}
}
