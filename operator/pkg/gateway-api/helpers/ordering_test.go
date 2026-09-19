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

func TestCompareByCreationTimestampAndObjectKey(t *testing.T) {
	t1 := metav1.NewTime(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))
	t2 := metav1.NewTime(time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC))

	newRoute := func(ns, name string, ts metav1.Time) *gatewayv1.HTTPRoute {
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
			name:     "earlier creation wins the slot",
			a:        newRoute("ns", "older", t1),
			b:        newRoute("ns", "newer", t2),
			expected: -1,
		},
		{
			name:     "later creation yields to the earlier one",
			a:        newRoute("ns", "newer", t2),
			b:        newRoute("ns", "older", t1),
			expected: 1,
		},
		{
			name:     "matching timestamps fall back to namespace",
			a:        newRoute("a-ns", "route", t1),
			b:        newRoute("z-ns", "route", t1),
			expected: -1,
		},
		{
			name:     "matching namespace falls back to name",
			a:        newRoute("ns", "alpha", t1),
			b:        newRoute("ns", "zebra", t1),
			expected: -1,
		},
		{
			name:     "hyphenated namespace does not jump ahead via punctuation",
			a:        newRoute("a", "c", t1),
			b:        newRoute("a-x", "b", t1),
			expected: -1,
		},
		{
			name:     "identical identity reports a tie",
			a:        newRoute("ns", "route", t1),
			b:        newRoute("ns", "route", t1),
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, CompareByCreationTimestampAndObjectKey(tt.a.ObjectMeta, tt.b.ObjectMeta))
			assert.Equal(t, -tt.expected, CompareByCreationTimestampAndObjectKey(tt.b.ObjectMeta, tt.a.ObjectMeta))
		})
	}
}
