// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"log/slog"
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/cilium/cilium/operator/pkg/gateway-api/helpers"
)

func fromPtr(f gatewayv1.FromNamespaces) *gatewayv1.FromNamespaces {
	return &f
}

func Test_sortListenerSets(t *testing.T) {
	t1 := metav1.NewTime(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))
	t2 := metav1.NewTime(time.Date(2024, 1, 2, 0, 0, 0, 0, time.UTC))

	tests := []struct {
		name     string
		input    []gatewayv1.ListenerSet
		expected []string // namespace/name in expected order
	}{
		{
			name: "sort by creation timestamp",
			input: []gatewayv1.ListenerSet{
				{ObjectMeta: metav1.ObjectMeta{Name: "newer", Namespace: "ns", CreationTimestamp: t2}},
				{ObjectMeta: metav1.ObjectMeta{Name: "older", Namespace: "ns", CreationTimestamp: t1}},
			},
			expected: []string{"ns/older", "ns/newer"},
		},
		{
			name: "same timestamp sorts alphabetically",
			input: []gatewayv1.ListenerSet{
				{ObjectMeta: metav1.ObjectMeta{Name: "zebra", Namespace: "ns", CreationTimestamp: t1}},
				{ObjectMeta: metav1.ObjectMeta{Name: "alpha", Namespace: "ns", CreationTimestamp: t1}},
			},
			expected: []string{"ns/alpha", "ns/zebra"},
		},
		{
			name: "same timestamp sorts by namespace then name",
			input: []gatewayv1.ListenerSet{
				{ObjectMeta: metav1.ObjectMeta{Name: "ls", Namespace: "z-ns", CreationTimestamp: t1}},
				{ObjectMeta: metav1.ObjectMeta{Name: "ls", Namespace: "a-ns", CreationTimestamp: t1}},
			},
			expected: []string{"a-ns/ls", "z-ns/ls"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sortListenerSets(tt.input)
			var got []string
			for _, ls := range tt.input {
				got = append(got, ls.GetNamespace()+"/"+ls.GetName())
			}
			require.Equal(t, tt.expected, got)
		})
	}
}

func Test_isListenerSetAllowed_noAllowedListeners(t *testing.T) {
	gw := &gatewayv1.Gateway{
		Spec: gatewayv1.GatewaySpec{},
	}
	ls := &gatewayv1.ListenerSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default"},
	}
	assert.False(t, isListenerSetAllowed(t.Context(), nil, gw, ls, nil))
}

func Test_isListenerSetAllowed_fromNone(t *testing.T) {
	gw := &gatewayv1.Gateway{
		Spec: gatewayv1.GatewaySpec{
			AllowedListeners: &gatewayv1.AllowedListeners{
				Namespaces: &gatewayv1.ListenerNamespaces{
					From: fromPtr(gatewayv1.NamespacesFromNone),
				},
			},
		},
	}
	ls := &gatewayv1.ListenerSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "default"},
	}
	assert.False(t, isListenerSetAllowed(t.Context(), nil, gw, ls, nil))
}

func Test_isListenerSetAllowed_fromAll(t *testing.T) {
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "gw-ns"},
		Spec: gatewayv1.GatewaySpec{
			AllowedListeners: &gatewayv1.AllowedListeners{
				Namespaces: &gatewayv1.ListenerNamespaces{
					From: fromPtr(gatewayv1.NamespacesFromAll),
				},
			},
		},
	}
	ls := &gatewayv1.ListenerSet{
		ObjectMeta: metav1.ObjectMeta{Namespace: "other-ns"},
	}
	assert.True(t, isListenerSetAllowed(t.Context(), nil, gw, ls, nil))
}

func Test_isListenerSetAllowed_fromSame(t *testing.T) {
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "gw-ns"},
		Spec: gatewayv1.GatewaySpec{
			AllowedListeners: &gatewayv1.AllowedListeners{
				Namespaces: &gatewayv1.ListenerNamespaces{
					From: fromPtr(gatewayv1.NamespacesFromSame),
				},
			},
		},
	}

	t.Run("same namespace allowed", func(t *testing.T) {
		ls := &gatewayv1.ListenerSet{
			ObjectMeta: metav1.ObjectMeta{Namespace: "gw-ns"},
		}
		assert.True(t, isListenerSetAllowed(t.Context(), nil, gw, ls, nil))
	})

	t.Run("different namespace rejected", func(t *testing.T) {
		ls := &gatewayv1.ListenerSet{
			ObjectMeta: metav1.ObjectMeta{Namespace: "other-ns"},
		}
		assert.False(t, isListenerSetAllowed(t.Context(), nil, gw, ls, nil))
	})
}

func Test_isListenerSetAllowed_fromSelector(t *testing.T) {
	logger := hivetest.Logger(t, hivetest.LogLevel(slog.LevelDebug))

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Namespace: "gw-ns"},
		Spec: gatewayv1.GatewaySpec{
			AllowedListeners: &gatewayv1.AllowedListeners{
				Namespaces: &gatewayv1.ListenerNamespaces{
					From:     fromPtr(gatewayv1.NamespacesFromSelector),
					Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"team": "infra"}},
				},
			},
		},
	}

	t.Run("matching label allowed", func(t *testing.T) {
		c := fake.NewClientBuilder().
			WithScheme(helpers.TestScheme(helpers.AllOptionalKinds)).
			WithObjects(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "infra-ns", Labels: map[string]string{"team": "infra"}}}).
			Build()
		ls := &gatewayv1.ListenerSet{ObjectMeta: metav1.ObjectMeta{Namespace: "infra-ns"}}
		assert.True(t, isListenerSetAllowed(t.Context(), c, gw, ls, logger))
	})

	t.Run("non-matching label rejected", func(t *testing.T) {
		c := fake.NewClientBuilder().
			WithScheme(helpers.TestScheme(helpers.AllOptionalKinds)).
			WithObjects(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "other-ns", Labels: map[string]string{"team": "platform"}}}).
			Build()
		ls := &gatewayv1.ListenerSet{ObjectMeta: metav1.ObjectMeta{Namespace: "other-ns"}}
		assert.False(t, isListenerSetAllowed(t.Context(), c, gw, ls, logger))
	})
}
