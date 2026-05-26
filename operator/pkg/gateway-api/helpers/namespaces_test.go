// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package helpers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestNewNamespaceLabelIndex(t *testing.T) {
	index := NewNamespaceLabelIndex([]corev1.Namespace{
		{ObjectMeta: metav1.ObjectMeta{Name: "team-a", Labels: map[string]string{"env": "prod"}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "team-b", Labels: map[string]string{"env": "dev"}}},
	})

	assert.Equal(t, NamespaceLabelIndex{
		"team-a": {"env": "prod"},
		"team-b": {"env": "dev"},
	}, index)
}

func TestIsListenerNamespaceAllowed(t *testing.T) {
	same := gatewayv1.NamespacesFromSame
	all := gatewayv1.NamespacesFromAll
	none := gatewayv1.NamespacesFromNone
	selector := gatewayv1.NamespacesFromSelector
	unknown := gatewayv1.FromNamespaces("Unknown")

	namespaces := NewNamespaceLabelIndex([]corev1.Namespace{
		{ObjectMeta: metav1.ObjectMeta{Name: "infra", Labels: map[string]string{"env": "infra"}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "backend", Labels: map[string]string{"env": "prod"}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "other", Labels: map[string]string{"env": "dev"}}},
		{ObjectMeta: metav1.ObjectMeta{Name: "unlabeled"}},
	})

	tests := []struct {
		name             string
		listener         gatewayv1.Listener
		routeNamespace   string
		gatewayNamespace string
		namespaces       NamespaceLabelIndex
		want             bool
	}{
		{
			name:             "nil AllowedRoutes defaults to Same - same ns",
			listener:         gatewayv1.Listener{Name: "l"},
			routeNamespace:   "infra",
			gatewayNamespace: "infra",
			want:             true,
		},
		{
			name:             "nil AllowedRoutes defaults to Same - different ns",
			listener:         gatewayv1.Listener{Name: "l"},
			routeNamespace:   "other",
			gatewayNamespace: "infra",
			want:             false,
		},
		{
			name: "explicit Same - same ns",
			listener: gatewayv1.Listener{Name: "l", AllowedRoutes: &gatewayv1.AllowedRoutes{
				Namespaces: &gatewayv1.RouteNamespaces{From: &same},
			}},
			routeNamespace:   "infra",
			gatewayNamespace: "infra",
			want:             true,
		},
		{
			name: "explicit Same - different ns",
			listener: gatewayv1.Listener{Name: "l", AllowedRoutes: &gatewayv1.AllowedRoutes{
				Namespaces: &gatewayv1.RouteNamespaces{From: &same},
			}},
			routeNamespace:   "backend",
			gatewayNamespace: "infra",
			want:             false,
		},
		{
			name: "explicit All",
			listener: gatewayv1.Listener{Name: "l", AllowedRoutes: &gatewayv1.AllowedRoutes{
				Namespaces: &gatewayv1.RouteNamespaces{From: &all},
			}},
			routeNamespace:   "anywhere",
			gatewayNamespace: "infra",
			want:             true,
		},
		{
			name: "explicit None",
			listener: gatewayv1.Listener{Name: "l", AllowedRoutes: &gatewayv1.AllowedRoutes{
				Namespaces: &gatewayv1.RouteNamespaces{From: &none},
			}},
			routeNamespace:   "infra",
			gatewayNamespace: "infra",
			want:             false,
		},
		{
			name: "Selector matches namespace labels",
			listener: gatewayv1.Listener{Name: "l", AllowedRoutes: &gatewayv1.AllowedRoutes{
				Namespaces: &gatewayv1.RouteNamespaces{
					From:     &selector,
					Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
				},
			}},
			routeNamespace:   "backend",
			gatewayNamespace: "infra",
			namespaces:       namespaces,
			want:             true,
		},
		{
			name: "Selector rejects non-matching namespace labels",
			listener: gatewayv1.Listener{Name: "l", AllowedRoutes: &gatewayv1.AllowedRoutes{
				Namespaces: &gatewayv1.RouteNamespaces{
					From:     &selector,
					Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
				},
			}},
			routeNamespace:   "other",
			gatewayNamespace: "infra",
			namespaces:       namespaces,
			want:             false,
		},
		{
			name: "Selector rejects missing namespace",
			listener: gatewayv1.Listener{Name: "l", AllowedRoutes: &gatewayv1.AllowedRoutes{
				Namespaces: &gatewayv1.RouteNamespaces{
					From:     &selector,
					Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
				},
			}},
			routeNamespace:   "missing",
			gatewayNamespace: "infra",
			namespaces:       namespaces,
			want:             false,
		},
		{
			name: "Selector rejects invalid selector",
			listener: gatewayv1.Listener{Name: "l", AllowedRoutes: &gatewayv1.AllowedRoutes{
				Namespaces: &gatewayv1.RouteNamespaces{
					From: &selector,
					Selector: &metav1.LabelSelector{MatchExpressions: []metav1.LabelSelectorRequirement{
						{Key: "env", Operator: metav1.LabelSelectorOperator("Invalid")},
					}},
				},
			}},
			routeNamespace:   "backend",
			gatewayNamespace: "infra",
			namespaces:       namespaces,
			want:             false,
		},
		{
			name: "Selector with nil selector rejects namespace",
			listener: gatewayv1.Listener{Name: "l", AllowedRoutes: &gatewayv1.AllowedRoutes{
				Namespaces: &gatewayv1.RouteNamespaces{From: &selector},
			}},
			routeNamespace:   "unlabeled",
			gatewayNamespace: "infra",
			namespaces:       namespaces,
			want:             false,
		},
		{
			name: "nil From with Selector follows selector behavior",
			listener: gatewayv1.Listener{Name: "l", AllowedRoutes: &gatewayv1.AllowedRoutes{
				Namespaces: &gatewayv1.RouteNamespaces{
					Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
				},
			}},
			routeNamespace:   "backend",
			gatewayNamespace: "infra",
			namespaces:       namespaces,
			want:             true,
		},
		{
			name: "nil From with Selector rejects non-matching namespace labels",
			listener: gatewayv1.Listener{Name: "l", AllowedRoutes: &gatewayv1.AllowedRoutes{
				Namespaces: &gatewayv1.RouteNamespaces{
					Selector: &metav1.LabelSelector{MatchLabels: map[string]string{"env": "prod"}},
				},
			}},
			routeNamespace:   "other",
			gatewayNamespace: "infra",
			namespaces:       namespaces,
			want:             false,
		},
		{
			name: "nil From and nil Selector defaults to Same",
			listener: gatewayv1.Listener{Name: "l", AllowedRoutes: &gatewayv1.AllowedRoutes{
				Namespaces: &gatewayv1.RouteNamespaces{},
			}},
			routeNamespace:   "other",
			gatewayNamespace: "infra",
			want:             false,
		},
		{
			name: "unknown From value is denied",
			listener: gatewayv1.Listener{Name: "l", AllowedRoutes: &gatewayv1.AllowedRoutes{
				Namespaces: &gatewayv1.RouteNamespaces{From: &unknown},
			}},
			routeNamespace:   "infra",
			gatewayNamespace: "infra",
			want:             false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, IsListenerNamespaceAllowed(tt.listener, tt.routeNamespace, tt.gatewayNamespace, tt.namespaces))
		})
	}
}
