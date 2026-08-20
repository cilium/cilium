// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gateway_api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func Test_sectionNameMatched(t *testing.T) {
	manager := &ListenerStatusManager{}
	httpListener := &gatewayv1.Listener{
		Name:     "http",
		Port:     80,
		Hostname: ptr.To[gatewayv1.Hostname]("*.cilium.io"),
		Protocol: "HTTP",
	}
	httpNoMatchListener := &gatewayv1.Listener{
		Name:     "http-no-match",
		Port:     8080,
		Hostname: ptr.To[gatewayv1.Hostname]("*.cilium.io"),
		Protocol: "HTTP",
	}
	gw := &gatewayv1.Gateway{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Gateway",
			APIVersion: gatewayv1.GroupName,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "valid-gateway",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "cilium",
			Listeners: []gatewayv1.Listener{
				*httpListener,
				*httpNoMatchListener,
			},
		},
	}
	type args struct {
		routeNamespace string
		listener       *gatewayv1.Listener
		refs           []gatewayv1.ParentReference
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "Matching Section name",
			args: args{
				listener: httpListener,
				refs: []gatewayv1.ParentReference{{
					Kind:        (*gatewayv1.Kind)(ptr.To("Gateway")),
					Name:        "valid-gateway",
					SectionName: (*gatewayv1.SectionName)(ptr.To("http")),
				}},
			},
			want: true,
		},
		{
			name: "Not matching Section name",
			args: args{
				listener: httpNoMatchListener,
				refs: []gatewayv1.ParentReference{{
					Kind:        (*gatewayv1.Kind)(ptr.To("Gateway")),
					Name:        "valid-gateway",
					SectionName: (*gatewayv1.SectionName)(ptr.To("http")),
				}},
			},
			want: false,
		},
		{
			name: "Matching Port number",
			args: args{
				listener: httpListener,
				refs: []gatewayv1.ParentReference{{
					Kind: (*gatewayv1.Kind)(ptr.To("Gateway")),
					Name: "valid-gateway",
					Port: (*gatewayv1.PortNumber)(ptr.To[int32](80)),
				}},
			},
			want: true,
		},
		{
			name: "No matching Port number",
			args: args{
				listener: httpNoMatchListener,
				refs: []gatewayv1.ParentReference{{
					Kind: (*gatewayv1.Kind)(ptr.To("Gateway")),
					Name: "valid-gateway",
					Port: (*gatewayv1.PortNumber)(ptr.To[int32](80)),
				}},
			},
			want: false,
		},
		{
			name: "Matching both Section name and Port number",
			args: args{
				listener: httpListener,
				refs: []gatewayv1.ParentReference{{
					Kind:        (*gatewayv1.Kind)(ptr.To("Gateway")),
					Name:        "valid-gateway",
					SectionName: (*gatewayv1.SectionName)(ptr.To("http")),
					Port:        (*gatewayv1.PortNumber)(ptr.To[int32](80)),
				}},
			},
			want: true,
		},
		{
			name: "Matching any listener (httpListener)",
			args: args{
				listener: httpListener,
				refs: []gatewayv1.ParentReference{{
					Kind: (*gatewayv1.Kind)(ptr.To("Gateway")),
					Name: "valid-gateway",
				}},
			},
			want: true,
		},
		{
			name: "Matching any listener (httpNoMatchListener)",
			args: args{
				listener: httpNoMatchListener,
				refs: []gatewayv1.ParentReference{{
					Kind: (*gatewayv1.Kind)(ptr.To("Gateway")),
					Name: "valid-gateway",
				}},
			},
			want: true,
		},
		{
			name: "GAMMA Service with same name as Gateway should not match",
			args: args{
				listener: httpListener,
				refs: []gatewayv1.ParentReference{{
					Kind:  (*gatewayv1.Kind)(ptr.To("Service")),
					Group: (*gatewayv1.Group)(ptr.To("")),
					Name:  "valid-gateway",
				}},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, manager.parentRefMatched(gw, tt.args.listener, nil, "default", tt.args.refs), "parentRefMatched(%v, %v, %v, %v)", gw, tt.args.listener, tt.args.routeNamespace, tt.args.refs)
		})
	}
}
