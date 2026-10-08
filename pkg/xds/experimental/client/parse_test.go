// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsclient

import (
	"strings"
	"testing"

	clusterpb "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	endpointpb "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listenerpb "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routepb "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/cilium/cilium/pkg/envoy"
)

func TestParseResource(t *testing.T) {
	const name = "test_name"
	for _, tc := range []struct {
		name    string
		typeUrl string
		res     *anypb.Any
		wantErr string
	}{
		{
			name:    "listener_ok",
			typeUrl: envoy.ListenerTypeURL,
			res:     mustMarshalAny(&listenerpb.Listener{Name: name}),
		},
		{
			name:    "listener_missing_name",
			typeUrl: envoy.ListenerTypeURL,
			res:     mustMarshalAny(&listenerpb.Listener{Name: ""}),
			wantErr: "missing name",
		},
		{
			name:    "cluster_ok",
			typeUrl: envoy.ClusterTypeURL,
			res:     mustMarshalAny(&clusterpb.Cluster{Name: name}),
		},
		{
			name:    "cluster_missing_name",
			typeUrl: envoy.ClusterTypeURL,
			res:     mustMarshalAny(&clusterpb.Cluster{Name: ""}),
			wantErr: "missing name",
		},
		{
			name:    "endpoint_ok",
			typeUrl: envoy.EndpointTypeURL,
			res:     mustMarshalAny(&endpointpb.ClusterLoadAssignment{ClusterName: name}),
		},
		{
			name:    "endpoint_missing_name",
			typeUrl: envoy.EndpointTypeURL,
			res:     mustMarshalAny(&endpointpb.ClusterLoadAssignment{ClusterName: ""}),
			wantErr: "missing name",
		},
		{
			name:    "route_ok",
			typeUrl: envoy.RouteTypeURL,
			res:     mustMarshalAny(&routepb.RouteConfiguration{Name: name}),
		},
		{
			name:    "route_missing_name",
			typeUrl: envoy.RouteTypeURL,
			res:     mustMarshalAny(&routepb.RouteConfiguration{Name: ""}),
			wantErr: "missing name",
		},
		{
			name:    "wrong_type_url",
			typeUrl: envoy.ClusterTypeURL,
			res:     mustMarshalAny(&listenerpb.Listener{Name: name}),
			wantErr: "mismatched typeUrls",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg, parsedName, err := parseResource(tc.typeUrl, tc.res)
			if err != nil {
				if tc.wantErr == "" {
					t.Fatalf("error = %v, want = nil", err)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error = %v, want = %s", err, tc.wantErr)
				}
				return
			}
			if tc.wantErr != "" {
				t.Fatalf("error = nil, want = %s", tc.wantErr)
			}
			if msg == nil {
				t.Error("unexpected nil msg")
			}
			if parsedName != name {
				t.Errorf("parsedName = %s, want = %s", parsedName, name)
			}
		})
	}
}
