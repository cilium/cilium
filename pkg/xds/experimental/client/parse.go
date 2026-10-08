// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsclient

import (
	"fmt"

	clusterpb "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	endpointpb "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listenerpb "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	routepb "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

func parseResource(typeUrl string, res *anypb.Any) (proto.Message, string, error) {
	if typeUrl != res.GetTypeUrl() {
		return nil, "", fmt.Errorf("mismatched typeUrls, got = %s, want = %s", res.GetTypeUrl(), typeUrl)
	}
	msg, err := res.UnmarshalNew()
	if err != nil {
		return nil, "", fmt.Errorf("resource typeUrl=%q: unmarshal: %w", typeUrl, err)
	}
	var name string
	switch obj := msg.(type) {
	case *listenerpb.Listener:
		name = obj.GetName()
	case *clusterpb.Cluster:
		name = obj.GetName()
	case *endpointpb.ClusterLoadAssignment:
		name = obj.GetClusterName()
	case *routepb.RouteConfiguration:
		name = obj.GetName()
	default:
		return nil, "", fmt.Errorf("unhandled typeUrl=%q", typeUrl)
	}
	if name == "" {
		return nil, "", fmt.Errorf("missing name for typeUrl=%q", typeUrl)
	}
	return msg, name, nil
}
