// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium
package xdsclient

import (
	"context"

	corepb "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// NewInsecureGRPCOptionsProvider creates dial options provider for insecure
// GRPC connections.
func NewInsecureGRPCOptionsProvider() DialOptionsProvider {
	return &insecureGRPCOptionsProvider{}
}

// insecureGRPCOptionsProvider implements DialOptionsProvider
type insecureGRPCOptionsProvider struct{}

// GRPCOptions creates grpc Dial options with insecure credentials.
func (g *insecureGRPCOptionsProvider) GRPCOptions(context.Context) ([]grpc.DialOption, error) {
	return []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	}, nil
}

// NewDefaultNodeProvider creates node provider for building default xds Node.
func NewDefaultNodeProvider() NodeProvider {
	return &defaultNodeProvider{}
}

// defaultNodeProvider implements NodeProvider
type defaultNodeProvider struct{}

// Node provides default Node with zone locality for xds client.
func (*defaultNodeProvider) Node(nodeID, zone string) *corepb.Node {
	locality := &corepb.Locality{
		Zone: zone,
	}
	return &corepb.Node{
		Id:            nodeID,
		UserAgentName: "cilium-agent",
		Locality:      locality,
	}
}
