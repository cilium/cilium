// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsclient

import (
	"context"
	"fmt"

	corepb "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discoverypb "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	statuspb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

type delta struct {
}

// delta implements flavour in delta protocol version.
var _ flavour[*discoverypb.DeltaDiscoveryRequest, *discoverypb.DeltaDiscoveryResponse] = (*delta)(nil)

// AggregatedDiscoveryService_DeltaAggregatedResourcesClient implements transport in delta protocol version.
var _ transport[*discoverypb.DeltaDiscoveryRequest, *discoverypb.DeltaDiscoveryResponse] = (discoverypb.AggregatedDiscoveryService_DeltaAggregatedResourcesClient)(nil)

func (delta *delta) transport(ctx context.Context, client discoverypb.AggregatedDiscoveryServiceClient) (transport[*discoverypb.DeltaDiscoveryRequest, *discoverypb.DeltaDiscoveryResponse], error) {
	return client.DeltaAggregatedResources(ctx, grpc.WaitForReady(true))
}

func (delta *delta) prepareObsReq(obsReq *observeRequest, node *corepb.Node, _ getter) (*discoverypb.DeltaDiscoveryRequest, error) {
	return &discoverypb.DeltaDiscoveryRequest{
		Node:                   node,
		TypeUrl:                obsReq.typeUrl,
		ResourceNamesSubscribe: obsReq.resourceNames,
	}, nil
}

func (delta *delta) tx(resp *discoverypb.DeltaDiscoveryResponse, _ getter) (txs, error) {
	ret := make(nameToResource, len(resp.GetResources()))
	for _, res := range resp.GetResources() {
		name := res.GetName()
		msg, _, err := parseResource(resp.GetTypeUrl(), res.GetResource())
		if err != nil {
			return nil, fmt.Errorf("parse resource: %w", err)
		}
		ret[name] = msg
	}
	return txs{{typeUrl: resp.GetTypeUrl(), updated: ret, deleted: resp.GetRemovedResources()}}, nil
}

func (delta *delta) ack(node *corepb.Node, resp *discoverypb.DeltaDiscoveryResponse, _ []string) *discoverypb.DeltaDiscoveryRequest {
	return &discoverypb.DeltaDiscoveryRequest{
		Node:          node,
		ResponseNonce: resp.GetNonce(),
		TypeUrl:       resp.GetTypeUrl(),
	}
}

func (delta *delta) nack(node *corepb.Node, resp *discoverypb.DeltaDiscoveryResponse, detail error) *discoverypb.DeltaDiscoveryRequest {
	return &discoverypb.DeltaDiscoveryRequest{
		Node:          node,
		ResponseNonce: resp.GetNonce(),
		TypeUrl:       resp.GetTypeUrl(),
		ErrorDetail: &statuspb.Status{
			Code:    int32(codes.Unknown),
			Message: detail.Error(),
		},
	}
}
