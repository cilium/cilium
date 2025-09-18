// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsclient

import (
	"context"
	"fmt"
	"maps"
	"slices"

	corepb "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	discoverypb "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	statuspb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/envoy"
)

type sotw struct {
}

// sotw implements flavour in sotw protocol version.
var _ flavour[*discoverypb.DiscoveryRequest, *discoverypb.DiscoveryResponse] = (*sotw)(nil)

// AggregatedDiscoveryService_StreamAggregatedResourcesClient implements transport in sotw protocol version.
var _ transport[*discoverypb.DiscoveryRequest, *discoverypb.DiscoveryResponse] = (discoverypb.AggregatedDiscoveryService_StreamAggregatedResourcesClient)(nil)

func (sotw *sotw) transport(ctx context.Context, client discoverypb.AggregatedDiscoveryServiceClient) (transport[*discoverypb.DiscoveryRequest, *discoverypb.DiscoveryResponse], error) {
	return client.StreamAggregatedResources(ctx, grpc.WaitForReady(true))
}

func (sotw *sotw) prepareObsReq(obsReq *observeRequest, node *corepb.Node, get getter) (*discoverypb.DiscoveryRequest, error) {
	curr, err := get(obsReq.typeUrl)
	if err != nil {
		return nil, fmt.Errorf("get resources: %w", err)
	}
	reqResourceNames := sets.Set[string]{}
	reqResourceNames.Insert(curr.ResourceNames...)
	reqResourceNames.Insert(obsReq.resourceNames...)

	return &discoverypb.DiscoveryRequest{
		Node:          node,
		TypeUrl:       obsReq.typeUrl,
		ResourceNames: slices.Collect(maps.Keys(reqResourceNames)),
	}, nil
}

func (sotw *sotw) tx(resp *discoverypb.DiscoveryResponse, get getter) (txs, error) {
	typeUrl := resp.GetTypeUrl()
	upsertedResources := make(nameToResource)
	for _, res := range resp.GetResources() {
		msg, name, err := parseResource(typeUrl, res)
		if err != nil {
			return nil, fmt.Errorf("parse resource: %w", err)
		}
		upsertedResources[name] = msg
	}

	var deletedResources []string
	var err error
	if typeUrl == envoy.ListenerTypeURL || typeUrl == envoy.ClusterTypeURL {
		deletedResources, err = findMissing(typeUrl, upsertedResources, get)
		if err != nil {
			return nil, fmt.Errorf("delete listeners/clusters: %w", err)
		}
	}
	transactions := txs{{typeUrl: typeUrl, updated: upsertedResources, deleted: deletedResources}}

	if typeUrl == envoy.ClusterTypeURL {
		deletedResources, err := findMissing(envoy.EndpointTypeURL, upsertedResources, get)
		if err != nil {
			return nil, fmt.Errorf("delete endpoints (after processing clusters): %w", err)
		}
		transactions = append(transactions, tx{typeUrl: envoy.EndpointTypeURL, deleted: deletedResources})
	}
	return transactions, nil
}

func findMissing(typeUrl string, curr nameToResource, get getter) ([]string, error) {
	old, err := get(typeUrl)
	if err != nil {
		// In version 1.14 GetResources doesn't return any error for these arguments.
		return nil, fmt.Errorf("get old resources: %w", err)
	}
	deletedResources := make([]string, 0, len(old.ResourceNames))
	for _, name := range old.ResourceNames {
		if _, ok := curr[name]; ok {
			continue
		}
		deletedResources = append(deletedResources, name)
	}
	return deletedResources, nil
}

func (sotw *sotw) ack(node *corepb.Node, resp *discoverypb.DiscoveryResponse, resourceNames []string) *discoverypb.DiscoveryRequest {
	return &discoverypb.DiscoveryRequest{
		Node:          node,
		VersionInfo:   resp.GetVersionInfo(),
		ResponseNonce: resp.GetNonce(),
		TypeUrl:       resp.GetTypeUrl(),
		ResourceNames: resourceNames,
	}
}

func (sotw *sotw) nack(node *corepb.Node, resp *discoverypb.DiscoveryResponse, detail error) *discoverypb.DiscoveryRequest {
	return &discoverypb.DiscoveryRequest{
		Node:          node,
		ResponseNonce: resp.GetNonce(),
		TypeUrl:       resp.GetTypeUrl(),
		ErrorDetail: &statuspb.Status{
			Code:    int32(codes.Unknown),
			Message: detail.Error(),
		},
	}
}
