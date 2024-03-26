// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import "context"

type FakeRouter struct{}

func NewFakeRouter() Router {
	return &FakeRouter{}
}

func (f *FakeRouter) Stop() {}

func (f *FakeRouter) AddNeighbor(ctx context.Context, n NeighborRequest) error {
	return nil
}

func (f *FakeRouter) UpdateNeighbor(ctx context.Context, n NeighborRequest) error {
	return nil
}

func (f *FakeRouter) RemoveNeighbor(ctx context.Context, n NeighborRequest) error {
	return nil
}

func (f *FakeRouter) ResetNeighbor(ctx context.Context, r ResetNeighborRequest) error {
	return nil
}

func (f *FakeRouter) AdvertisePath(ctx context.Context, p PathRequest) (PathResponse, error) {
	path := p.Path
	return PathResponse{path}, nil
}

func (f *FakeRouter) WithdrawPath(ctx context.Context, p PathRequest) error {
	return nil
}

func (f *FakeRouter) AddRoutePolicy(ctx context.Context, p RoutePolicyRequest) error {
	return nil
}

func (f *FakeRouter) RemoveRoutePolicy(ctx context.Context, p RoutePolicyRequest) error {
	return nil
}

func (f *FakeRouter) GetPeerState(ctx context.Context) (GetPeerStateResponse, error) {
	return GetPeerStateResponse{}, nil
}

func (f *FakeRouter) GetRoutes(ctx context.Context, r *GetRoutesRequest) (*GetRoutesResponse, error) {
	return nil, nil
}

func (f *FakeRouter) GetRoutePolicies(ctx context.Context) (*GetRoutePoliciesResponse, error) {
	return nil, nil
}

func (f *FakeRouter) GetBGP(ctx context.Context) (GetBGPResponse, error) {
	return GetBGPResponse{}, nil
}
