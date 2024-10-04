// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import "context"

type FakeRouter struct {
	paths map[string]*Path
}

func NewFakeRouter() Router {
	return &FakeRouter{
		paths: make(map[string]*Path),
	}
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
	f.paths[path.NLRI.String()] = path
	return PathResponse{path}, nil
}

func (f *FakeRouter) WithdrawPath(ctx context.Context, p PathRequest) error {
	path := p.Path
	delete(f.paths, path.NLRI.String())
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
	var routes []*Route
	for _, path := range f.paths {
		routes = append(routes, &Route{
			Prefix: path.NLRI.String(),
			Paths:  []*Path{path},
		})
	}
	return &GetRoutesResponse{Routes: routes}, nil
}

func (f *FakeRouter) GetRoutePolicies(ctx context.Context) (*GetRoutePoliciesResponse, error) {
	return nil, nil
}

func (f *FakeRouter) GetBGP(ctx context.Context) (GetBGPResponse, error) {
	return GetBGPResponse{}, nil
}
