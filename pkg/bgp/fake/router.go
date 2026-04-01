// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"context"
	"maps"
	"net/netip"

	"github.com/cilium/cilium/pkg/bgp/types"
	"github.com/cilium/cilium/pkg/lock"
)

type FakeRouter struct {
	mu       lock.RWMutex
	paths    map[string]*types.Path
	policies map[string]*types.RoutePolicy
	resets   map[netip.Addr]types.SoftResetDirection
}

func NewFakeRouter() *FakeRouter {
	return &FakeRouter{
		paths:    make(map[string]*types.Path),
		policies: make(map[string]*types.RoutePolicy),
		resets:   make(map[netip.Addr]types.SoftResetDirection),
	}
}

func (f *FakeRouter) Stop(ctx context.Context, r types.StopRequest) {}

func (f *FakeRouter) AddNeighbor(ctx context.Context, n *types.Neighbor) error {
	return nil
}

func (f *FakeRouter) UpdateNeighbor(ctx context.Context, n *types.Neighbor) error {
	return nil
}

func (f *FakeRouter) RemoveNeighbor(ctx context.Context, n *types.Neighbor) error {
	return nil
}

func (f *FakeRouter) ResetNeighbor(ctx context.Context, r types.ResetNeighborRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Soft {
		f.resets[r.PeerAddress] = r.SoftResetDirection
	}
	return nil
}

func (f *FakeRouter) ResetAllNeighbors(ctx context.Context, r types.ResetAllNeighborsRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Soft {
		// Use an invalid address to indicate the all reset
		f.resets[netip.Addr{}] = r.SoftResetDirection
	}
	return nil
}

func (f *FakeRouter) GetResets() map[netip.Addr]types.SoftResetDirection {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return maps.Clone(f.resets)
}

func (f *FakeRouter) AdvertisePath(ctx context.Context, p types.PathRequest) (types.PathResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := p.Path
	f.paths[path.NLRI.String()] = path
	return types.PathResponse{Path: path}, nil
}

func (f *FakeRouter) WithdrawPath(ctx context.Context, p types.PathRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := p.Path
	delete(f.paths, path.NLRI.String())
	return nil
}

func (f *FakeRouter) AddRoutePolicy(ctx context.Context, p types.RoutePolicyRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.policies[p.Policy.Name] = p.Policy
	return nil
}

func (f *FakeRouter) RemoveRoutePolicy(ctx context.Context, p types.RoutePolicyRequest) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.policies, p.Policy.Name)
	return nil
}

func (f *FakeRouter) GetPeerState(ctx context.Context, r *types.GetPeerStateRequest) (*types.GetPeerStateResponse, error) {
	return &types.GetPeerStateResponse{}, nil
}

func (f *FakeRouter) GetPeerStateLegacy(ctx context.Context) (types.GetPeerStateLegacyResponse, error) {
	return types.GetPeerStateLegacyResponse{}, nil
}

func (f *FakeRouter) GetRoutes(ctx context.Context, r *types.GetRoutesRequest) (*types.GetRoutesResponse, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	var routes []*types.Route
	for _, path := range f.paths {
		routes = append(routes, &types.Route{
			Prefix: path.NLRI.String(),
			Paths:  []*types.Path{path},
		})
	}
	return &types.GetRoutesResponse{Routes: routes}, nil
}

func (f *FakeRouter) GetRoutePolicies(ctx context.Context) (*types.GetRoutePoliciesResponse, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	var policies []*types.RoutePolicy
	for _, policy := range f.policies {
		policies = append(policies, policy)
	}
	return &types.GetRoutePoliciesResponse{Policies: policies}, nil
}

func (f *FakeRouter) GetBGP(ctx context.Context) (types.GetBGPResponse, error) {
	return types.GetBGPResponse{}, nil
}
