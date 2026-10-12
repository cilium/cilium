// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"context"
	"reflect"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/endpoint"
	"github.com/cilium/cilium/pkg/revert"
)

// EndpointProxy defines any L7 proxy with which an Endpoint must interact.
type EndpointProxy interface {
	CreateOrUpdateRedirect(ctx context.Context, l4 policy.ProxyPolicy, id string, epID uint16, wg *completion.WaitGroup) (proxyPort uint16, err error, revertFunc revert.RevertFunc)
	RemoveRedirect(id string)
	UpdateSDP(rules map[identity.NumericIdentity]policy.SelectorPolicy)
	UpdateNetworkPolicy(ctx context.Context, ep endpoint.EndpointUpdater, policy *policy.EndpointPolicy, wg *completion.WaitGroup) (error, revert.Revertible)
	RemoveNetworkPolicy(ctx context.Context, ep endpoint.EndpointInfoSource)
	GetListenerProxyPort(listener string) uint16
	IsSDPEnabled() bool
	// DNSProxyReady returns a channel closed once the embedded DNS proxy is
	// listening with its proxy port registered. Used to gate DNS redirect
	// creation on proxy startup.
	DNSProxyReady() <-chan struct{}
}

func (e *Endpoint) removeNetworkPolicy() {
	if e.IsProxyDisabled() {
		return
	}
	e.proxy.RemoveNetworkPolicy(context.Background(), e)
}

func (e *Endpoint) IsProxyDisabled() bool {
	return e.proxy == nil || reflect.ValueOf(e.proxy).IsNil()
}

// FakeEndpointProxy is a stub proxy used for testing.
type FakeEndpointProxy struct{}

// CreateOrUpdateRedirect does nothing.
func (f *FakeEndpointProxy) CreateOrUpdateRedirect(ctx context.Context, l4 policy.ProxyPolicy, id string, epid uint16, wg *completion.WaitGroup) (proxyPort uint16, err error, revertFunc revert.RevertFunc) {
	return
}

// RemoveRedirect does nothing.
func (f *FakeEndpointProxy) RemoveRedirect(id string) {
}

// UpdateNetworkPolicy does nothing.
func (f *FakeEndpointProxy) UpdateNetworkPolicy(ctx context.Context, ep endpoint.EndpointUpdater, policy *policy.EndpointPolicy, wg *completion.WaitGroup) (error, revert.Revertible) {
	return nil, nil
}

// RemoveNetworkPolicy does nothing.
func (f *FakeEndpointProxy) RemoveNetworkPolicy(ctx context.Context, ep endpoint.EndpointInfoSource) {
}

func (f *FakeEndpointProxy) UpdateSDP(rules map[identity.NumericIdentity]policy.SelectorPolicy) {
}

// GetListenerProxyPort does nothing.
func (f *FakeEndpointProxy) GetListenerProxyPort(listener string) uint16 {
	return 0
}

// IsSDPEnabled returns false for fake proxy.
func (f *FakeEndpointProxy) IsSDPEnabled() bool {
	return false
}

// DNSProxyReady returns an already-closed channel; the fake proxy is always ready.
func (f *FakeEndpointProxy) DNSProxyReady() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}
