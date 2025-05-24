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
	UpdateNetworkPolicy(ep endpoint.EndpointUpdater, policy *policy.L4Policy, ingressPolicyEnforced, egressPolicyEnforced bool, wg *completion.WaitGroup) (error, func() error)
	UseCurrentNetworkPolicy(ep endpoint.EndpointUpdater, policy *policy.L4Policy, wg *completion.WaitGroup)
	RemoveNetworkPolicy(ep endpoint.EndpointInfoSource)
	GetListenerProxyPort(listener string) uint16
}

func (e *Endpoint) removeNetworkPolicy() {
	if e.IsProxyDisabled() {
		return
	}
	e.proxy.RemoveNetworkPolicy(e)
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

// UseCurrentNetworkPolicy does nothing.
func (f *FakeEndpointProxy) UseCurrentNetworkPolicy(ep endpoint.EndpointUpdater, policy *policy.L4Policy, wg *completion.WaitGroup) {
}

// UpdateNetworkPolicy does nothing.
func (f *FakeEndpointProxy) UpdateNetworkPolicy(ep endpoint.EndpointUpdater, policy *policy.L4Policy, ingressPolicyEnforced, egressPolicyEnforced bool, wg *completion.WaitGroup) (error, func() error) {
	return nil, nil
}

// RemoveNetworkPolicy does nothing.
func (f *FakeEndpointProxy) RemoveNetworkPolicy(ep endpoint.EndpointInfoSource) {}

func (f *FakeEndpointProxy) UpdateSDP(rules map[identity.NumericIdentity]policy.SelectorPolicy) {
}

// GetListenerProxyPort does nothing.
func (f *FakeEndpointProxy) GetListenerProxyPort(listener string) uint16 {
	return 0
}
