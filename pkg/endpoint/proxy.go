// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package endpoint

import (
	"fmt"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/logger"
	"github.com/cilium/cilium/pkg/revert"
	"github.com/sirupsen/logrus"
)

// EndpointProxy defines any L7 proxy with which an Endpoint must interact.
type EndpointProxy interface {
	CreateOrUpdateRedirect(l4 *policy.L4Filter, id string, localEndpoint logger.EndpointUpdater, wg *completion.WaitGroup) (proxyPort uint16, err error, finalizeFunc revert.FinalizeFunc, revertFunc revert.RevertFunc)
	RemoveRedirect(id string, wg *completion.WaitGroup) (error, revert.FinalizeFunc, revert.RevertFunc)
	UpdateNetworkPolicy(ep logger.EndpointUpdater, policy *policy.L4Policy, ingressPolicyEnforced, egressPolicyEnforced bool, wg *completion.WaitGroup) (error, func() error)
	RemoveNetworkPolicy(ep logger.EndpointInfoSource)
}

// SetProxy sets the proxy for this endpoint.
func (e *Endpoint) SetProxy(p EndpointProxy) {
	e.unconditionalLock()
	defer e.unlock()
	e.proxy = p
}

// updateProxyRedirect updates the redirect rules in the proxy for a particular
// endpoint using the provided L4 filter. Returns the allocated proxy port
func (e *Endpoint) updateProxyRedirect(l4 *policy.L4Filter, proxyWaitGroup *completion.WaitGroup) (proxyPort uint16, err error, finalizeFunc revert.FinalizeFunc, revertFunc revert.RevertFunc) {
	if e.proxy == nil {
		return 0, fmt.Errorf("can't redirect, proxy disabled"), nil, nil
	}
	return e.proxy.CreateOrUpdateRedirect(l4, e.ProxyID(l4), e, proxyWaitGroup)
}

// removeProxyRedirect removes a previously installed proxy redirect for an
// endpoint.
func (e *Endpoint) removeProxyRedirect(id string, proxyWaitGroup *completion.WaitGroup) (error, revert.FinalizeFunc, revert.RevertFunc) {
	if e.proxy == nil {
		return nil, nil, nil
	}
	log.WithFields(logrus.Fields{
		logfields.EndpointID: e.ID,
		logfields.L4PolicyID: id,
	}).Debug("Removing redirect to endpoint")
	return e.proxy.RemoveRedirect(id, proxyWaitGroup)
}

func (e *Endpoint) removeNetworkPolicy() {
	if e.proxy == nil {
		return
	}
	e.proxy.RemoveNetworkPolicy(e)
}

type FakeEndpointProxy struct{}

func (f *FakeEndpointProxy) CreateOrUpdateRedirect(l4 *policy.L4Filter, id string, localEndpoint logger.EndpointUpdater, wg *completion.WaitGroup) (proxyPort uint16, err error, finalizeFunc revert.FinalizeFunc, revertFunc revert.RevertFunc) {
	return
}

func (f *FakeEndpointProxy) RemoveRedirect(id string, wg *completion.WaitGroup) (error, revert.FinalizeFunc, revert.RevertFunc) {
	return nil, nil, nil
}
func (f *FakeEndpointProxy) UpdateNetworkPolicy(ep logger.EndpointUpdater, policy *policy.L4Policy, ingressPolicyEnforced, egressPolicyEnforced bool, wg *completion.WaitGroup) (error, func() error) {
	return nil, nil
}
func (f *FakeEndpointProxy) RemoveNetworkPolicy(ep logger.EndpointInfoSource) {}
