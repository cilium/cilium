// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxy

import (
	"fmt"
	"net"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/completion"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/endpoint"
	"github.com/cilium/cilium/pkg/proxy/types"
	"github.com/cilium/cilium/pkg/revert"
)

// envoyRedirect implements the RedirectImplementation interface for an l7 proxy.
type envoyRedirect struct {
	listenerName string
	xdsServer    envoy.XDSServer
	adminClient  *envoy.EnvoyAdminClient
}

type envoyProxyIntegration struct {
	adminClient     *envoy.EnvoyAdminClient
	xdsServer       envoy.XDSServer
	iptablesManager datapath.IptablesManager
}

// createRedirect creates a redirect with corresponding proxy configuration. This will launch a proxy instance.
func (p *envoyProxyIntegration) createRedirect(r *Redirect, wg *completion.WaitGroup) (RedirectImplementation, error) {
	if r.listener.ProxyType == types.ProxyTypeCRD {
		// CRD Listeners already exist, create a no-op implementation
		return &CRDRedirect{}, nil
	}

	// create an Envoy Listener for Cilium policy enforcement
	return p.handleEnvoyRedirect(r, wg)
}

func (p *envoyProxyIntegration) changeLogLevel(level logrus.Level) error {
	return p.adminClient.ChangeLogLevel(level)
}

func (p *envoyProxyIntegration) handleEnvoyRedirect(r *Redirect, wg *completion.WaitGroup) (RedirectImplementation, error) {
	l := r.listener
	redirect := &envoyRedirect{
		listenerName: net.JoinHostPort(r.name, fmt.Sprintf("%d", l.ProxyPort)),
		xdsServer:    p.xdsServer,
		adminClient:  p.adminClient,
	}

	mayUseOriginalSourceAddr := p.iptablesManager.SupportsOriginalSourceAddr()
	// Only use original source address for egress
	if l.Ingress {
		mayUseOriginalSourceAddr = false
	}
	p.xdsServer.AddListener(redirect.listenerName, policy.L7ParserType(l.ProxyType), l.ProxyPort, l.Ingress, mayUseOriginalSourceAddr, wg)

	return redirect, nil
}

func (p *envoyProxyIntegration) UpdateNetworkPolicy(ep endpoint.EndpointUpdater, vis *policy.VisibilityPolicy, policy *policy.L4Policy, ingressPolicyEnforced, egressPolicyEnforced bool, wg *completion.WaitGroup) (error, func() error) {
	return p.xdsServer.UpdateNetworkPolicy(ep, vis, policy, ingressPolicyEnforced, egressPolicyEnforced, wg)
}

func (p *envoyProxyIntegration) RemoveNetworkPolicy(ep endpoint.EndpointInfoSource) {
	p.xdsServer.RemoveNetworkPolicy(ep)
}

// UpdateRules is a no-op for envoy, as redirect data is synchronized via the xDS cache.
func (k *envoyRedirect) UpdateRules(wg *completion.WaitGroup) (revert.RevertFunc, error) {
	return func() error { return nil }, nil
}

// Close the redirect.
func (r *envoyRedirect) Close(wg *completion.WaitGroup) (revert.FinalizeFunc, revert.RevertFunc) {
	revertFunc := r.xdsServer.RemoveListener(r.listenerName, wg)

	return nil, func() error {
		// Don't wait for an ACK for the reverted xDS updates.
		// This is best-effort.
		revertFunc(completion.NewCompletion(nil, nil))
		return nil
	}
}
