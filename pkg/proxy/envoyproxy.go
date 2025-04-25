// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxy

import (
	"fmt"
	"log/slog"
	"net"

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
	Redirect
	listenerName string
	xdsServer    envoy.XDSServer
	adminClient  *envoy.EnvoyAdminClient
}

func (dr *envoyRedirect) GetRedirect() *Redirect {
	return &dr.Redirect
}

type envoyProxyIntegration struct {
	adminClient     *envoy.EnvoyAdminClient
	xdsServer       envoy.XDSServer
	iptablesManager datapath.IptablesManager
}

// createRedirect creates a redirect with corresponding proxy configuration. This will launch a proxy instance.
func (p *envoyProxyIntegration) createRedirect(r Redirect, wg *completion.WaitGroup, cb func(err error)) (RedirectImplementation, error) {
	if r.proxyPort.ProxyType == types.ProxyTypeCRD {
		// CRD Listeners already exist, create a no-op implementation
		return &CRDRedirect{Redirect: r}, nil
	}

	// create an Envoy Listener for Cilium policy enforcement
	l := r.proxyPort
	redirect := &envoyRedirect{
		Redirect:     r,
		listenerName: net.JoinHostPort(r.name, fmt.Sprintf("%d", l.ProxyPort)),
		xdsServer:    p.xdsServer,
		adminClient:  p.adminClient,
	}

	mayUseOriginalSourceAddr := p.iptablesManager.SupportsOriginalSourceAddr()
	// Only use original source address for egress
	if l.Ingress {
		mayUseOriginalSourceAddr = false
	}
	err := p.xdsServer.AddListener(redirect.listenerName, policy.L7ParserType(l.ProxyType), l.ProxyPort, l.Ingress, mayUseOriginalSourceAddr, wg, cb)

	return redirect, err
}

func (p *envoyProxyIntegration) changeLogLevel(level slog.Level) error {
	return p.adminClient.ChangeLogLevel(level)
}

func (p *envoyProxyIntegration) UpdateNetworkPolicy(ep endpoint.EndpointUpdater, policy *policy.L4Policy, ingressPolicyEnforced, egressPolicyEnforced bool, wg *completion.WaitGroup) (error, func() error) {
	return p.xdsServer.UpdateNetworkPolicy(ep, policy, ingressPolicyEnforced, egressPolicyEnforced, wg)
}

func (p *envoyProxyIntegration) UseCurrentNetworkPolicy(ep endpoint.EndpointUpdater, policy *policy.L4Policy, wg *completion.WaitGroup) {
	p.xdsServer.UseCurrentNetworkPolicy(ep, policy, wg)
}

func (p *envoyProxyIntegration) RemoveNetworkPolicy(ep endpoint.EndpointInfoSource) {
	p.xdsServer.RemoveNetworkPolicy(ep)
}

// UpdateRules is a no-op for envoy, as redirect data is synchronized via the xDS cache.
func (k *envoyRedirect) UpdateRules(rules policy.L7DataMap) (revert.RevertFunc, error) {
	return nil, nil
}

// Close the redirect.
func (r *envoyRedirect) Close() {
	r.xdsServer.RemoveListener(r.listenerName, nil)
}
