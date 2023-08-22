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
	adminClient *envoy.EnvoyAdminClient
	xdsServer   envoy.XDSServer
	datapath    datapath.Datapath
}

// createRedirect creates a redirect with corresponding proxy configuration. This will launch a proxy instance.
func (p *envoyProxyIntegration) createRedirect(r *Redirect, wg *completion.WaitGroup) (RedirectImplementation, error) {
	if r.listener.proxyType == types.ProxyTypeCRD {
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
		listenerName: net.JoinHostPort(r.name, fmt.Sprintf("%d", l.proxyPort)),
		xdsServer:    p.xdsServer,
		adminClient:  p.adminClient,
	}

	mayUseOriginalSourceAddr := p.datapath.SupportsOriginalSourceAddr()
	// Only use original source address for egress
	if l.ingress {
		mayUseOriginalSourceAddr = false
	}
	p.xdsServer.AddListener(redirect.listenerName, policy.L7ParserType(l.proxyType), l.proxyPort, l.ingress, mayUseOriginalSourceAddr, wg)

	return redirect, nil
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
