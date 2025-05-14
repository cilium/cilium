// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxy

import (
	"log/slog"

	fqdnproxy "github.com/cilium/cilium/pkg/fqdn/proxy"
	"github.com/cilium/cilium/pkg/fqdn/service"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/revert"
)

// dnsRedirect implements the Redirect interface for an l7 proxy
type dnsRedirect struct {
	Redirect
	dnsProxy fqdnproxy.DNSProxier
}

func (dr *dnsRedirect) GetRedirect() *Redirect {
	return &dr.Redirect
}

// setRules replaces old l7 rules of a redirect with new ones.
func (dr *dnsRedirect) setRules(newRules policy.L7DataMap) (revert.RevertFunc, error) {
	dr.logger.Debug(
		"DNS Proxy updating matchNames in allowed list during UpdateRules",
		logfields.NewRules, newRules,
		logfields.EndpointID, dr.endpointID,
	)

	return dr.dnsProxy.UpdateAllowed(uint64(dr.endpointID), dr.dstPortProto, newRules)
}

// UpdateRules atomically replaces the proxy rules in effect for this redirect.
// It is not aware of revision number and doesn't account for out-of-order
// calls to UpdateRules or the returned RevertFunc.
func (dr *dnsRedirect) UpdateRules(rules policy.L7DataMap) (revert.RevertFunc, error) {
	return dr.setRules(rules)
}

// Close the redirect.
func (dr *dnsRedirect) Close() {
	dr.setRules(nil)
}

type dnsProxyIntegration struct {
	dnsProxy         fqdnproxy.DNSProxier
	sdpPolicyUpdater service.PolicyUpdater
}

// createRedirect creates a redirect to the dns proxy. The redirect structure passed
// in is safe to access for reading and writing.
func (p *dnsProxyIntegration) createRedirect(redirect Redirect) (RedirectImplementation, error) {
	dr := &dnsRedirect{
		Redirect: redirect,
		dnsProxy: p.dnsProxy,
	}

	return dr, nil
}

func (p *dnsProxyIntegration) changeLogLevel(level slog.Level) error {
	return nil
}
