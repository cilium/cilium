// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxy

import (
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/fqdn/proxy"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/revert"
)

var (
	// DefaultDNSProxy is the global, shared, DNS Proxy singleton.
	DefaultDNSProxy proxy.DNSProxier
	// GlobalStandaloneDNSProxy is the global, shared, standalone DNS Proxy singleton.
	GlobalStandaloneDNSProxy sdpPolicyUpdater
)

// dnsRedirect implements the Redirect interface for an l7 proxy
type dnsRedirect struct {
	Redirect
	proxyRuleUpdater proxyRuleUpdater
}

func (dr *dnsRedirect) GetRedirect() *Redirect {
	return &dr.Redirect
}

// proxyRuleUpdater updates L7 proxy rules per endpoint.
//
// Note: Implementations must not take the IPcache lock, as the usage of this
// interface is within the endpoint regeneration critical section.
type proxyRuleUpdater interface {
	// UpdateAllowed updates the rules in the DNS proxy with newRules for the
	// endpointID and destPort.
	UpdateAllowed(endpointID uint64, destPort restore.PortProto, newRules policy.L7DataMap) (revert.RevertFunc, error)
}

type sdpPolicyUpdater interface {
	UpdatePolicyRulesLocked(map[identity.NumericIdentity]policy.SelectorPolicy, bool) error
}

// setRules replaces old l7 rules of a redirect with new ones.
func (dr *dnsRedirect) setRules(newRules policy.L7DataMap) (revert.RevertFunc, error) {
	dr.logger.Debug("DNS Proxy updating matchNames in allowed list during UpdateRules",
		"newRules", newRules,
		logfields.EndpointID, dr.endpointID,
	)
	return dr.proxyRuleUpdater.UpdateAllowed(uint64(dr.endpointID), dr.dstPortProto, newRules)
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

type dnsProxyIntegration struct{}

// createRedirect creates a redirect to the dns proxy. The redirect structure passed
// in is safe to access for reading and writing.
func (p *dnsProxyIntegration) createRedirect(redirect Redirect) (RedirectImplementation, error) {
	dr := &dnsRedirect{
		Redirect:         redirect,
		proxyRuleUpdater: DefaultDNSProxy,
	}

	return dr, nil
}

func (p *dnsProxyIntegration) changeLogLevel(level logrus.Level) error {
	return nil
}
