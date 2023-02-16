// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxy

import (
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/fqdn/proxy"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/logger"
	"github.com/cilium/cilium/pkg/revert"
)

var (
	// DefaultDNSProxy is the global, shared, DNS Proxy singleton.
	DefaultDNSProxy proxy.DNSProxier
)

// dnsRedirect implements the Redirect interface for an l7 proxy
type dnsRedirect struct {
	redirect             *Redirect
	endpointInfoRegistry logger.EndpointInfoRegistry
	currentRules         policy.L7DataMap
	proxyRuleUpdater     proxyRuleUpdater
}

// proxyRuleUpdater updates L7 proxy rules per endpoint.
//
// Note: Implementations must not take the IPcache lock, as the usage of this
// interface is within the endpoint regeneration critical section.
type proxyRuleUpdater interface {
	// UpdateAllowed updates the rules in the DNS proxy with newRules for the
	// endpointID and destPort.
	UpdateAllowed(endpointID uint64, destPort uint16, newRules policy.L7DataMap) error
}

// setRules replaces old l7 rules of a redirect with new ones.
// TODO: Get rid of the duplication between 'currentRules' and 'r.rules'
func (dr *dnsRedirect) setRules(wg *completion.WaitGroup, newRules policy.L7DataMap) error {
	log.WithFields(logrus.Fields{
		"newRules":           newRules,
		logfields.EndpointID: dr.redirect.endpointID,
	}).Debug("DNS Proxy updating matchNames in allowed list during UpdateRules")
	if err := dr.proxyRuleUpdater.UpdateAllowed(dr.redirect.endpointID, dr.redirect.dstPort, newRules); err != nil {
		return err
	}
	dr.currentRules = copyRules(dr.redirect.rules)

	return nil
}

// UpdateRules atomically replaces the proxy rules in effect for this redirect.
// It is not aware of revision number and doesn't account for out-of-order
// calls to UpdateRules or the returned RevertFunc.
func (dr *dnsRedirect) UpdateRules(wg *completion.WaitGroup) (revert.RevertFunc, error) {
	oldRules := dr.currentRules
	err := dr.setRules(wg, dr.redirect.rules)
	revertFunc := func() error {
		return dr.setRules(nil, oldRules)
	}
	return revertFunc, err
}

// Close the redirect.
func (dr *dnsRedirect) Close(wg *completion.WaitGroup) (revert.FinalizeFunc, revert.RevertFunc) {
	return func() {
		dr.proxyRuleUpdater.UpdateAllowed(dr.redirect.endpointID, dr.redirect.dstPort, nil)
		dr.redirect.localEndpoint.OnDNSPolicyUpdateLocked(nil)
		dr.currentRules = nil
	}, nil
}

// creatednsRedirect creates a redirect to the dns proxy. The redirect structure passed
// in is safe to access for reading and writing.
func createDNSRedirect(r *Redirect, endpointInfoRegistry logger.EndpointInfoRegistry) (RedirectImplementation, error) {
	dr := &dnsRedirect{
		redirect:             r,
		endpointInfoRegistry: endpointInfoRegistry,
		proxyRuleUpdater:     DefaultDNSProxy,
	}

	log.WithFields(logrus.Fields{
		"dnsRedirect": dr,
	}).Debug("Creating DNS Proxy redirect")

	return dr, dr.setRules(nil, r.rules)
}

func copyRules(rules policy.L7DataMap) policy.L7DataMap {
	currentRules := policy.L7DataMap{}
	for key, val := range rules {
		currentRules[key] = val
	}
	return currentRules
}
