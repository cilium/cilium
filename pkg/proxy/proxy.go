// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxy

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/endpoint"
	"github.com/cilium/cilium/pkg/proxy/proxyports"
	"github.com/cilium/cilium/pkg/proxy/types"
	"github.com/cilium/cilium/pkg/revert"
	"github.com/cilium/cilium/pkg/time"
)

// field names used while logging
const (
	fieldProxyRedirectID = "id"

	// redirectCreationAttempts is the number of attempts to create a redirect
	redirectCreationAttempts = 5
)

// Proxy maintains state about redirects
type Proxy struct {
	// mutex is the lock required when modifying any proxy datastructure
	mutex lock.RWMutex

	logger *slog.Logger

	localNodeStore *node.LocalNodeStore

	// redirects is the map of all redirect configurations indexed by
	// the redirect identifier. Redirects may be implemented by different
	// proxies.
	redirects map[string]RedirectImplementation

	envoyIntegration *envoyProxyIntegration
	dnsIntegration   *dnsProxyIntegration

	// proxyPorts manages proxy port allocation
	proxyPorts *proxyports.ProxyPorts
}

func createProxy(
	logger *slog.Logger,
	localNodeStore *node.LocalNodeStore,
	proxyPorts *proxyports.ProxyPorts,
	envoyIntegration *envoyProxyIntegration,
	dnsIntegration *dnsProxyIntegration,
) *Proxy {
	return &Proxy{
		logger:           logger,
		localNodeStore:   localNodeStore,
		redirects:        make(map[string]RedirectImplementation),
		envoyIntegration: envoyIntegration,
		dnsIntegration:   dnsIntegration,
		proxyPorts:       proxyPorts,
	}
}

func (p *Proxy) ReinstallRoutingRules(ctx context.Context, mtu int) error {
	ln, err := p.localNodeStore.Get(ctx)
	if err != nil {
		return fmt.Errorf("failed to retrieve local node: %w", err)
	}
	return ReinstallRoutingRules(p.logger, ln, mtu)
}

func (p *Proxy) GetListenerProxyPort(listener string) uint16 {
	proxyPort, _, _ := p.proxyPorts.GetProxyPort(listener)
	return proxyPort
}

// CreateOrUpdateRedirect creates or updates a L4 redirect with corresponding
// proxy configuration. This will allocate a proxy port as required and launch
// a proxy instance. If the redirect is already in place, only the rules will be
// updated.
// The proxy listening port is returned, but proxy configuration on that port
// may still be ongoing asynchronously. Caller should wait for successful completion
// on 'wg' before assuming the returned proxy port is listening.
// Caller must call exactly one of the returned functions:
// - finalizeFunc to make the changes stick, or
// - revertFunc to cancel the changes.
// Called with 'localEndpoint' locked for reading!
func (p *Proxy) CreateOrUpdateRedirect(
	ctx context.Context, l4 policy.ProxyPolicy, id string, epID uint16, wg *completion.WaitGroup,
) (
	uint16, error, revert.RevertFunc,
) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// Check for existing redirect and try to update it if possible. Otherwise, it gets removed before re-creation.
	if existingImpl, ok := p.redirects[id]; ok {
		existingRedirect := existingImpl.GetRedirect()
		// Only consider configured (but not necessarily acked) proxy ports for update
		if p.proxyPorts.HasProxyType(existingRedirect.proxyPort, types.ProxyType(l4.GetL7Parser())) {
			// (DNS) proxy policy is updated in finalize function
			revert, err := existingImpl.UpdateRules(l4.GetPerSelectorPolicies())
			if err != nil {
				return 0, fmt.Errorf("unable to update existing redirect: %w", err), nil
			}

			p.logger.Debug("updated existing proxy instance",
				fieldProxyRedirectID, id,
				logfields.Listener, l4.GetListener(),
				logfields.L7Parser, l4.GetL7Parser(),
				logfields.Object, logfields.Repr(existingRedirect),
				logfields.ProxyType, existingRedirect.proxyPort.ProxyType)

			// Must return the proxy port when successful
			return existingRedirect.proxyPort.ProxyPort, nil, revert
		}

		// Stale or incompatible redirects get removed before a new one is created below
		p.removeRedirect(id)
	}

	// Create a new redirect
	return p.createNewRedirect(ctx, l4, id, epID, wg)
}

func proxyTypeNotFoundError(proxyType types.ProxyType, listener string, ingress bool) error {
	dir := "egress"
	if ingress {
		dir = "ingress"
	}
	return fmt.Errorf("unrecognized %s proxy type for %s: %s", dir, listener, proxyType)
}

func (p *Proxy) UpdateSDP(rules map[identity.NumericIdentity]policy.SelectorPolicy) {
	p.dnsIntegration.sdpPolicyUpdater.UpdatePolicyRules(rules, true)
}

func (p *Proxy) createNewRedirect(
	ctx context.Context, l4 policy.ProxyPolicy, id string, epID uint16, wg *completion.WaitGroup,
) (
	uint16, error, revert.RevertFunc,
) {
	// FindByTypeWithReference takes a reference on the proxy port which must be eventually released
	ppName, pp := p.proxyPorts.FindByTypeWithReference(types.ProxyType(l4.GetL7Parser()), l4.GetListener(), l4.GetIngress())
	if pp == nil {
		return 0, proxyTypeNotFoundError(types.ProxyType(l4.GetL7Parser()), l4.GetListener(), l4.GetIngress()), nil
	}

	redirect := initRedirect(p.logger, epID, ppName, pp, l4.GetPort(), l4.GetProtocol())

	scopedLog := p.logger.With(
		fieldProxyRedirectID, id,
		logfields.Listener, l4.GetListener(),
		logfields.L7Parser, l4.GetL7Parser(),
		logfields.PortName, ppName)

	// try first with the previous port, if any
	p.proxyPorts.Restore(pp)

	// Callback for Envoy ACK/NACK handling for the redirect.
	// If we get a non-nil 'err' Envoy has NACKed the listener update, and the whole (endpoint)
	// regeneration will also be reverted. Revert can happen for other reasons as well (such as
	// bpf datapath compilation failure), and we do not want to churn proxy ports in that case.
	// Not called for DNS redirects.
	// This callback is called before the finalize or revert function is called.
	proxyCallback := func(err error) {
		if err == nil {
			// Enable datapath redirection for the proxy port if proxy creation
			// was successful, even if the overall (endpoint) regeneration
			// fails. This way there is less churn on the proxy port allocation
			// and datapath. Endpoint policy will no redirect to the new proxy
			// implementation if regeneration fails.
			err = p.proxyPorts.AckProxyPort(ctx, ppName, pp)
			if err != nil {
				scopedLog.Error("Datapath proxy redirection cannot be enabled, L7 proxy may be bypassed", logfields.Error, err)
			}
		} else {
			// Release proxy port if NACK was received. Do not release a port that has
			// already been successfully acknowledged or that it statically configured.
			p.proxyPorts.ResetUnacknowledged(pp)
		}
	}

	var impl RedirectImplementation
	var err error
	for nRetry := range redirectCreationAttempts {
		if err != nil {
			// an error occurred and we are retrying
			scopedLog.Warn("Unable to create proxy, retrying",
				logfields.ProxyPort, pp.ProxyPort,
				logfields.Error, err)
		}

		err = p.proxyPorts.AllocatePort(pp, nRetry > 0)
		if err != nil {
			err = fmt.Errorf("failed to allocate port: %w", err)
			break
		}

		impl, err = p.createRedirectImpl(redirect, l4, wg, proxyCallback)
		if err == nil {
			break
		}
	}

	if err != nil {
		// an error occurred, and we have no more retries
		scopedLog.Error("Unable to create proxy",
			logfields.ProxyPort, pp.ProxyPort,
			logfields.Error, err)

		p.proxyPorts.ReleaseProxyPort(ppName)
		return 0, fmt.Errorf("failed to create redirect implementation: %w", err), nil
	}

	// Set the rules on the new redirect. Returned revert function not used, removing the rules
	// is explicitly handled by the revertFunc below by calling redirect.implementation.Close()
	_, err = impl.UpdateRules(l4.GetPerSelectorPolicies())
	if err != nil {
		return 0, fmt.Errorf("unable to set rules on redirect: %w", err), nil
	}

	scopedLog.Info("Created new proxy instance",
		logfields.Object, logfields.Repr(redirect),
		logfields.ProxyPort, pp.ProxyPort)

	p.redirects[id] = impl
	p.updateRedirectMetrics()

	revertFunc := func() error {
		// Undo what we have done above.
		p.mutex.Lock()
		delete(p.redirects, id)
		p.updateRedirectMetrics()
		p.proxyPorts.ReleaseProxyPort(ppName)
		p.mutex.Unlock()
		impl.Close()
		return nil
	}

	// Must return the proxy port when successful
	return pp.ProxyPort, nil, revertFunc
}

func (p *Proxy) createRedirectImpl(redir Redirect, l4 policy.ProxyPolicy, wg *completion.WaitGroup, cb func(err error)) (impl RedirectImplementation, err error) {
	switch l4.GetL7Parser() {
	case policy.ParserTypeDNS:
		// 'cb' not called for DNS redirects, which have a static proxy port
		r, err := p.dnsIntegration.createRedirect(redir)
		p.logger.Debug("Creating DNS Proxy redirect", logfields.DNSRedirect, r)
		return r, err
	default:
		r, err := p.envoyIntegration.createRedirect(redir, wg, cb)
		p.logger.Debug("Creating Envoy Proxy redirect", logfields.EnvoyRedirect, r)
		return r, err
	}
}

// RemoveRedirect removes an existing redirect that has been successfully created earlier.
// Called with 'localEndpoint' passed to 'CreateOrUpdateRedirect' locked for writing!
func (p *Proxy) RemoveRedirect(id string) {
	p.mutex.Lock()
	defer func() {
		p.updateRedirectMetrics()
		p.mutex.Unlock()
	}()
	p.removeRedirect(id)
}

// removeRedirect removes an existing redirect. p.mutex must be held
func (p *Proxy) removeRedirect(id string) {
	p.logger.Debug("Removing proxy redirect", fieldProxyRedirectID, id)

	impl, ok := p.redirects[id]
	if !ok {
		return
	}
	r := impl.GetRedirect()
	delete(p.redirects, id)

	impl.Close()

	// Delay the release and reuse of the port number so it is guaranteed to be
	// safe to listen on the port again.
	proxyPort := r.proxyPort.ProxyPort
	listenerName := r.name

	err := p.proxyPorts.ReleaseProxyPort(listenerName)
	if err != nil {
		r.logger.Warn("Releasing proxy port failed",
			fieldProxyRedirectID, id,
			logfields.ProxyPort, proxyPort,
			logfields.Error, err)
	}
}

func (p *Proxy) UpdateNetworkPolicy(ep endpoint.EndpointUpdater, policy *policy.L4Policy, ingressPolicyEnforced, egressPolicyEnforced bool, wg *completion.WaitGroup) (error, func() error) {
	return p.envoyIntegration.UpdateNetworkPolicy(ep, policy, ingressPolicyEnforced, egressPolicyEnforced, wg)
}

func (p *Proxy) UseCurrentNetworkPolicy(ep endpoint.EndpointUpdater, policy *policy.L4Policy, wg *completion.WaitGroup) {
	p.envoyIntegration.UseCurrentNetworkPolicy(ep, policy, wg)
}

func (p *Proxy) RemoveNetworkPolicy(ep endpoint.EndpointInfoSource) {
	p.envoyIntegration.RemoveNetworkPolicy(ep)
}

// ChangeLogLevel changes proxy log level to correspond to the logrus log level 'level'.
func (p *Proxy) ChangeLogLevel(level slog.Level) {
	if err := p.envoyIntegration.changeLogLevel(level); err != nil {
		p.logger.Debug("failed to change log level in Envoy proxy", logfields.Error, err)
	}

	if err := p.dnsIntegration.changeLogLevel(level); err != nil {
		p.logger.Debug("failed to change log level in DNS proxy", logfields.Error, err)
	}
}

// GetStatusModel returns the proxy status as API model
func (p *Proxy) GetStatusModel() *models.ProxyStatus {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	rangeMin, rangeMax, nPorts := p.proxyPorts.GetStatusInfo()

	ctx, cancelCtx := context.WithTimeout(context.Background(), time.Second)
	defer cancelCtx()

	result := &models.ProxyStatus{
		IP:             p.getProxyIP(ctx),
		PortRange:      fmt.Sprintf("%d-%d", rangeMin, rangeMax),
		TotalPorts:     int64(nPorts),
		TotalRedirects: int64(len(p.redirects)),
	}

	for name, impl := range p.redirects {
		redirect := impl.GetRedirect()
		result.Redirects = append(result.Redirects, &models.ProxyRedirect{
			Name:      name,
			Proxy:     redirect.name,
			ProxyPort: int64(p.proxyPorts.GetRulesPort(redirect.proxyPort)),
		})
	}
	result.EnvoyDeploymentMode = "embedded"
	if option.Config.ExternalEnvoyProxy {
		result.EnvoyDeploymentMode = "external"
	}
	return result
}

func (p *Proxy) getProxyIP(ctx context.Context) string {
	ln, err := p.localNodeStore.Get(ctx)
	if err != nil {
		return "n/a"
	}

	localNodeIP := ln.GetCiliumInternalIP(false)
	if localNodeIP == nil {
		return "n/a"
	}

	return localNodeIP.String()
}

// updateRedirectMetrics updates the redirect metrics per application protocol
// in Prometheus. Lock needs to be held to call this function.
func (p *Proxy) updateRedirectMetrics() {
	result := map[string]int{}
	for _, impl := range p.redirects {
		redirect := impl.GetRedirect()
		result[string(redirect.proxyPort.ProxyType)]++
	}
	for proto, count := range result {
		metrics.ProxyRedirects.WithLabelValues(proto).Set(float64(count))
	}
}
