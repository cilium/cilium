// Copyright 2016-2020 Authors of Cilium
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

package proxy

import (
	"fmt"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/logger"
	"github.com/cilium/cilium/pkg/rand"
	"github.com/cilium/cilium/pkg/revert"

	"github.com/sirupsen/logrus"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "proxy")
)

// field names used while logging
const (
	fieldProxyRedirectID = "id"

	// portReuseDelay is the delay until a port is being reused
	portReuseDelay = 5 * time.Minute

	// redirectCreationAttempts is the number of attempts to create a redirect
	redirectCreationAttempts = 5
)

type DatapathUpdater interface {
	InstallProxyRules(proxyPort uint16, ingress bool, name string) error
	SupportsOriginalSourceAddr() bool
}

type ProxyPort struct {
	// Listener name (immutable)
	name string
	// isStatic is true when the listener on the proxy port is incapable
	// of stopping and/or being reconfigured with a new proxy port once it has been
	// first started. Set 'true' by SetProxyPort(), which is only called for
	// static listeners (currently only DNS proxy).
	isStatic bool
	// parser type this port applies to (immutable)
	parserType policy.L7ParserType
	// 'true' for ingress, 'false' for egress (immutable)
	ingress bool
	// ProxyPort is the desired proxy listening port number.
	proxyPort uint16
	// nRedirects is the number of redirects using this proxy port
	nRedirects int
	// Configured is true when the proxy is (being) configured, but not necessarily
	// acknowledged yet. This is reset to false when the underlying proxy listener
	// is removed.
	configured bool
	// rulesPort congains the proxy port value configured to the datapath rules and
	// is non-zero when a proxy has been successfully created and the
	// datapath rules have been created.
	rulesPort uint16
}

// Proxy maintains state about redirects
type Proxy struct {
	*envoy.XDSServer

	// stateDir is the path of the directory where the state of L7 proxies is
	// stored.
	stateDir string

	// mutex is the lock required when modifying any proxy datastructure
	mutex lock.RWMutex

	// rangeMin is the minimum port used for proxy port allocation
	rangeMin uint16

	// rangeMax is the maximum port used for proxy port allocation.
	// If port is unspecified, the proxy will automatically allocate
	// ports out of the rangeMin-rangeMax range.
	rangeMax uint16

	// redirects is the map of all redirect configurations indexed by
	// the redirect identifier. Redirects may be implemented by different
	// proxies.
	redirects map[string]*Redirect

	// Datapath updater for installing and removing proxy rules for a single
	// proxy port
	datapathUpdater DatapathUpdater
}

// StartProxySupport starts the servers to support L7 proxies: xDS GRPC server
// and access log server.
func StartProxySupport(minPort uint16, maxPort uint16, stateDir string,
	accessLogNotifier logger.LogRecordNotifier, accessLogMetadata []string,
	datapathUpdater DatapathUpdater, mgr EndpointLookup) *Proxy {
	endpointManager = mgr
	xdsServer := envoy.StartXDSServer(stateDir)

	if accessLogNotifier != nil {
		logger.SetNotifier(accessLogNotifier)
	}

	if len(accessLogMetadata) > 0 {
		logger.SetMetadata(accessLogMetadata)
	}

	envoy.StartAccessLogServer(stateDir, xdsServer, DefaultEndpointInfoRegistry)

	return &Proxy{
		XDSServer:       xdsServer,
		stateDir:        stateDir,
		rangeMin:        minPort,
		rangeMax:        maxPort,
		redirects:       make(map[string]*Redirect),
		datapathUpdater: datapathUpdater,
	}
}

var (
	// proxyPortsMutex protects access to allocatedPorts, portRandomized, and proxyPorts
	proxyPortsMutex lock.Mutex

	// allocatedPorts is the map of all allocated proxy ports
	allocatedPorts = make(map[uint16]struct{})

	portRandomizer = rand.NewSafeRand(time.Now().UnixNano())

	// proxyPorts is a slice of all supported proxy ports
	// The number and order of entries are fixed, and the fields
	// initialized here are immutable.
	proxyPorts = []ProxyPort{
		{
			parserType: policy.ParserTypeHTTP,
			ingress:    false,
			name:       "cilium-http-egress",
		},
		{
			parserType: policy.ParserTypeHTTP,
			ingress:    true,
			name:       "cilium-http-ingress",
		},
		{
			parserType: policy.ParserTypeDNS,
			ingress:    false,
			name:       "cilium-dns-egress",
		},
		{
			parserType: policy.ParserTypeNone,
			ingress:    false,
			name:       "cilium-proxylib-egress",
		},
		{
			parserType: policy.ParserTypeNone,
			ingress:    true,
			name:       "cilium-proxylib-ingress",
		},
	}
)

// Called with proxyPortsMutex held!
func isPortAvailable(openLocalPorts map[uint16]struct{}, port uint16) bool {
	if _, used := allocatedPorts[port]; used {
		return false // port already used
	}
	if port == 0 {
		return false // zero port requested
	}
	// Check that the port is not already open
	if _, alreadyOpen := openLocalPorts[port]; alreadyOpen {
		return false // port already open
	}

	return true
}

// Called with proxyPortsMutex held!
func allocatePort(port, min, max uint16) (uint16, error) {
	// Get a snapshot of the TCP and UDP ports already open locally.
	openLocalPorts := readOpenLocalPorts(append(procNetTCPFiles, procNetUDPFiles...))

	if isPortAvailable(openLocalPorts, port) {
		return port, nil
	}

	// TODO: Maybe not create a large permutation each time?
	for _, r := range portRandomizer.Perm(int(max - min + 1)) {
		resPort := uint16(r) + min

		if isPortAvailable(openLocalPorts, resPort) {
			return resPort, nil
		}
	}

	return 0, fmt.Errorf("no available proxy ports")
}

// Called with proxyPortsMutex held!
func (pp *ProxyPort) reservePort() {
	if !pp.configured {
		allocatedPorts[pp.proxyPort] = struct{}{}
		pp.configured = true
	}
}

// Called with proxyPortsMutex held!
func findProxyPort(name string) *ProxyPort {
	for i := range proxyPorts {
		if proxyPorts[i].name == name {
			return &proxyPorts[i]
		}
	}
	return nil
}

// AckProxyPort() marks the proxy of the given type as successfully
// created and creates or updates the datapath rules accordingly.
func (p *Proxy) AckProxyPort(l7Type policy.L7ParserType, ingress bool) error {
	proxyPortsMutex.Lock()
	defer proxyPortsMutex.Unlock()
	pp := getProxyPort(l7Type, ingress)
	if pp == nil {
		return proxyNotFoundError(l7Type, ingress)
	}
	return p.ackProxyPort(pp) // creates datapath rules, increases the reference count
}

// ackProxyPort() marks the proxy as successfully created and creates or updates the datapath rules
// accordingly. Each call must eventually be paired with a corresponding releaseProxyPort() call
// to keep the use count up-to-date.
// Must be called with proxyPortsMutex held!
func (p *Proxy) ackProxyPort(pp *ProxyPort) error {
	if pp.nRedirects == 0 {
		scopedLog := log.WithField("proxy port name", pp.name)
		scopedLog.Debugf("Considering updating proxy port rules for %s:%d (old: %d)", pp.name, pp.proxyPort, pp.rulesPort)

		// Datapath rules are added only after we know the proxy configuration
		// with the actual port number has succeeded. Deletion of the rules
		// is delayed after the redirects have been removed to the point
		// when we know the port number changes. This is to reduce the churn
		// in the datapath, but means that the datapath rules may exist even
		// if the proxy is not currently configured.

		// Add new rules, if needed
		if pp.rulesPort != pp.proxyPort {
			// Add rules for the new port
			// This should always succeed if we have managed to start-up properly
			scopedLog.Infof("Adding new proxy port rules for %s:%d", pp.name, pp.proxyPort)
			err := p.datapathUpdater.InstallProxyRules(pp.proxyPort, pp.ingress, pp.name)
			if err != nil {
				return fmt.Errorf("Cannot install proxy rules for %s: %s", pp.name, err)
			}
			pp.rulesPort = pp.proxyPort
		}
	}
	pp.nRedirects++
	return nil
}

// releaseProxyPort() decreases the use count and frees the port if no users remain
// Must be called with proxyPortsMutex held!
func (p *Proxy) releaseProxyPort(name string) error {
	pp := findProxyPort(name)
	if pp == nil {
		return fmt.Errorf("Can't find proxy port %s", name)
	}
	if pp.nRedirects == 0 {
		return fmt.Errorf("Can't release proxy port: proxy %s on %d has refcount 0", name, pp.proxyPort)
	}

	pp.nRedirects--
	if pp.nRedirects == 0 {
		if pp.isStatic {
			return fmt.Errorf("Can't release proxy port: proxy %s on %d has a static listener", name, pp.proxyPort)
		}
		delete(allocatedPorts, pp.proxyPort)
		// Force new port allocation the next time this ProxyPort is used.
		pp.configured = false
		// Leave the datapath rules behind on the hope that they get reused later.
		// This becomes possible when we are able to keep the proxy listeners
		// configured also when there are no redirects.
		log.WithField(fieldProxyRedirectID, name).Debugf("Delayed release of proxy port %d", pp.proxyPort)
	}

	return nil
}

// mutex need not be held, as this only refers to immutable members in the static slice.
func getProxyPort(l7Type policy.L7ParserType, ingress bool) *ProxyPort {
	portType := l7Type
	switch l7Type {
	case policy.ParserTypeDNS, policy.ParserTypeHTTP:
	default:
		// "Unknown" parsers are assumed to be Proxylib (TCP) parsers, which
		// is registered with an empty string.
		portType = ""
	}
	// proxyPorts is small enough to not bother indexing it.
	for i := range proxyPorts {
		if proxyPorts[i].parserType == portType && proxyPorts[i].ingress == ingress {
			return &proxyPorts[i]
		}
	}
	return nil
}

func proxyNotFoundError(l7Type policy.L7ParserType, ingress bool) error {
	dir := "egress"
	if ingress {
		dir = "ingress"
	}
	return fmt.Errorf("unrecognized %s proxy type: %s", dir, l7Type)
}

// Exported API

// GetProxyPort() returns the fixed listen port for a proxy, if any.
func GetProxyPort(l7Type policy.L7ParserType, ingress bool) (uint16, string, error) {
	// Accessing pp.proxyPort requires the lock
	proxyPortsMutex.Lock()
	defer proxyPortsMutex.Unlock()
	pp := getProxyPort(l7Type, ingress)
	if pp != nil {
		return pp.proxyPort, pp.name, nil
	}
	return 0, "", proxyNotFoundError(l7Type, ingress)
}

// SetProxyPort() marks the proxy 'name' as successfully created with proxy port 'port'.
// Another call to AckProxyPort(name) is needed to update the datapath rules accordingly.
// This should only be called for proxies that have a static listener that is already listening on
// 'port'. May only be called once per proxy.
func (p *Proxy) SetProxyPort(name string, port uint16) error {
	proxyPortsMutex.Lock()
	defer proxyPortsMutex.Unlock()
	pp := findProxyPort(name)
	if pp == nil {
		return fmt.Errorf("Can't find proxy port %s", name)
	}
	if pp.nRedirects > 0 {
		return fmt.Errorf("Can't set proxy port to %d: proxy %s is already configured on %d", port, name, pp.proxyPort)
	}
	pp.proxyPort = port
	pp.isStatic = true // prevents release of the proxy port
	pp.reservePort()   // marks 'port' as reserved, 'pp' as configured
	return nil
}

// ReinstallRules is called by daemon reconfiguration to re-install proxy ports rules that
// were removed during the removal of all Cilium rules.
func (p *Proxy) ReinstallRules() {
	proxyPortsMutex.Lock()
	defer proxyPortsMutex.Unlock()
	for _, pp := range proxyPorts {
		if pp.rulesPort > 0 {
			// This should always succeed if we have managed to start-up properly
			err := p.datapathUpdater.InstallProxyRules(pp.rulesPort, pp.ingress, pp.name)
			if err != nil {
				log.WithError(err).Errorf("Can't install proxy rules for %s", pp.name)
			}
		}
	}
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
// Called with 'localEndpoint' locked!
func (p *Proxy) CreateOrUpdateRedirect(l4 policy.ProxyPolicy, id string, localEndpoint logger.EndpointUpdater,
	wg *completion.WaitGroup) (proxyPort uint16, err error, finalizeFunc revert.FinalizeFunc, revertFunc revert.RevertFunc) {

	p.mutex.Lock()
	defer func() {
		p.updateRedirectMetrics()
		p.mutex.Unlock()
		if err == nil && proxyPort == 0 {
			panic("Trying to configure zero proxy port")
		}
	}()

	scopedLog := log.WithField(fieldProxyRedirectID, id)

	var revertStack revert.RevertStack
	revertFunc = revertStack.Revert

	if redir, ok := p.redirects[id]; ok {
		redir.mutex.Lock()

		if redir.listener.parserType == l4.GetL7Parser() {
			updateRevertFunc := redir.updateRules(l4)
			revertStack.Push(updateRevertFunc)
			var implUpdateRevertFunc revert.RevertFunc
			implUpdateRevertFunc, err = redir.implementation.UpdateRules(wg)
			if err != nil {
				redir.mutex.Unlock()
				err = fmt.Errorf("unable to update existing redirect: %s", err)
				return 0, err, nil, nil
			}
			revertStack.Push(implUpdateRevertFunc)

			scopedLog.WithField(logfields.Object, logfields.Repr(redir)).
				Debug("updated existing ", l4.GetL7Parser(), " proxy instance")

			redir.mutex.Unlock()

			// Must return the proxy port when successful
			proxyPort = redir.listener.proxyPort
			return
		}

		var removeRevertFunc revert.RevertFunc
		err, finalizeFunc, removeRevertFunc = p.removeRedirect(id, wg)
		redir.mutex.Unlock()

		if err != nil {
			err = fmt.Errorf("unable to remove old redirect: %s", err)
			return 0, err, nil, nil
		}

		revertStack.Push(removeRevertFunc)
	}

	proxyPortsMutex.Lock()
	defer proxyPortsMutex.Unlock()
	pp := getProxyPort(l4.GetL7Parser(), l4.GetIngress())
	if pp == nil {
		err = proxyNotFoundError(l4.GetL7Parser(), l4.GetIngress())
		revertFunc()
		return 0, err, nil, nil
	}

	redir := newRedirect(localEndpoint, pp, l4.GetPort())
	redir.updateRules(l4)
	// Rely on create*Redirect to update rules, unlike the update case above.

	for nRetry := 0; nRetry < redirectCreationAttempts; nRetry++ {
		if nRetry > 0 {
			// an error occurred and we can retry
			scopedLog.WithError(err).Warningf("Unable to create %s proxy, retrying", pp.name)
		}

		if !pp.configured {
			// Try allocate (the configured) port, but only if the proxy has not
			// been already configured.
			pp.proxyPort, err = allocatePort(pp.proxyPort, p.rangeMin, p.rangeMax)
			if err != nil {
				revertFunc() // Ignore errors while reverting. This is best-effort.
				return 0, err, nil, nil
			}
		}

		switch l4.GetL7Parser() {
		case policy.ParserTypeDNS:
			redir.implementation, err = createDNSRedirect(redir, dnsConfiguration{}, DefaultEndpointInfoRegistry)

		case policy.ParserTypeHTTP:
			redir.implementation, err = createEnvoyRedirect(redir, p.stateDir, p.XDSServer, p.datapathUpdater.SupportsOriginalSourceAddr(), wg)
		default:
			redir.implementation, err = createEnvoyRedirect(redir, p.stateDir, p.XDSServer, p.datapathUpdater.SupportsOriginalSourceAddr(), wg)
		}

		if err == nil {
			scopedLog.WithField(logfields.Object, logfields.Repr(redir)).
				Debug("Created new ", l4.GetL7Parser(), " proxy instance")
			p.redirects[id] = redir
			// must mark the proxyPort configured while we still hold the lock to prevent racing between
			// two parallel runs
			pp.reservePort()

			revertStack.Push(func() error {
				// Proxy port refcount has not been incremented yet, so it must not be decremented
				// when reverting. Undo what we have done above.
				p.mutex.Lock()
				delete(p.redirects, id)
				p.updateRedirectMetrics()
				p.mutex.Unlock()
				implFinalizeFunc, _ := redir.implementation.Close(wg)
				if implFinalizeFunc != nil {
					implFinalizeFunc()
				}
				return nil
			})

			// Set the proxy port only after an ACK is received.
			removeFinalizeFunc := finalizeFunc
			finalizeFunc = func() {
				if removeFinalizeFunc != nil {
					removeFinalizeFunc()
				}

				proxyPortsMutex.Lock()
				err := p.ackProxyPort(pp)
				proxyPortsMutex.Unlock()
				if err != nil {
					log.WithError(err).Errorf("Datapath proxy redirection cannot be enabled for %s, L7 proxy may be bypassed", pp.name)
				}
			}
			// Must return the proxy port when successful
			proxyPort = pp.proxyPort
			return
		}
	}

	// an error occurred, and we have no more retries
	scopedLog.WithError(err).Error("Unable to create ", l4.GetL7Parser(), " proxy")
	revertFunc() // Ignore errors while reverting. This is best-effort.
	return 0, err, nil, nil
}

// RemoveRedirect removes an existing redirect that has been successfully created earlier.
func (p *Proxy) RemoveRedirect(id string, wg *completion.WaitGroup) (error, revert.FinalizeFunc, revert.RevertFunc) {
	p.mutex.Lock()
	defer func() {
		p.updateRedirectMetrics()
		p.mutex.Unlock()
	}()
	return p.removeRedirect(id, wg)
}

// removeRedirect removes an existing redirect. p.mutex must be held
// p.mutex must NOT be held when the returned revert function is called!
// proxyPortsMutex must NOT be held when the returned finalize function is called!
func (p *Proxy) removeRedirect(id string, wg *completion.WaitGroup) (err error, finalizeFunc revert.FinalizeFunc, revertFunc revert.RevertFunc) {
	log.WithField(fieldProxyRedirectID, id).
		Debug("Removing proxy redirect")

	r, ok := p.redirects[id]
	if !ok {
		return fmt.Errorf("unable to find redirect %s", id), nil, nil
	}
	delete(p.redirects, id)

	implFinalizeFunc, implRevertFunc := r.implementation.Close(wg)

	// Delay the release and reuse of the port number so it is guaranteed to be
	// safe to listen on the port again. This can't be reverted, so do it in a
	// FinalizeFunc.
	proxyPort := r.listener.proxyPort
	listenerName := r.listener.name

	finalizeFunc = func() {
		// break GC loop (implementation may point back to 'r')
		r.implementation = nil

		if implFinalizeFunc != nil {
			implFinalizeFunc()
		}

		go func() {
			time.Sleep(portReuseDelay)

			proxyPortsMutex.Lock()
			err := p.releaseProxyPort(listenerName)
			proxyPortsMutex.Unlock()
			if err != nil {
				log.WithField(fieldProxyRedirectID, id).WithError(err).Warningf("Releasing proxy port %d failed", proxyPort)
			}
		}()
	}

	revertFunc = func() error {
		if implRevertFunc != nil {
			return implRevertFunc()
		}

		p.mutex.Lock()
		p.redirects[id] = r
		p.mutex.Unlock()

		return nil
	}

	return
}

// ChangeLogLevel changes proxy log level to correspond to the logrus log level 'level'.
func ChangeLogLevel(level logrus.Level) {
	if envoyProxy != nil {
		envoyProxy.ChangeLogLevel(level)
	}
}

// GetStatusModel returns the proxy status as API model
func (p *Proxy) GetStatusModel() *models.ProxyStatus {
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	proxyPortsMutex.Lock()
	defer proxyPortsMutex.Unlock()

	result := &models.ProxyStatus{
		IP:             node.GetInternalIPv4Router().String(),
		PortRange:      fmt.Sprintf("%d-%d", p.rangeMin, p.rangeMax),
		TotalRedirects: int64(len(p.redirects)),
	}
	for _, pp := range proxyPorts {
		if pp.nRedirects > 0 {
			result.TotalPorts++
		}
	}
	for name, redirect := range p.redirects {
		result.Redirects = append(result.Redirects, &models.ProxyRedirect{
			Name:      name,
			Proxy:     redirect.listener.name,
			ProxyPort: int64(redirect.listener.rulesPort),
		})
	}
	return result
}

// updateRedirectMetrics updates the redirect metrics per application protocol
// in Prometheus. Lock needs to be held to call this function.
func (p *Proxy) updateRedirectMetrics() {
	result := map[string]int{}
	for _, redirect := range p.redirects {
		result[string(redirect.listener.parserType)]++
	}
	for proto, count := range result {
		metrics.ProxyRedirects.WithLabelValues(proto).Set(float64(count))
	}
}

// UpdateNetworkPolicy must update the redirect configuration of an endpoint in the proxy
func (p *Proxy) UpdateNetworkPolicy(ep logger.EndpointUpdater, policy *policy.L4Policy, ingressPolicyEnforced, egressPolicyEnforced bool, wg *completion.WaitGroup) (error, func() error) {
	return p.XDSServer.UpdateNetworkPolicy(ep, policy, ingressPolicyEnforced, egressPolicyEnforced, wg)
}

// UseCurrentNetworkPolicy inserts a Completion to the WaitGroup if the current network policy has not yet been acked
func (p *Proxy) UseCurrentNetworkPolicy(ep logger.EndpointUpdater, policy *policy.L4Policy, wg *completion.WaitGroup) {
	p.XDSServer.UseCurrentNetworkPolicy(ep, policy, wg)
}
