// Copyright 2016-2018 Authors of Cilium
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
	"math/rand"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/logger"
	"github.com/cilium/cilium/pkg/revert"

	"github.com/sirupsen/logrus"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "proxy")
)

// field names used while logging
const (
	fieldMarker          = "marker"
	fieldSocket          = "socket"
	fieldFd              = "fd"
	fieldProxyRedirectID = "id"

	// portReuseDelay is the delay until a port is being reused
	portReuseDelay = 5 * time.Minute

	// listenerCreationAttempts is the number of attempts to create a redirect
	listenerCreationAttempts = 5
)

type DatapathUpdater interface {
	InstallProxyRules(proxyPort uint16, ingress bool, name string) error
	RemoveProxyRules(proxyPort uint16, ingress bool, name string) error
	SupportsOriginalSourceAddr() bool
}

type ProxyPort struct {
	// Listener name (immutable)
	name string
	// parser type this port applies to (immutable)
	parserType policy.L7ParserType
	// 'true' for ingress, 'false' for egress (immutable)
	ingress bool
	// redirectType encodes the parser type and direction as one type (immutable)
	redirectType policy.RedirectType
	// createListener is called when the listener should be created (immutable)
	createListener func(*Proxy, *ProxyPort, *completion.WaitGroup) (error, revert.RevertFunc)
	// ProxyPort is the desired proxy listening port number.
	proxyPort uint16
	// Configured is true when the proxy is (being) configured, but not necessarily
	// acknowledged yet. This is reset to false when the underlying proxy listener
	// is removed.
	configured bool
	// acknowledged is true when a listener has been acknowledged. Reset to false
	// when the listener is removed.
	acknowledged bool
	// rulesPort is the proxy port value configured to the datapath rules and
	// is non-zero when a proxy has been successfully created and the
	// datapath rules have been created.
	rulesPort uint16
}

// Proxy maintains state about redirects
type Proxy struct {
	*envoy.XDSServer

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

	// mask of all listeners started so far,
	runningProxies policy.RedirectType
}

// StartListeners makes sure the proxies and listeners for the given
// mask of redirect types are configured.
func (p *Proxy) StartListeners(rTypes policy.RedirectType, wg *completion.WaitGroup) (error, revert.FinalizeFunc, revert.RevertFunc) {
	rTypes &^= p.runningProxies // minus the proxies already running

	if rTypes != 0 {
		p.mutex.Lock()
		defer p.mutex.Unlock()

		// Check that Envoy is started when needed
		if rTypes&^policy.RedirectTypeAgentMask != 0 {
			p.StartEnvoy()
		}

		var revertStack revert.RevertStack
		var finalizeList revert.FinalizeList

		proxyPortsMutex.Lock()
		defer proxyPortsMutex.Unlock()

		for i := range proxyPorts {
			pp := &proxyPorts[i]
			rType := pp.redirectType
			name := pp.name
			if rTypes&rType != 0 {
				err, createFinalizeFunc, createRevertFunc := p.createListenerLocked(pp, wg)
				if err != nil {
					revertStack.Revert()
					return fmt.Errorf("Failed to create listener %s: %s", name, err), nil, nil
				}
				finalizeList.Append(createFinalizeFunc)
				finalizeList.Append(func() {
					p.runningProxies |= rType
					log.WithField(fieldProxyRedirectID, name).Debugf("Listener creation ACKed")
				})
				revertStack.Push(createRevertFunc)
			}
		}
		return nil, finalizeList.Finalize, revertStack.Revert
	}
	return nil, nil, nil
}

// StartProxySupport starts the servers to support L7 proxies: xDS GRPC server
// and access log server.
func StartProxySupport(accessLogNotifier logger.LogRecordNotifier, datapathUpdater DatapathUpdater,
	mgr EndpointLookup) *Proxy {
	endpointManager = mgr
	// FIXME: Make the port range configurable.
	minPort := uint16(10000)
	maxPort := uint16(20000)
	stateDir := option.Config.RunDir
	accessLogFile := option.Config.AccessLog
	accessLogMetadata := option.Config.AgentLabels

	xdsServer := envoy.StartXDSServer(stateDir)

	if accessLogFile != "" {
		if err := logger.OpenLogfile(accessLogFile); err != nil {
			log.WithError(err).WithField(logfields.Path, accessLogFile).
				Warn("Cannot open L7 access log")
		}
	}

	if accessLogNotifier != nil {
		logger.SetNotifier(accessLogNotifier)
	}

	if len(accessLogMetadata) > 0 {
		logger.SetMetadata(accessLogMetadata)
	}

	envoy.StartAccessLogServer(stateDir, xdsServer, DefaultEndpointInfoRegistry)

	return &Proxy{
		XDSServer:       xdsServer,
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

	portRandomizer = rand.New(rand.NewSource(time.Now().UnixNano()))

	// proxyPorts is a slice of all supported proxy ports
	// The number and order of entries are fixed, and the fields
	// initialized here are immutable.
	proxyPorts = []ProxyPort{
		{
			parserType:     policy.ParserTypeHTTP,
			ingress:        false,
			name:           "cilium-http-egress",
			redirectType:   policy.RedirectTypeHTTPEgress,
			createListener: createEnvoyListener,
		},
		{
			parserType:     policy.ParserTypeHTTP,
			ingress:        true,
			name:           "cilium-http-ingress",
			redirectType:   policy.RedirectTypeHTTPIngress,
			createListener: createEnvoyListener,
		},
		{
			parserType:     policy.ParserTypeKafka,
			ingress:        false,
			name:           "cilium-kafka-egress",
			redirectType:   policy.RedirectTypeKafkaEgress,
			createListener: createKafkaListener,
		},
		{
			parserType:     policy.ParserTypeKafka,
			ingress:        true,
			name:           "cilium-kafka-ingress",
			redirectType:   policy.RedirectTypeKafkaIngress,
			createListener: createKafkaListener,
		},
		{
			parserType:   policy.ParserTypeDNS,
			ingress:      false,
			name:         "cilium-dns-egress",
			redirectType: policy.RedirectTypeDNSEgress,
		},
		{
			parserType:     policy.ParserTypeNone,
			ingress:        false,
			name:           "cilium-proxylib-egress",
			redirectType:   policy.RedirectTypeProxylibEgress,
			createListener: createEnvoyListener,
		},
		{
			parserType:     policy.ParserTypeNone,
			ingress:        true,
			name:           "cilium-proxylib-ingress",
			redirectType:   policy.RedirectTypeProxylibIngress,
			createListener: createEnvoyListener,
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
	allocatedPorts[pp.proxyPort] = struct{}{}
	pp.configured = true
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

// ackProxyPort() marks the proxy as successfully created and creates or updates the datapath rules
// accordingly.
// Must be called with proxyPortsMutex held!
func (p *Proxy) ackProxyPort(pp *ProxyPort) error {
	if !pp.acknowledged {
		scopedLog := log.WithField("proxy port name", pp.name)
		scopedLog.Debugf("Considering updating proxy port rules for %s:%d (old: %d)", pp.name, pp.proxyPort, pp.rulesPort)

		// Datapath rules are added only after we know the proxy configuration
		// with the actual port number has succeeded. Deletion of the rules
		// is delayed after the redirects have been removed to the point
		// when we know the port number changes. This is to reduce the churn
		// in the datapath, but means that the datapath rules may exist even
		// if the proxy is not currently configured.

		// Remove old rules, if any and for different port
		if pp.rulesPort != 0 && pp.rulesPort != pp.proxyPort && p.datapathUpdater != nil {
			scopedLog.Debugf("Removing old proxy port rules for %s:%d", pp.name, pp.rulesPort)
			p.datapathUpdater.RemoveProxyRules(pp.rulesPort, pp.ingress, pp.name)
			pp.rulesPort = 0
		}
		// Add new rules, if needed
		if pp.rulesPort != pp.proxyPort && p.datapathUpdater != nil {
			// This should always succeed if we have managed to start-up properly
			scopedLog.Debugf("Adding new proxy port rules for %s:%d", pp.name, pp.proxyPort)
			err := p.datapathUpdater.InstallProxyRules(pp.proxyPort, pp.ingress, pp.name)
			if err != nil {
				return fmt.Errorf("Can't install proxy rules for %s: %s", pp.name, err)
			}
		}
		pp.rulesPort = pp.proxyPort
		pp.acknowledged = true
	}
	return nil
}

// mutex need not be held, as this only refers to immutable members in the static slice.
func getProxyPort(l7Type policy.L7ParserType, ingress bool) *ProxyPort {
	portType := l7Type
	switch l7Type {
	case policy.ParserTypeDNS, policy.ParserTypeKafka, policy.ParserTypeHTTP:
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

// SetProxyPort() marks the proxy 'name' as successfully created with proxy port 'port' and creates
// or updates the datapath rules accordingly.
// May only be called once per proxy.
func (p *Proxy) SetProxyPort(name string, port uint16) error {
	proxyPortsMutex.Lock()
	defer proxyPortsMutex.Unlock()
	pp := findProxyPort(name)
	if pp == nil {
		return fmt.Errorf("Can't find proxy port %s", name)
	}
	if pp.configured {
		return fmt.Errorf("Can't set proxy port to %d: proxy %s is already configured on %d", port, name, pp.proxyPort)
	}
	pp.proxyPort = port
	pp.configured = true
	return p.ackProxyPort(pp)
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
				proxyPortsMutex.Unlock()
				panic(fmt.Sprintf("Can't install proxy rules for %s: %s", pp.name, err))
			}
		}
	}
}

// createListenerLocked creates listener for the given ProxyPort. This will allocate
// a proxy port as required. The proxy listening port is returned, but proxy configuration
// on that port may still be ongoing asynchronously. Caller should wait for successful
// completion on 'wg' before assuming the returned proxy port is listening.
func (p *Proxy) createListenerLocked(pp *ProxyPort, wg *completion.WaitGroup) (err error, finalizeFunc revert.FinalizeFunc, revertFunc revert.RevertFunc) {
	defer func() {
		if err == nil && pp.proxyPort == 0 {
			panic("Trying to configure zero proxy port")
		}
	}()

	if pp.acknowledged {
		return
	}

	scopedLog := log.WithField(fieldProxyRedirectID, pp.name)

	if pp.createListener == nil {
		scopedLog.Error("createListener not set")
		return err, nil, nil
	}

	for nRetry := 0; nRetry < listenerCreationAttempts; nRetry++ {
		if nRetry > 0 {
			// an error occurred and we can retry
			scopedLog.WithError(err).Warningf("Unable to create listener, retrying")
		}

		if !pp.configured {
			// Try allocate (the configured) port, but only if the proxy has not
			// been already configured.
			pp.proxyPort, err = allocatePort(pp.proxyPort, p.rangeMin, p.rangeMax)
			if err != nil {
				return err, nil, nil
			}
		}

		err, revertFunc = pp.createListener(p, pp, wg)

		if err == nil {
			scopedLog.Debug("Created new ", pp.parserType, " proxy listener")
			// must mark the proxyPort configured while we still hold the lock to prevent racing between
			// two parallel runs
			pp.reservePort()

			// Set the proxy port only after an ACK is received.
			finalizeFunc = func() {
				proxyPortsMutex.Lock()
				err := p.ackProxyPort(pp)
				proxyPortsMutex.Unlock()
				if err != nil {
					// Finalize functions can't error out. This failure can only
					// happen if there is an internal Cilium logic error regarding
					// installation of iptables rules.
					panic(err)
				}
			}
			return
		}
	}
	// an error occurred, and we have no more retries
	scopedLog.WithError(err).Error("Unable to create ", pp.parserType, " listener")
	return err, nil, nil
}

// CreateOrUpdateRedirect creates or updates a L4 redirect with corresponding
// proxy configuration. This will allocate a proxy port as required and launch
// a proxy instance. If the redirect is already in place, only the rules will be
// updated.
// The proxy listening port is returned, but proxy configuration on that port
// may still be ongoing asynchronously.
func (p *Proxy) CreateOrUpdateRedirect(l4 *policy.L4Filter, id string, localEndpoint logger.EndpointUpdater) (err error, finalizeFunc revert.FinalizeFunc, revertFunc revert.RevertFunc) {

	p.mutex.Lock()
	defer func() {
		p.UpdateRedirectMetrics()
		p.mutex.Unlock()
	}()

	scopedLog := log.WithField(fieldProxyRedirectID, id)

	var revertStack revert.RevertStack
	revertFunc = revertStack.Revert

	var finalizeList revert.FinalizeList
	finalizeFunc = finalizeList.Finalize

	if redir, ok := p.redirects[id]; ok {
		redir.mutex.Lock()

		if redir.listener.parserType == l4.L7Parser {
			if redir.implementation != nil {
				implUpdateRevertFunc := redir.implementation.UpdateRules(l4.L7RulesPerEp)
				revertStack.Push(implUpdateRevertFunc)
			}
			redir.lastUpdated = time.Now()

			scopedLog.WithField(logfields.Object, logfields.Repr(redir)).
				Debug("updated existing ", l4.L7Parser, " proxy instance")
			redir.mutex.Unlock()
			return
		}

		var removeRevertFunc revert.RevertFunc
		var removeFinalizeFunc revert.FinalizeFunc
		err, removeFinalizeFunc, removeRevertFunc = p.removeRedirect(id)
		redir.mutex.Unlock()

		if err != nil {
			err = fmt.Errorf("unable to remove old redirect: %s", err)
			return err, nil, nil
		}

		finalizeList.Append(removeFinalizeFunc)
		revertStack.Push(removeRevertFunc)
	}

	proxyPortsMutex.Lock()
	defer proxyPortsMutex.Unlock()
	pp := getProxyPort(l4.L7Parser, l4.Ingress)
	if pp == nil {
		err = proxyNotFoundError(l4.L7Parser, l4.Ingress)
		revertFunc()
		return err, nil, nil
	}

	redir := newRedirect(localEndpoint, pp, uint16(l4.Port))

	switch l4.L7Parser {
	case policy.ParserTypeDNS:
		redir.implementation, err = createDNSRedirect(redir)
	case policy.ParserTypeKafka:
		redir.implementation, err = createKafkaRedirect(redir, kafkaConfiguration{})
	}

	if err == nil {
		if redir.implementation != nil {
			redir.implementation.UpdateRules(l4.L7RulesPerEp)
		}
		scopedLog.WithField(logfields.Object, logfields.Repr(redir)).
			Debug("Created new ", l4.L7Parser, " proxy instance")
		p.redirects[id] = redir

		revertStack.Push(func() error {
			err, finalize, _ := p.RemoveRedirect(id)
			if err == nil && finalize != nil {
				finalize()
			}
			return err
		})
		return
	}

	// an error occurred, and we have no more retries
	scopedLog.WithError(err).Error("Unable to create ", l4.L7Parser, " proxy")
	revertFunc() // Ignore errors while reverting. This is best-effort.
	return err, nil, nil
}

// RemoveRedirect removes an existing redirect.
func (p *Proxy) RemoveRedirect(id string) (error, revert.FinalizeFunc, revert.RevertFunc) {
	p.mutex.Lock()
	defer func() {
		p.UpdateRedirectMetrics()
		p.mutex.Unlock()
	}()
	return p.removeRedirect(id)
}

// removeRedirect removes an existing redirect. p.mutex must be held
// p.mutex must NOT be held when the returned finalize and revert functions are called!
func (p *Proxy) removeRedirect(id string) (err error, finalizeFunc revert.FinalizeFunc, revertFunc revert.RevertFunc) {
	log.WithField(fieldProxyRedirectID, id).
		Debug("Removing proxy redirect")

	r, ok := p.redirects[id]
	if !ok {
		return fmt.Errorf("unable to find redirect %s", id), nil, nil
	}
	delete(p.redirects, id)

	if r.implementation != nil {
		finalizeFunc = func() {
			r.implementation.Close()
			// break GC loop (implementation may point back to 'r')
			r.implementation = nil
		}
	}

	revertFunc = func() error {
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

	return &models.ProxyStatus{
		IP:        node.GetInternalIPv4().String(),
		PortRange: fmt.Sprintf("%d-%d", p.rangeMin, p.rangeMax),
	}
}

// UpdateRedirectMetrics updates the redirect metrics per application protocol
// in Prometheus. Lock needs to be held to call this function.
func (p *Proxy) UpdateRedirectMetrics() {
	result := map[string]int{}
	for _, redirect := range p.redirects {
		result[string(redirect.listener.parserType)]++
	}
	for proto, count := range result {
		metrics.ProxyRedirects.WithLabelValues(proto).Set(float64(count))
	}
}
