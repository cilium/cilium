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
	"context"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/envoy"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/proxymap"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
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

	// redirectCreationAttempts is the number of attempts to create a redirect
	redirectCreationAttempts = 5
)

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

	// allocatedPorts is the map of all allocated proxy ports
	allocatedPorts map[uint16]struct{}

	// redirects is the map of all redirect configurations indexed by
	// the redirect identifier. Redirects may be implemented by different
	// proxies.
	redirects map[string]*Redirect
}

// StartProxySupport starts the servers to support L7 proxies: xDS GRPC server
// and access log server.
func StartProxySupport(minPort uint16, maxPort uint16, stateDir string,
	accessLogFile string, accessLogNotifier logger.LogRecordNotifier, accessLogMetadata []string) *Proxy {
	xdsServer := envoy.StartXDSServer(stateDir)

	if accessLogFile != "" {
		if err := logger.OpenLogfile(accessLogFile); err != nil {
			log.WithError(err).WithField(logger.FieldFilePath, accessLogFile).
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
		XDSServer:      xdsServer,
		stateDir:       stateDir,
		rangeMin:       minPort,
		rangeMax:       maxPort,
		redirects:      make(map[string]*Redirect),
		allocatedPorts: make(map[uint16]struct{}),
	}
}

var (
	portRandomizer      = rand.New(rand.NewSource(time.Now().UnixNano()))
	portRandomizerMutex lock.Mutex
)

func (p *Proxy) allocatePort() (uint16, error) {
	// Get a snapshot of the TCP ports already open locally.
	openLocalPorts, err := readOpenLocalPorts(procNetTCPFiles)
	if err != nil {
		return 0, fmt.Errorf("couldn't read local ports from /proc: %s", err)
	}

	portRandomizerMutex.Lock()
	defer portRandomizerMutex.Unlock()

	for _, r := range portRandomizer.Perm(int(p.rangeMax - p.rangeMin + 1)) {
		resPort := uint16(r) + p.rangeMin

		if _, ok := p.allocatedPorts[resPort]; !ok {
			if _, alreadyOpen := openLocalPorts[resPort]; !alreadyOpen {
				return resPort, nil
			}
		}

	}

	return 0, fmt.Errorf("no available proxy ports")
}

var gcOnce sync.Once

// CreateOrUpdateRedirect creates or updates a L4 redirect with corresponding
// proxy configuration. This will allocate a proxy port as required and launch
// a proxy instance. If the redirect is already in place, only the rules will be
// updated.
func (p *Proxy) CreateOrUpdateRedirect(l4 *policy.L4Filter, id string, localEndpoint logger.EndpointUpdater,
	wg *completion.WaitGroup) (redir *Redirect, err error, finalizeFunc revert.FinalizeFunc, revertFunc revert.RevertFunc) {
	gcOnce.Do(func() {
		go func() {
			for {
				time.Sleep(10 * time.Second)
				if deleted := proxymap.GC(); deleted > 0 {
					log.WithField("count", deleted).
						Debug("Evicted entries from proxy table")
				}
			}
		}()
	})

	p.mutex.Lock()
	defer func() {
		p.UpdateRedirectMetrics()
		p.mutex.Unlock()
	}()

	scopedLog := log.WithField(fieldProxyRedirectID, id)

	var revertStack revert.RevertStack
	revertFunc = revertStack.Revert

	var ok bool
	if redir, ok = p.redirects[id]; ok {
		redir.mutex.Lock()

		if redir.parserType == l4.L7Parser {
			updateRevertFunc := redir.updateRules(l4)
			revertStack.Push(updateRevertFunc)
			var implUpdateRevertFunc revert.RevertFunc
			implUpdateRevertFunc, err = redir.implementation.UpdateRules(wg, l4)
			if err != nil {
				err = fmt.Errorf("unable to update existing redirect: %s", err)
				return
			}
			revertStack.Push(implUpdateRevertFunc)

			redir.lastUpdated = time.Now()

			scopedLog.WithField(logfields.Object, logfields.Repr(redir)).
				Debug("updated existing ", l4.L7Parser, " proxy instance")

			redir.mutex.Unlock()
			return
		}

		var removeRevertFunc revert.RevertFunc
		err, finalizeFunc, removeRevertFunc = p.removeRedirect(id, wg)
		redir.mutex.Unlock()

		if err != nil {
			err = fmt.Errorf("unable to remove old redirect: %s", err)
			return
		}

		revertStack.Push(removeRevertFunc)
	}

	var to uint16
	fixedProxyPort := false
	listenerName := id
	// Detect the need for a reusable listener here and override the defaults, e.g.:
	// if <need reusable listener> {
	//         listenerName = "cilium-xxxx-yyyy" // unique name for the reusable listener
	//         to = <port> // listener port to use
	//         fixedProxyPort = true // needed if `to` was overridden above
	// }

	redir = newRedirect(localEndpoint, listenerName)
	redir.endpointID = localEndpoint.GetID()
	redir.ingress = l4.Ingress
	redir.parserType = l4.L7Parser
	redir.updateRules(l4)
	// Rely on create*Redirect to update rules, unlike the update case above.

	for nRetry := 0; ; nRetry++ {
		if fixedProxyPort == false {
			to, err = p.allocatePort()
			if err != nil {
				revertFunc() // Ignore errors while reverting. This is best-effort.
				return
			}
		}

		redir.ProxyPort = to

		switch l4.L7Parser {
		case policy.ParserTypeDNS:
			redir.implementation, err = createDNSRedirect(redir, dnsConfiguration{}, DefaultEndpointInfoRegistry)
			// DNS uses a fixed port. Release the allocated ProxyPort since normal
			// cleanup will not (.ProxyPort is set in createDNSRedirect). This must
			// be deferred because it is set below.
			defer delete(p.allocatedPorts, to)

		case policy.ParserTypeKafka:
			redir.implementation, err = createKafkaRedirect(redir, kafkaConfiguration{}, DefaultEndpointInfoRegistry)

		case policy.ParserTypeHTTP:
			redir.implementation, err = createEnvoyRedirect(redir, p.stateDir, p.XDSServer, wg)
		default:
			redir.implementation, err = createEnvoyRedirect(redir, p.stateDir, p.XDSServer, wg)
		}

		switch {
		case err == nil:
			scopedLog.WithField(logfields.Object, logfields.Repr(redir)).
				Debug("Created new ", l4.L7Parser, " proxy instance")

			p.allocatedPorts[to] = struct{}{}
			p.redirects[id] = redir

			revertStack.Push(func() error {
				completionCtx, cancel := context.WithCancel(context.Background())
				proxyWaitGroup := completion.NewWaitGroup(completionCtx)
				err, finalize, _ := p.RemoveRedirect(id, proxyWaitGroup)
				// Don't wait for an ACK. This is best-effort. Just clean up the completions.
				cancel()
				proxyWaitGroup.Wait() // Ignore the returned error.
				if err == nil && finalize != nil {
					finalize()
				}
				return err
			})

			return

		// an error occurred, and we have no more retries
		case nRetry >= redirectCreationAttempts:
			scopedLog.WithError(err).Error("Unable to create ", l4.L7Parser, " proxy")

			revertFunc() // Ignore errors while reverting. This is best-effort.
			return

		// an error occurred and we can retry
		default:
			scopedLog.WithError(err).Warning("Unable to create ", l4.L7Parser, " proxy, will retry")
		}
	}
}

// RemoveRedirect removes an existing redirect.
func (p *Proxy) RemoveRedirect(id string, wg *completion.WaitGroup) (error, revert.FinalizeFunc, revert.RevertFunc) {
	p.mutex.Lock()
	defer func() {
		p.UpdateRedirectMetrics()
		p.mutex.Unlock()
	}()
	return p.removeRedirect(id, wg)
}

// removeRedirect removes an existing redirect. p.mutex must be held
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
	proxyPort := r.ProxyPort
	finalizeFunc = func() {
		if implFinalizeFunc != nil {
			implFinalizeFunc()
		}

		go func() {
			time.Sleep(portReuseDelay)

			// The cleanup of the proxymap is delayed a bit to ensure that
			// the datapath has implemented the redirect change and we
			// cleanup the map before we release the port and allow reuse
			proxymap.CleanupOnRedirectClose(proxyPort)

			p.mutex.Lock()
			delete(p.allocatedPorts, proxyPort)
			p.mutex.Unlock()

			log.WithField(fieldProxyRedirectID, id).Debugf("Delayed release of proxy port %d", proxyPort)
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
		result[string(redirect.parserType)]++
	}
	for proto, count := range result {
		metrics.ProxyRedirects.WithLabelValues(proto).Set(float64(count))
	}
}
