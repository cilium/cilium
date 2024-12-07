// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxyports

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/proxy/types"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/trigger"

	"github.com/google/renameio/v2"
	jsoniter "github.com/json-iterator/go"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "proxy")

// field names used while logging
const (
	fieldProxyRedirectID = "id"

	// portReuseDelay is the delay until a port is being reused
	portReuseDelay = 5 * time.Minute

	// The filename for the allocated proxy ports. This is periodically
	// written, and restored on restart.
	// The full path is, by default, /run/cilium/state/proxy_ports_state.json
	proxyPortsFile = "proxy_ports_state.json"
)

type DatapathUpdater interface {
	InstallProxyRules(proxyPort uint16, name string)
	SupportsOriginalSourceAddr() bool
	GetProxyPorts() map[string]uint16
}

type ProxyPort struct {
	// proxy type this port applies to (immutable)
	ProxyType types.ProxyType `json:"type"`
	// 'true' for Ingress, 'false' for egress (immutable)
	// 'false' for CRD redirects, which are accessed by name only.
	Ingress bool `json:"ingress"`
	// ProxyPort is the desired proxy listening port number.
	ProxyPort uint16 `json:"port"`
	// isStatic is true when the listener on the proxy port is incapable
	// of stopping and/or being reconfigured with a new proxy port once it has been
	// first started. Set 'true' by SetProxyPort(), which is only called for
	// static listeners (currently only DNS proxy).
	isStatic bool
	// nRedirects is the number of redirects using this proxy port
	nRedirects int
	// Configured is true when the proxy is (being) configured, but not necessarily
	// acknowledged yet. This is reset to false when the underlying proxy listener
	// is removed.
	configured bool
	// acknowledged is true when the proxy port has been successfully acknowledged
	// An acknowledged port is not reset even if a NACK is received later.
	acknowledged bool
	// rulesPort contains the proxy port value configured to the datapath rules and
	// is non-zero when a proxy has been successfully created and the
	// (new, if after restart) datapath rules have been created.
	rulesPort uint16
	// cancel for delayed release. Call if non-nil when a new reference is taken to cancel out a pending delayed release
	releaseCancel func()
}

type proxyPortsMap map[string]*ProxyPort

type ProxyPorts struct {
	// rangeMin is the minimum port used for proxy port allocation
	rangeMin uint16

	// rangeMax is the maximum port used for proxy port allocation.
	// If port is unspecified, the proxy will automatically allocate
	// ports out of the rangeMin-rangeMax range.
	rangeMax uint16

	// Datapath updater for installing and removing proxy rules for a single
	// proxy port
	datapathUpdater DatapathUpdater

	// path where the set of proxyPorts is persisted on the filesystem for restoration on
	// restart
	proxyPortsPath string

	// Trigger for stroring proxy ports on to file
	Trigger *trigger.Trigger

	// mutex is the lock required when accessing fields below or
	// any of the mutable fields of a specific ProxyPort.
	mutex lock.RWMutex

	// allocatedPorts is the map of all allocated proxy ports
	// 'true' - port is currently in use
	// 'false' - port has been used the past, and can be reused if needed
	allocatedPorts map[uint16]bool

	// proxyPorts defaults to a map of all supported proxy ports.
	// In addition, it also manages dynamically created proxy ports (e.g. CEC).
	proxyPorts proxyPortsMap
}

func NewProxyPorts(
	minPort uint16,
	maxPort uint16,
	datapathUpdater DatapathUpdater,
) *ProxyPorts {
	return &ProxyPorts{
		rangeMin:        minPort,
		rangeMax:        maxPort,
		datapathUpdater: datapathUpdater,
		proxyPortsPath:  filepath.Join(option.Config.StateDir, proxyPortsFile),
		allocatedPorts:  make(map[uint16]bool),
		proxyPorts:      defaultProxyPortMap(),
	}
}

func (p *ProxyPorts) GetStatusInfo() (rangeMin, rangeMax, nPorts uint16) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	for _, pp := range p.proxyPorts {
		if pp.nRedirects > 0 {
			nPorts++
		}
	}
	return p.rangeMin, p.rangeMax, nPorts
}

func defaultProxyPortMap() proxyPortsMap {
	return proxyPortsMap{
		"cilium-http-egress": {
			ProxyType: types.ProxyTypeHTTP,
			Ingress:   false,
		},
		"cilium-http-ingress": {
			ProxyType: types.ProxyTypeHTTP,
			Ingress:   true,
		},
		types.DNSProxyName: {
			ProxyType: types.ProxyTypeDNS,
			Ingress:   false,
		},
		"cilium-proxylib-egress": {
			ProxyType: types.ProxyTypeAny,
			Ingress:   false,
		},
		"cilium-proxylib-ingress": {
			ProxyType: types.ProxyTypeAny,
			Ingress:   true,
		},
	}
}

func (p *ProxyPorts) isPortAvailable(openLocalPorts map[uint16]struct{}, port uint16, reuse bool) bool {
	if port == 0 {
		return false // zero port requested
	}
	if inuse, used := p.allocatedPorts[port]; used && (inuse || !reuse) {
		return false // port already used
	}
	// Check that the port is not already open
	if _, alreadyOpen := openLocalPorts[port]; alreadyOpen {
		return false // port already open
	}

	return true
}

func (p *ProxyPorts) allocatePort(port, min, max uint16) (uint16, error) {
	// Get a snapshot of the TCP and UDP ports already open locally.
	openLocalPorts := OpenLocalPorts()

	if p.isPortAvailable(openLocalPorts, port, false) {
		return port, nil
	}

	// TODO: Maybe not create a large permutation each time?
	portRange := rand.Perm(int(max - min + 1))

	// Allow reuse of previously used ports only if no ports are otherwise available.
	// This allows the same port to be used again by a listener being reconfigured
	// after deletion.
	for _, reuse := range []bool{false, true} {
		for _, r := range portRange {
			resPort := uint16(r) + min

			if p.isPortAvailable(openLocalPorts, resPort, reuse) {
				return resPort, nil
			}
		}
	}

	return 0, fmt.Errorf("no available proxy ports")
}

func (p *ProxyPorts) AllocatePort(pp *ProxyPort, retry bool) (err error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	// Reallocate port only if not yet configured and the first try failed, or the port
	// has not been (pre)allocated yet.

	// For example, on restart we may have preallocated port that is not configured
	// yet. The port may already be listening, causing allocatePort() to select another
	// one, as the port is not available. We should make the first try with the
	// preallocated port, as in typical case the listener we are about to configure
	// already exists (daemonset proxy), or can be created on a new proxy with the same
	// port (embedded Envoy).
	if !pp.configured && (retry || pp.ProxyPort == 0) {
		if pp.ProxyPort != 0 {
			p.reset(pp)
		}

		// Check if pp.proxyPort is available and find another available proxy port
		// if not.
		pp.ProxyPort, err = p.allocatePort(pp.ProxyPort, p.rangeMin, p.rangeMax)
		if err == nil {
			// marks port as reserved
			p.allocatedPorts[pp.ProxyPort] = true
			// mark proxy port as configured
			pp.configured = true
		}
	}
	return err
}

// AllocateCRDProxyPort() allocates a new port for listener 'name', or returns the current one if
// already allocated.
// Each call has to be paired with AckProxyPort(name) to update the datapath rules accordingly.
// Each allocated port must be eventually freed with ReleaseProxyPort().
func (p *ProxyPorts) AllocateCRDProxyPort(name string) (uint16, error) {
	// Accessing pp.proxyPort requires the lock
	p.mutex.Lock()
	defer p.mutex.Unlock()

	pp := p.proxyPorts[name]
	if pp == nil || pp.Ingress {
		pp = &ProxyPort{ProxyType: types.ProxyTypeCRD, Ingress: false}
	}

	// Allocate a new port only if a port was never allocated before.
	// This is required since Envoy may already be listening on the
	// previously allocated port for this proxy listener.
	if pp.ProxyPort == 0 {
		var err error
		// Try to allocate the same port that was previously used on the datapath
		if pp.rulesPort != 0 && !p.allocatedPorts[pp.rulesPort] {
			pp.ProxyPort = pp.rulesPort
		} else {
			pp.ProxyPort, err = p.allocatePort(pp.rulesPort, p.rangeMin, p.rangeMax)
			if err != nil {
				return 0, err
			}
		}
	}
	p.proxyPorts[name] = pp
	// marks port as reserved
	p.allocatedPorts[pp.ProxyPort] = true
	// mark proxy port as configured
	pp.configured = true

	log.WithField(fieldProxyRedirectID, name).Debugf("AllocateProxyPort: allocated proxy port %d (%v)", pp.ProxyPort, *pp)

	return pp.ProxyPort, nil
}

func (pp *ProxyPort) addReference() {
	pp.nRedirects++
	if pp.releaseCancel != nil {
		pp.releaseCancel()
		pp.releaseCancel = nil
	}
}

// AckProxyPortWithReference() marks the proxy of the given type as successfully
// created and creates or updates the datapath rules accordingly.
// Takes a reference on the proxy port.
func (p *ProxyPorts) AckProxyPortWithReference(ctx context.Context, name string) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	pp := p.proxyPorts[name]
	if pp == nil {
		return proxyNotFoundError(name)
	}
	err := p.ackProxyPort(ctx, name, pp) // creates datapath rules
	if err == nil {
		pp.addReference()
	}
	return err
}

// AckProxyPort() marks the proxy of the given type as successfully
// created and creates or updates the datapath rules accordingly.
// Does NOT take a reference on the proxy port.
func (p *ProxyPorts) AckProxyPort(ctx context.Context, name string, pp *ProxyPort) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	return p.ackProxyPort(ctx, name, pp)
}

// ackProxyPort() increases proxy port reference count and creates or updates the datapath rules.
// Each call must eventually be paired with a corresponding releaseProxyPort() call
// to keep the use count up-to-date.
// Must be called with mutex held!
func (p *ProxyPorts) ackProxyPort(ctx context.Context, name string, pp *ProxyPort) error {
	scopedLog := log.WithField(fieldProxyRedirectID, name)

	if pp.ProxyPort == 0 {
		return fmt.Errorf("ackProxyPort: zero port on %s not allowed", name)
	}

	// Datapath rules are added only after we know the proxy configuration
	// with the actual port number has succeeded. Deletion of the rules
	// is delayed after the redirects have been removed to the point
	// when we know the port number changes. This is to reduce the churn
	// in the datapath, but means that the datapath rules may exist even
	// if the proxy is not currently configured.

	// Add new rules, if needed
	if pp.rulesPort != pp.ProxyPort {
		// Add rules for the new port
		// This should always succeed if we have managed to start-up properly
		scopedLog.Infof("Adding new proxy port rules for %s:%d", name, pp.ProxyPort)
		p.datapathUpdater.InstallProxyRules(pp.ProxyPort, name)
		pp.rulesPort = pp.ProxyPort

		// trigger writing proxy ports to file
		p.Trigger.Trigger()
	}
	pp.acknowledged = true
	scopedLog.Debugf("AckProxyPort: acked proxy port %d (%v)", pp.ProxyPort, *pp)
	return nil
}

// releaseProxyPort() decreases the use count and frees the port if no users remain
// Must be called with mutex held!
func (p *ProxyPorts) releaseProxyPort(name string, portReuseWait time.Duration) error {
	pp := p.proxyPorts[name]
	if pp == nil {
		return fmt.Errorf("Can't find proxy port %s", name)
	}

	if pp.nRedirects <= 0 {
		nRedirects := pp.nRedirects
		pp.nRedirects = 0
		return fmt.Errorf("Can't release proxy port with has non-positive reference count: %d", nRedirects)
	}

	pp.nRedirects--

	// Static proxy port is not released, dynamic proxy ports are released after a delay if
	// still on last reference count
	if !pp.isStatic && pp.nRedirects == 0 && pp.releaseCancel == nil {
		ctx, cancel := context.WithCancel(context.Background())
		pp.releaseCancel = cancel

		go func() {
			select {
			case <-time.After(portReuseWait):
				p.mutex.Lock()
				defer p.mutex.Unlock()

				if pp.nRedirects == 0 {
					pp.releaseCancel = nil
					log.WithField(fieldProxyRedirectID, name).Debugf("Delayed release of proxy port %d", pp.ProxyPort)
					p.reset(pp)

					// Leave the datapath rules behind on the hope that they get reused
					// later.  This becomes possible when we are able to keep the proxy
					// listeners configured also when there are no redirects.
				}
			case <-ctx.Done():
			}
		}()
	}

	return nil
}

// HasProxyType returns 'true' if 'pp' is configured and has the given proxy type.
func (p *ProxyPorts) HasProxyType(pp *ProxyPort, proxyType types.ProxyType) bool {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	return pp.configured && pp.ProxyType == proxyType
}

// reset() frees the port
// Must be called with mutex held!
func (p *ProxyPorts) Restore(pp *ProxyPort) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if pp.ProxyPort == 0 && pp.rulesPort != 0 {
		// try first with the previous port
		pp.ProxyPort = pp.rulesPort
	}
}

func (p *ProxyPorts) GetRulesPort(pp *ProxyPort) uint16 {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	return pp.rulesPort
}

// ResetUnacknowledged() frees the port if it has not been acknowledged yet
// A static port is not reset.
func (p *ProxyPorts) ResetUnacknowledged(pp *ProxyPort) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	if !pp.isStatic && !pp.acknowledged {
		p.reset(pp)
	}
}

// reset() frees the port
// Must be called with mutex held!
func (p *ProxyPorts) reset(pp *ProxyPort) {
	// Mark the port for reuse only if no other ports are
	// available Discourage the reuse of the same port in future
	// as revert may have been due to port not being available
	// for bind().
	p.allocatedPorts[pp.ProxyPort] = false
	// clear proxy port on failure so that a new one will be
	// tried next time
	pp.ProxyPort = 0
	pp.configured = false
	pp.acknowledged = false
}

// FindByType returns a ProxyPort matching the given type, listener name, and direction, if
// found.
// Adds reference cound to the returned ProxyPort to prevent it being concurrently released.
// Reference must be released with ReleaseProxyPort.
// Must NOT be called with mutex held!
func (p *ProxyPorts) FindByTypeWithReference(l7Type types.ProxyType, listener string, ingress bool) (string, *ProxyPort) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	portType := l7Type
	switch l7Type {
	case types.ProxyTypeCRD:
		// CRD proxy ports are dynamically created, look up by name
		// 'ingress' is always false for CRD type
		if pp, ok := p.proxyPorts[listener]; ok && pp.ProxyType == types.ProxyTypeCRD && !pp.Ingress {
			pp.addReference()
			return listener, pp
		}
		log.Debugf("findProxyPortByType: can not find crd listener %s from %v", listener, p.proxyPorts)
		return "", nil
	case types.ProxyTypeDNS, types.ProxyTypeHTTP:
		// Look up by the given type
	default:
		// "Unknown" parsers are assumed to be Proxylib (TCP) parsers, which
		// is registered with an empty string.
		// This works also for explicit TCP and TLS parser types, which are backed by the
		// TCP Proxy filter chain.
		portType = types.ProxyTypeAny
	}
	// proxyPorts is small enough to not bother indexing it.
	for name, pp := range p.proxyPorts {
		if pp.ProxyType == portType && pp.Ingress == ingress {
			pp.addReference()
			return name, pp
		}
	}
	return "", nil
}

func proxyNotFoundError(name string) error {
	return fmt.Errorf("unrecognized proxy: %s", name)
}

// must be called with mutex NOT held via p.proxyPortsTrigger
func (p *ProxyPorts) StoreProxyPorts(ctx context.Context) error {
	if p.proxyPortsPath == "" {
		return nil // this is a unit test
	}
	log := log.WithField(logfields.Path, p.proxyPortsPath)

	// use renameio to prevent partial writes
	out, err := renameio.NewPendingFile(p.proxyPortsPath, renameio.WithExistingPermissions(), renameio.WithPermissions(0o600))
	if err != nil {
		log.WithError(err).Error("failed to prepare proxy ports file")
		return err
	}
	defer out.Cleanup()

	jw := jsoniter.ConfigFastest.NewEncoder(out)

	portsMap := make(proxyPortsMap)
	p.mutex.Lock()
	// only retain acknowledged, non-zero ports
	for name, pp := range p.proxyPorts {
		if pp.acknowledged {
			portsMap[name] = pp
		}
	}
	p.mutex.Unlock()

	if err := jw.Encode(portsMap); err != nil {
		log.WithError(err).Error("failed to marshal proxy ports state")
		return err
	}
	if err := out.CloseAtomicallyReplace(); err != nil {
		log.WithError(err).Error("failed to write proxy ports file")
		return err
	}
	log.Debug("Wrote proxy ports state")
	return nil
}

var (
	staleProxyPortsFile = errors.New("proxy ports file is too old")
)

// restore proxy ports from file created earlier by stroreProxyPorts
// must be called with mutex held
func (p *ProxyPorts) restoreProxyPortsFromFile(restoredProxyPortsStaleLimit uint) error {
	log := log.WithField(logfields.Path, p.proxyPortsPath)

	// Check that the file exists and is not too old
	stat, err := os.Stat(p.proxyPortsPath)
	if err != nil {
		return err
	}
	if time.Since(stat.ModTime()) > time.Duration(restoredProxyPortsStaleLimit)*time.Minute {
		return staleProxyPortsFile
	}

	// Read in checkpoint file
	fp, err := os.Open(p.proxyPortsPath)
	if err != nil {
		return err
	}
	defer fp.Close()

	jr := jsoniter.ConfigFastest.NewDecoder(fp)
	var portsMap proxyPortsMap
	if err := jr.Decode(&portsMap); err != nil {
		return err
	}

	for name, pp := range portsMap {
		if existing := p.proxyPorts[name]; existing != nil {
			if existing.ProxyPort != 0 {
				continue // do not overwrite explicitly set port
			}
		}
		p.proxyPorts[name] = pp
		p.allocatedPorts[pp.ProxyPort] = false
		log.
			WithField(fieldProxyRedirectID, name).
			WithField("proxyPort", pp.ProxyPort).
			Debugf("RestoreProxyPorts: preallocated proxy port")
	}
	return nil
}

// restoreProxyPortsFromIptables tries to find earlier port numbers from datapath and use them
// as defaults for proxy ports
// must be called with mutex held
func (p *ProxyPorts) restoreProxyPortsFromIptables() {
	// restore proxy ports from the datapath iptables rules
	portsMap := p.datapathUpdater.GetProxyPorts()
	for name, port := range portsMap {
		pp := p.proxyPorts[name]
		if pp != nil {
			if pp.ProxyPort != 0 {
				continue // do not overwrite explicitly set port
			}
			pp.ProxyPort = port
		} else {
			// Only CRD type proxy ports can be dynamically allocated. Assume a port
			// from datapath with an unknown name was for a dynamically allocated CRD
			// proxy and pre-allocate a proxy port for it.
			// CRD proxy ports always have 'ingress' as 'false'.
			p.proxyPorts[name] = &ProxyPort{ProxyType: types.ProxyTypeCRD, Ingress: false, ProxyPort: port}
		}
		p.allocatedPorts[port] = false
		log.
			WithField(fieldProxyRedirectID, name).
			WithField("proxyPort", port).
			Debugf("RestoreProxyPorts: preallocated proxy port from iptables")
	}
}

// Exported API

// RestoreProxyPorts tries to find earlier port numbers from datapath and use them
// as defaults for proxy ports
func (p *ProxyPorts) RestoreProxyPorts(restoredProxyPortsStaleLimit uint) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	err := p.restoreProxyPortsFromFile(restoredProxyPortsStaleLimit)
	if err != nil {
		log.WithError(err).WithField(logfields.Path, p.proxyPortsPath).Info("Resoring proxy ports from file failed, falling back to restoring from iptables rules")
		p.restoreProxyPortsFromIptables()
	}
}

// GetProxyPort() returns the fixed listen port for a proxy, if any.
func (p *ProxyPorts) GetProxyPort(name string) (port uint16, isStatic bool, err error) {
	// Accessing pp.proxyPort requires the lock
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	pp := p.proxyPorts[name]
	if pp != nil {
		return pp.ProxyPort, pp.isStatic, nil
	}
	return 0, false, proxyNotFoundError(name)
}

func (p *ProxyPorts) ReleaseProxyPort(name string) error {
	// Accessing p.proxyPorts requires the lock
	p.mutex.Lock()
	defer p.mutex.Unlock()
	return p.releaseProxyPort(name, portReuseDelay)
}

// SetProxyPort() marks the proxy 'name' as successfully created with proxy port 'port'.
// Another call to AckProxyPort(name) is needed to update the datapath rules accordingly.
// This should only be called for proxies that have a static listener that is already listening on
// 'port'. May only be called once per proxy.
func (p *ProxyPorts) SetProxyPort(name string, proxyType types.ProxyType, port uint16, ingress bool) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	pp := p.proxyPorts[name]
	if pp == nil {
		pp = &ProxyPort{ProxyType: proxyType, Ingress: ingress}
		p.proxyPorts[name] = pp
	}
	if pp.nRedirects > 0 {
		return fmt.Errorf("Can't set proxy port to %d: proxy %s is already configured on %d", port, name, pp.ProxyPort)
	}
	pp.ProxyPort = port
	pp.isStatic = true // prevents release of the proxy port
	// marks port as reserved
	p.allocatedPorts[pp.ProxyPort] = true
	// mark proxy port as configured
	pp.configured = true
	return nil
}
