// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package proxy

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"

	"github.com/google/renameio/v2"
	jsoniter "github.com/json-iterator/go"
	"github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/completion"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/endpoint"
	"github.com/cilium/cilium/pkg/proxy/types"
	"github.com/cilium/cilium/pkg/revert"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/trigger"
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "proxy")

// field names used while logging
const (
	fieldProxyRedirectID = "id"

	// portReuseDelay is the delay until a port is being reused
	portReuseDelay = 5 * time.Minute

	// redirectCreationAttempts is the number of attempts to create a redirect
	redirectCreationAttempts = 5

	// The filename for the allocated proxy ports. This is periodically
	// written, and restored on restart.
	// The full path is, by default, /run/cilium/state/proxy_ports_state.json
	proxyPortsFile = "proxy_ports_state.json"
)

type DatapathUpdater interface {
	InstallProxyRules(proxyPort uint16, name string)
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
	// rulesPort contains the proxy port value configured to the datapath rules and
	// is non-zero when a proxy has been successfully created and the
	// (new, if after restart) datapath rules have been created.
	rulesPort uint16
}

type proxyPortsMap map[string]*ProxyPort

// Proxy maintains state about redirects
type Proxy struct {
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

	// allocatedPorts is the map of all allocated proxy ports
	// 'true' - port is currently in use
	// 'false' - port has been used the past, and can be reused if needed
	allocatedPorts map[uint16]bool

	// proxyPorts defaults to a map of all supported proxy ports.
	// In addition, it also manages dynamically created proxy ports (e.g. CEC).
	proxyPorts proxyPortsMap

	// path where the set of proxyPorts is persisted on the filesystem for restoration on
	// restart
	proxyPortsPath string

	proxyPortsTrigger *trigger.Trigger

	envoyIntegration *envoyProxyIntegration
	dnsIntegration   *dnsProxyIntegration
}

func createProxy(
	minPort uint16,
	maxPort uint16,
	datapathUpdater DatapathUpdater,
	envoyIntegration *envoyProxyIntegration,
	dnsIntegration *dnsProxyIntegration,
) *Proxy {
	return &Proxy{
		rangeMin:         minPort,
		rangeMax:         maxPort,
		redirects:        make(map[string]*Redirect),
		datapathUpdater:  datapathUpdater,
		allocatedPorts:   make(map[uint16]bool),
		proxyPorts:       defaultProxyPortMap(),
		proxyPortsPath:   filepath.Join(option.Config.StateDir, proxyPortsFile),
		envoyIntegration: envoyIntegration,
		dnsIntegration:   dnsIntegration,
	}
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

// Called with mutex held!
func (p *Proxy) isPortAvailable(openLocalPorts map[uint16]struct{}, port uint16, reuse bool) bool {
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

// Called with mutex held!
func (p *Proxy) allocatePort(port, min, max uint16) (uint16, error) {
	// Get a snapshot of the TCP and UDP ports already open locally.
	openLocalPorts := readOpenLocalPorts(append(procNetTCPFiles, procNetUDPFiles...))

	if p.isPortAvailable(openLocalPorts, port, false) {
		return port, nil
	}

	// TODO: Maybe not create a large permutation each time?
	portRange := rand.Perm(int(max - min + 1))

	// Allow reuse of previously used ports only if no ports are otherwise availeble.
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

// AckProxyPort() marks the proxy of the given type as successfully
// created and creates or updates the datapath rules accordingly.
func (p *Proxy) AckProxyPort(ctx context.Context, name string) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	pp := p.proxyPorts[name]
	if pp == nil {
		return proxyNotFoundError(name)
	}
	return p.ackProxyPort(ctx, name, pp) // creates datapath rules, increases the reference count
}

// ackProxyPort() increases proxy port reference count and creates or updates the datapath rules.
// Each call must eventually be paired with a corresponding releaseProxyPort() call
// to keep the use count up-to-date.
// Must be called with mutex held!
func (p *Proxy) ackProxyPort(ctx context.Context, name string, pp *ProxyPort) error {
	scopedLog := log.WithField(fieldProxyRedirectID, name)

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
		p.proxyPortsTrigger.Trigger()
	}
	pp.nRedirects++
	scopedLog.Debugf("AckProxyPort: acked proxy port %d (%v)", pp.ProxyPort, *pp)
	return nil
}

// releaseProxyPort() decreases the use count and frees the port if no users remain
// Must be called with mutex held!
func (p *Proxy) releaseProxyPort(name string) error {
	pp := p.proxyPorts[name]
	if pp == nil {
		return fmt.Errorf("Can't find proxy port %s", name)
	}

	pp.nRedirects--
	if pp.nRedirects <= 0 {
		if pp.isStatic {
			return fmt.Errorf("Can't release proxy port: proxy %s on %d has a static listener", name, pp.ProxyPort)
		}

		log.WithField(fieldProxyRedirectID, name).Debugf("Delayed release of proxy port %d", pp.ProxyPort)

		// Allow the port to be reallocated for other use if needed.
		p.allocatedPorts[pp.ProxyPort] = false
		pp.ProxyPort = 0
		pp.configured = false
		pp.nRedirects = 0

		// Leave the datapath rules behind on the hope that they get reused later.
		// This becomes possible when we are able to keep the proxy listeners
		// configured also when there are no redirects.
	}

	return nil
}

// findProxyPortByType returns a ProxyPort matching the given type, listener name, and direction, if
// found.  Must be called with mutex held!
func (p *Proxy) findProxyPortByType(l7Type types.ProxyType, listener string, ingress bool) (string, *ProxyPort) {
	portType := l7Type
	switch l7Type {
	case types.ProxyTypeCRD:
		// CRD proxy ports are dynamically created, look up by name
		// 'ingress' is always false for CRD type
		if pp, ok := p.proxyPorts[listener]; ok && pp.ProxyType == types.ProxyTypeCRD && !pp.Ingress {
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
			return name, pp
		}
	}
	return "", nil
}

func proxyTypeNotFoundError(proxyType types.ProxyType, listener string, ingress bool) error {
	dir := "egress"
	if ingress {
		dir = "ingress"
	}
	return fmt.Errorf("unrecognized %s proxy type for %s: %s", dir, listener, proxyType)
}

func proxyNotFoundError(name string) error {
	return fmt.Errorf("unrecognized proxy: %s", name)
}

// must be called with mutex NOT held via p.proxyPortsTrigger
func (p *Proxy) storeProxyPorts(reasons []string) {
	if p.proxyPortsPath == "" {
		return // this is a unit test
	}
	log := log.WithField(logfields.Path, p.proxyPortsPath)

	// use renameio to prevent partial writes
	out, err := renameio.NewPendingFile(p.proxyPortsPath, renameio.WithExistingPermissions(), renameio.WithPermissions(0o600))
	if err != nil {
		log.WithError(err).Error("failed to prepare proxy ports file")
		return
	}
	defer out.Cleanup()

	jw := jsoniter.ConfigFastest.NewEncoder(out)

	portsMap := make(proxyPortsMap)
	p.mutex.Lock()
	// only retain acknowledged, non-zero ports
	for name, pp := range p.proxyPorts {
		if pp.configured && pp.ProxyPort > 0 {
			portsMap[name] = pp
		}
	}
	p.mutex.Unlock()

	if err := jw.Encode(portsMap); err != nil {
		log.WithError(err).Error("failed to marshal proxy ports state")
		return
	}
	if err := out.CloseAtomicallyReplace(); err != nil {
		log.WithError(err).Error("failed to write proxy ports file")
		return
	}
	log.Debug("Wrote proxy ports state")
}

// restore proxy ports from file created earlier by stroreProxyPorts
// must be called with mutex held
func (p *Proxy) restoreProxyPortsFromFile() error {
	log := log.WithField(logfields.Path, p.proxyPortsPath)

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
func (p *Proxy) restoreProxyPortsFromIptables() {
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
func (p *Proxy) RestoreProxyPorts() {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	err := p.restoreProxyPortsFromFile()
	if err != nil {
		log.WithError(err).WithField(logfields.Path, p.proxyPortsPath).Info("No proxy ports file found, falling back to restoring from iptables rules")
		p.restoreProxyPortsFromIptables()
	}
}

// GetProxyPort() returns the fixed listen port for a proxy, if any.
func (p *Proxy) GetProxyPort(name string) (port uint16, isStatic bool, err error) {
	// Accessing pp.proxyPort requires the lock
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	pp := p.proxyPorts[name]
	if pp != nil {
		return pp.ProxyPort, pp.isStatic, nil
	}
	return 0, false, proxyNotFoundError(name)
}

// AllocateCRDProxyPort() allocates a new port for listener 'name', or returns the current one if
// already allocated.
// Each call has to be paired with AckProxyPort(name) to update the datapath rules accordingly.
// Each allocated port must be eventually freed with ReleaseProxyPort().
func (p *Proxy) AllocateCRDProxyPort(name string) (uint16, error) {
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

func (p *Proxy) ReleaseProxyPort(name string) error {
	// Accessing pp.proxyPort requires the lock
	p.mutex.Lock()
	defer p.mutex.Unlock()
	return p.releaseProxyPort(name)
}

// SetProxyPort() marks the proxy 'name' as successfully created with proxy port 'port'.
// Another call to AckProxyPort(name) is needed to update the datapath rules accordingly.
// This should only be called for proxies that have a static listener that is already listening on
// 'port'. May only be called once per proxy.
func (p *Proxy) SetProxyPort(name string, proxyType types.ProxyType, port uint16, ingress bool) error {
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

// ReinstallRoutingRules ensures the presence of routing rules and tables needed
// to route packets to and from the L7 proxy.
func (p *Proxy) ReinstallRoutingRules() error {
	fromIngressProxy, fromEgressProxy := requireFromProxyRoutes()

	if option.Config.EnableIPv4 {
		if err := installToProxyRoutesIPv4(); err != nil {
			return err
		}

		if fromIngressProxy || fromEgressProxy {
			if err := installFromProxyRoutesIPv4(node.GetInternalIPv4Router(), defaults.HostDevice, fromIngressProxy, fromEgressProxy); err != nil {
				return err
			}
		} else {
			if err := removeFromProxyRoutesIPv4(); err != nil {
				return err
			}
		}
	} else {
		if err := removeToProxyRoutesIPv4(); err != nil {
			return err
		}
		if err := removeFromProxyRoutesIPv4(); err != nil {
			return err
		}
	}

	if option.Config.EnableIPv6 {
		if err := installToProxyRoutesIPv6(); err != nil {
			return err
		}

		if fromIngressProxy || fromEgressProxy {
			ipv6, err := getCiliumNetIPv6()
			if err != nil {
				return err
			}
			if err := installFromProxyRoutesIPv6(ipv6, defaults.HostDevice, fromIngressProxy, fromEgressProxy); err != nil {
				return err
			}
		} else {
			if err := removeFromProxyRoutesIPv6(); err != nil {
				return err
			}
		}
	} else {
		if err := removeToProxyRoutesIPv6(); err != nil {
			return err
		}
		if err := removeFromProxyRoutesIPv6(); err != nil {
			return err
		}
	}

	return nil
}

func requireFromProxyRoutes() (fromIngressProxy, fromEgressProxy bool) {
	fromIngressProxy = (option.Config.EnableEnvoyConfig || option.Config.EnableIPSec) && !option.Config.TunnelingEnabled()
	fromEgressProxy = option.Config.EnableIPSec && !option.Config.TunnelingEnabled()
	return
}

// getCiliumNetIPv6 retrieves the first IPv6 address from the cilium_net device.
func getCiliumNetIPv6() (net.IP, error) {
	link, err := netlink.LinkByName(defaults.SecondHostDevice)
	if err != nil {
		return nil, fmt.Errorf("cannot find link '%s': %w", defaults.SecondHostDevice, err)
	}

	addrList, err := netlink.AddrList(link, netlink.FAMILY_V6)
	if err == nil && len(addrList) > 0 {
		return addrList[0].IP, nil
	}

	return nil, fmt.Errorf("failed to find valid IPv6 address for cilium_net")
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
func (p *Proxy) CreateOrUpdateRedirect(
	ctx context.Context, l4 policy.ProxyPolicy, id string, localEndpoint endpoint.EndpointUpdater, wg *completion.WaitGroup,
) (
	uint16, error, revert.FinalizeFunc, revert.RevertFunc,
) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	scopedLog := log.
		WithField(fieldProxyRedirectID, id).
		WithField(logfields.Listener, l4.GetListener()).
		WithField("l7parser", l4.GetL7Parser())

	var finalizeList revert.FinalizeList
	var revertStack revert.RevertStack

	// Check for existing redirect and try to update it if possible. Otherwise, it gets removed before re-creation.
	if existingRedirect, ok := p.redirects[id]; ok {
		existingRedirect.mutex.Lock()

		// Only consider configured (but not necessarily acked) proxy ports for update
		if existingRedirect.listener.configured && existingRedirect.listener.ProxyType == types.ProxyType(l4.GetL7Parser()) {
			updateRevertFunc := existingRedirect.updateRules(l4)
			revertStack.Push(updateRevertFunc)
			implUpdateRevertFunc, err := existingRedirect.implementation.UpdateRules(wg)
			if err != nil {
				existingRedirect.mutex.Unlock()
				p.revertStackUnlocked(revertStack)
				return 0, fmt.Errorf("unable to update existing redirect: %w", err), nil, nil
			}

			revertStack.Push(implUpdateRevertFunc)

			scopedLog.
				WithField(logfields.Object, logfields.Repr(existingRedirect)).
				WithField("proxyType", existingRedirect.listener.ProxyType).
				Debug("updated existing proxy instance")

			existingRedirect.mutex.Unlock()

			// Must return the proxy port when successful
			return existingRedirect.listener.ProxyPort, nil, nil, revertStack.Revert
		}

		// Stale or incompatible redirects get removed before a new one is created below
		err, removeFinalizeFunc, removeRevertFunc := p.removeRedirect(id, wg)
		existingRedirect.mutex.Unlock()

		if err != nil {
			p.revertStackUnlocked(revertStack)
			return 0, fmt.Errorf("unable to remove old redirect: %w", err), nil, nil
		}

		finalizeList.Append(removeFinalizeFunc)
		revertStack.Push(removeRevertFunc)
	}

	// Create a new redirect
	port, err, newRedirectFinalizeFunc, newRedirectRevertFunc := p.createNewRedirect(ctx, l4, id, localEndpoint, wg)
	if err != nil {
		p.revertStackUnlocked(revertStack)
		return 0, fmt.Errorf("failed to create new redirect: %w", err), nil, nil
	}

	finalizeList.Append(newRedirectFinalizeFunc)
	revertStack.Push(newRedirectRevertFunc)

	return port, nil, finalizeList.Finalize, revertStack.Revert
}

func (p *Proxy) createNewRedirect(
	ctx context.Context, l4 policy.ProxyPolicy, id string, localEndpoint endpoint.EndpointUpdater, wg *completion.WaitGroup,
) (
	uint16, error, revert.FinalizeFunc, revert.RevertFunc,
) {
	scopedLog := log.
		WithField(fieldProxyRedirectID, id).
		WithField(logfields.Listener, l4.GetListener()).
		WithField("l7parser", l4.GetL7Parser())

	ppName, pp := p.findProxyPortByType(types.ProxyType(l4.GetL7Parser()), l4.GetListener(), l4.GetIngress())
	if pp == nil {
		return 0, proxyTypeNotFoundError(types.ProxyType(l4.GetL7Parser()), l4.GetListener(), l4.GetIngress()), nil, nil
	}

	redirect := newRedirect(localEndpoint, ppName, pp, l4.GetPort(), l4.GetProtocol())
	_ = redirect.updateRules(l4) // revertFunc not used because revert will remove whole redirect
	// Rely on create*Redirect to update rules, unlike the update case above.

	scopedLog = scopedLog.
		WithField("portName", ppName)

	if pp.ProxyPort == 0 && pp.rulesPort != 0 {
		// try first with the previous port
		pp.ProxyPort = pp.rulesPort
	}

	for nRetry := 0; nRetry < redirectCreationAttempts; nRetry++ {
		// Reallocate port only if not yet configured and the first try failed, or the port
		// has not been (pre)allocated yet.
		// For example, on restart we may have preallocated port that is not configured
		// yet. The port may already be listening, causing allocatePort() to select another
		// one, as the port is not available. We should make the first try with the
		// preallocated port, as in typical case the listener we are about to configure
		// already exists (daemonset proxy), or can be created on a new proxy with the same
		// port (embedded Envoy).
		if !pp.configured && (nRetry > 0 || pp.ProxyPort == 0) {
			// Clear the proxy port on retry so that a random new port will be tried.
			pp.ProxyPort = 0

			// Check if pp.proxyPort is available and find another available proxy port if not.
			proxyPort, err := p.allocatePort(pp.ProxyPort, p.rangeMin, p.rangeMax)
			if err != nil {
				return 0, fmt.Errorf("failed to allocate port: %w", err), nil, nil
			}
			pp.ProxyPort = proxyPort
		}

		if err := p.createRedirectImpl(redirect, l4, wg); err != nil {
			if nRetry < redirectCreationAttempts-1 {
				// an error occurred and we are retrying
				scopedLog.
					WithError(err).
					Warning("Unable to create proxy, retrying")
				continue
			} else {
				// an error occurred, and we have no more retries
				scopedLog.
					WithError(err).
					Error("Unable to create proxy")
				return 0, fmt.Errorf("failed to create redirect implementation: %w", err), nil, nil
			}
		}

		break
	}

	scopedLog.
		WithField(logfields.Object, logfields.Repr(redirect)).
		Debug("Created new proxy instance")

	p.redirects[id] = redirect
	p.updateRedirectMetrics()

	// must mark the proxyPort configured while we still hold the lock to prevent racing between two parallel runs

	// marks port as reserved
	p.allocatedPorts[pp.ProxyPort] = true
	// mark proxy port as configured
	pp.configured = true

	revertFunc := func() error {
		// Proxy port refcount has not been incremented yet, so it must not be decremented
		// when reverting. Undo what we have done above.
		p.mutex.Lock()
		delete(p.redirects, id)

		// Mark the  port for reuse only if no other ports are available
		// Discourage the reuse of the same port in future as revert may have been due to
		// port not being available for bind().
		p.allocatedPorts[pp.ProxyPort] = false
		// clear proxy port on failure so that a new one will be tried next time
		pp.ProxyPort = 0
		pp.configured = false

		p.updateRedirectMetrics()
		p.mutex.Unlock()
		implFinalizeFunc, _ := redirect.implementation.Close(wg)
		if implFinalizeFunc != nil {
			implFinalizeFunc()
		}
		return nil
	}

	// Set the proxy port only after an ACK is received.
	finalizeFunc := func() {
		p.mutex.Lock()
		err := p.ackProxyPort(ctx, ppName, pp)
		p.mutex.Unlock()
		if err != nil {
			scopedLog.
				WithError(err).
				Error("Datapath proxy redirection cannot be enabled, L7 proxy may be bypassed")
		}
	}

	// Must return the proxy port when successful
	return pp.ProxyPort, nil, finalizeFunc, revertFunc
}

func (p *Proxy) createRedirectImpl(redir *Redirect, l4 policy.ProxyPolicy, wg *completion.WaitGroup) error {
	var err error

	switch l4.GetL7Parser() {
	case policy.ParserTypeDNS:
		redir.implementation, err = p.dnsIntegration.createRedirect(redir, wg)
	default:
		redir.implementation, err = p.envoyIntegration.createRedirect(redir, wg)
	}

	return err
}

func (p *Proxy) revertStackUnlocked(revertStack revert.RevertStack) {
	// We ignore errors while reverting. This is best-effort.
	// revertFunc must be called after p.mutex is unlocked, because
	// some functions in the revert stack (like removeRevertFunc)
	// require it
	p.mutex.Unlock()
	revertStack.Revert()
	p.mutex.Lock()
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
func (p *Proxy) removeRedirect(id string, wg *completion.WaitGroup) (error, revert.FinalizeFunc, revert.RevertFunc) {
	log.
		WithField(fieldProxyRedirectID, id).
		Debug("Removing proxy redirect")

	var finalizeList revert.FinalizeList
	var revertStack revert.RevertStack

	r, ok := p.redirects[id]
	if !ok {
		return fmt.Errorf("unable to find redirect %s", id), nil, nil
	}
	delete(p.redirects, id)

	implFinalizeFunc, implRevertFunc := r.implementation.Close(wg)

	finalizeList.Append(implFinalizeFunc)
	revertStack.Push(implRevertFunc)

	// Delay the release and reuse of the port number so it is guaranteed to be
	// safe to listen on the port again. This can't be reverted, so do it in a
	// FinalizeFunc.
	proxyPort := r.listener.ProxyPort
	listenerName := r.name

	finalizeList.Append(func() {
		// break GC loop (implementation may point back to 'r')
		r.implementation = nil

		go func() {
			time.Sleep(portReuseDelay)

			p.mutex.Lock()
			err := p.releaseProxyPort(listenerName)
			p.mutex.Unlock()
			if err != nil {
				log.
					WithField(fieldProxyRedirectID, id).
					WithField("proxyPort", proxyPort).
					WithError(err).
					Warning("Releasing proxy port failed")
			}
		}()
	})

	revertStack.Push(func() error {
		p.mutex.Lock()
		p.redirects[id] = r
		p.mutex.Unlock()

		return nil
	})

	return nil, finalizeList.Finalize, revertStack.Revert
}

func (p *Proxy) UpdateNetworkPolicy(ep endpoint.EndpointUpdater, vis *policy.VisibilityPolicy, policy *policy.L4Policy, ingressPolicyEnforced, egressPolicyEnforced bool, wg *completion.WaitGroup) (error, func() error) {
	return p.envoyIntegration.UpdateNetworkPolicy(ep, vis, policy, ingressPolicyEnforced, egressPolicyEnforced, wg)
}

func (p *Proxy) RemoveNetworkPolicy(ep endpoint.EndpointInfoSource) {
	p.envoyIntegration.RemoveNetworkPolicy(ep)
}

// ChangeLogLevel changes proxy log level to correspond to the logrus log level 'level'.
func (p *Proxy) ChangeLogLevel(level logrus.Level) {
	if err := p.envoyIntegration.changeLogLevel(level); err != nil {
		log.WithError(err).Debug("failed to change log level in Envoy proxy")
	}

	if err := p.dnsIntegration.changeLogLevel(level); err != nil {
		log.WithError(err).Debug("failed to change log level in DNS proxy")
	}
}

// GetStatusModel returns the proxy status as API model
func (p *Proxy) GetStatusModel() *models.ProxyStatus {
	p.mutex.RLock()
	defer p.mutex.RUnlock()

	result := &models.ProxyStatus{
		IP:             node.GetInternalIPv4Router().String(),
		PortRange:      fmt.Sprintf("%d-%d", p.rangeMin, p.rangeMax),
		TotalRedirects: int64(len(p.redirects)),
	}
	for _, pp := range p.proxyPorts {
		if pp.nRedirects > 0 {
			result.TotalPorts++
		}
	}
	for name, redirect := range p.redirects {
		result.Redirects = append(result.Redirects, &models.ProxyRedirect{
			Name:      name,
			Proxy:     redirect.name,
			ProxyPort: int64(redirect.listener.rulesPort),
		})
	}
	result.EnvoyDeploymentMode = "embedded"
	if option.Config.ExternalEnvoyProxy {
		result.EnvoyDeploymentMode = "external"
	}
	return result
}

// updateRedirectMetrics updates the redirect metrics per application protocol
// in Prometheus. Lock needs to be held to call this function.
func (p *Proxy) updateRedirectMetrics() {
	result := map[string]int{}
	for _, redirect := range p.redirects {
		result[string(redirect.listener.ProxyType)]++
	}
	for proto, count := range result {
		metrics.ProxyRedirects.WithLabelValues(proto).Set(float64(count))
	}
}
