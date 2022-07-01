// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dnsproxy

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/semaphore"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn/matchpattern"
	"github.com/cilium/cilium/pkg/fqdn/re"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/spanstat"
)

const (
	// ProxyForwardTimeout is the maximum time to wait for DNS responses to
	// forwarded DNS requests. This is needed since UDP queries have no way to
	// indicate that the client has stopped expecting a response.
	ProxyForwardTimeout = 10 * time.Second

	// ProxyBindTimeout is how long we wait for a successful bind to the bindaddr.
	// Note: This must be divisible by 5 without going to 0
	ProxyBindTimeout = 20 * time.Second

	// ProxyBindRetryInterval is how long to wait between attempts to bind to the
	// proxy address:port
	ProxyBindRetryInterval = ProxyBindTimeout / 5
)

// DNSProxy is a L7 proxy for DNS traffic. It keeps a list of allowed DNS
// lookups that can be regexps and blocks lookups that are not allowed.
// A singleton is always running inside cilium-agent.
// Note: All public fields are read only and do not require locking
type DNSProxy struct {
	// BindAddr is the local address the server is using to listen for DNS
	// requests. This is a read-only value and reflects the actual value. Passing
	// ":0" to StartDNSProxy will allow the kernel to set the port, and that can
	// be read here.
	BindAddr string

	// BindPort is the port in BindAddr.
	BindPort uint16

	// LookupRegisteredEndpoint is a provided callback that returns the endpoint ID
	// as a uint16.
	// Note: this is a little pointless since this proxy is in-process but it is
	// intended to allow us to switch to an external proxy process by forcing the
	// design now.
	LookupRegisteredEndpoint LookupEndpointIDByIPFunc

	// LookupSecIDByIP is a provided callback that returns the IP's security ID
	// from the ipcache.
	// Note: this is a little pointless since this proxy is in-process but it is
	// intended to allow us to switch to an external proxy process by forcing the
	// design now.
	LookupSecIDByIP LookupSecIDByIPFunc

	// LookupIPsBySecID is a provided callback that returns the IPs by security ID
	// from the ipcache.
	LookupIPsBySecID LookupIPsBySecIDFunc

	// NotifyOnDNSMsg is a provided callback by which the proxy can emit DNS
	// response data. It is intended to wire into a DNS cache and a
	// fqdn.NameManager.
	// Note: this is a little pointless since this proxy is in-process but it is
	// intended to allow us to switch to an external proxy process by forcing the
	// design now.
	NotifyOnDNSMsg NotifyOnDNSMsgFunc

	// UDPServer, TCPServer are the miekg/dns server instances. They handle DNS
	// parsing etc. for us.
	UDPServer, TCPServer *dns.Server

	// UDPClient, TCPClient are the miekg/dns client instances. Forwarded
	// requests are made with these clients but are sent to the originally
	// intended DNS server.
	// Note: The DNS request ID is randomized but when seeing a lot of traffic we
	// may still exhaust the 16-bit ID space for our (source IP, source Port) and
	// this may cause DNS disruption. A client pool may be better.
	UDPClient, TCPClient *dns.Client

	// EnableDNSCompression allows the DNS proxy to compress responses to
	// endpoints that are larger than 512 Bytes or the EDNS0 option, if present.
	EnableDNSCompression bool

	// ConcurrencyLimit limits parallel goroutines number that serve DNS
	ConcurrencyLimit *semaphore.Weighted
	// ConcurrencyGracePeriod is the grace period for waiting on
	// ConcurrencyLimit before timing out
	ConcurrencyGracePeriod time.Duration
	// logLimiter limits log msgs that could be bursty and too verbose.
	// Currently used when ConcurrencyLimit is set.
	logLimiter logging.Limiter

	// lookupTargetDNSServer extracts the originally intended target of a DNS
	// query. It is always set to lookupTargetDNSServer in
	// helpers.go but is modified during testing.
	lookupTargetDNSServer func(w dns.ResponseWriter) (serverIP net.IP, serverPort uint16, addrStr string, err error)

	// maxIPsPerRestoredDNSRule is the maximum number of IPs to maintain for each
	// restored DNS rule.
	maxIPsPerRestoredDNSRule int

	// this mutex protects variables below this point
	lock.RWMutex

	// usedServers is the set of DNS servers that have been allowed and used successfully.
	// This is used to limit the number of IPs we store for restored DNS rules.
	usedServers map[string]struct{}

	// allowed tracks all allowed L7 DNS rules by endpointID, destination port,
	// and L3 Selector. All must match for a query to be allowed.
	//
	// matchNames with no regexp wildcards are still compiled, internally.
	// Note: Simple DNS names, e.g. bar.foo.com, will treat the "." as a literal.
	allowed perEPAllow

	// restored is a set of rules restored from a previous instance that can be
	// used until 'allowed' rules for an endpoint are first initialized after
	// a restart
	restored perEPRestored

	// mapping restored endpoint IP (both IPv4 and IPv6) to *Endpoint
	restoredEPs restoredEPs

	// rejectReply is the OPCode send from the DNS-proxy to the endpoint if the
	// DNS request is invalid
	rejectReply int32
}

// perEPAllow maps EndpointIDs to ports + selectors + rules
type perEPAllow map[uint64]portToSelectorAllow

// portToSelectorAllow maps port numbers to selectors + rules
type portToSelectorAllow map[uint16]CachedSelectorREEntry

// CachedSelectorREEntry maps port numbers to selectors to rules, mirroring
// policy.L7DataMap but the DNS rules are compiled into a single regexp
type CachedSelectorREEntry map[policy.CachedSelector]*regexp.Regexp

// structure for restored rules that can be used while Cilium agent is restoring endpoints
type perEPRestored map[uint64]restore.DNSRules

// map from EP IPs to *Endpoint
type restoredEPs map[string]*endpoint.Endpoint

// CheckRestored checks endpointID, destPort, destIP, and name against the restored rules,
// and only returns true if a restored rule matches.
func (p *DNSProxy) checkRestored(endpointID uint64, destPort uint16, destIP string, name string) bool {
	ipRules, exists := p.restored[endpointID][destPort]
	if !exists {
		return false
	}

	for i := range ipRules {
		if _, exists := ipRules[i].IPs[destIP]; (exists || ipRules[i].IPs == nil) && ipRules[i].Re.MatchString(name) {
			return true
		}
	}
	return false
}

// GetRules creates a fresh copy of EP's DNS rules to be stored
// for later restoration.
func (p *DNSProxy) GetRules(endpointID uint16) (restore.DNSRules, error) {
	p.RLock()
	defer p.RUnlock()

	restored := make(restore.DNSRules)
	for port, entries := range p.allowed[uint64(endpointID)] {
		var ipRules restore.IPRules
		for cs, regex := range entries {
			var IPs map[string]struct{}
			if !cs.IsWildcard() {
				IPs = make(map[string]struct{})
				count := 0
			Loop:
				for _, nid := range cs.GetSelections() {
					nidIPs := p.LookupIPsBySecID(nid)
					for _, ip := range nidIPs {
						// Skip IPs that are allowed but have never been used,
						// but only if at least one server has been used so far.
						if len(p.usedServers) > 0 {
							if _, used := p.usedServers[ip]; !used {
								continue
							}
						}
						IPs[ip] = struct{}{}
						count++
						if count > p.maxIPsPerRestoredDNSRule {
							log.WithFields(logrus.Fields{
								logfields.EndpointID:            endpointID,
								logfields.Port:                  port,
								logfields.EndpointLabelSelector: cs,
								logfields.Limit:                 p.maxIPsPerRestoredDNSRule,
								logfields.Count:                 len(nidIPs),
							}).Warning("Too many IPs for a DNS rule, skipping the rest")
							break Loop
						}
					}
				}
			}
			ipRules = append(ipRules, restore.IPRule{IPs: IPs, Re: restore.RuleRegex{Regexp: regex}})
		}
		restored[port] = ipRules
	}
	return restored, nil
}

// RestoreRules is used in the beginning of endpoint restoration to
// install rules saved before the restart to be used before the endpoint
// is regenerated.
// 'ep' passed in is not fully functional yet, but just unmarshaled from JSON!
func (p *DNSProxy) RestoreRules(ep *endpoint.Endpoint) {
	p.Lock()
	defer p.Unlock()
	if ep.IPv4.IsSet() {
		p.restoredEPs[ep.IPv4.String()] = ep
	}
	if ep.IPv6.IsSet() {
		p.restoredEPs[ep.IPv6.String()] = ep
	}
	p.restored[uint64(ep.ID)] = ep.DNSRules

	log.Debugf("Restored rules for endpoint %d: %v", ep.ID, ep.DNSRules)
}

// 'p' must be locked
func (p *DNSProxy) removeRestoredRulesLocked(endpointID uint64) {
	if _, exists := p.restored[endpointID]; exists {
		// Remove IP->ID mappings for the restored EP
		for ip, ep := range p.restoredEPs {
			if ep.ID == uint16(endpointID) {
				delete(p.restoredEPs, ip)
			}
		}
		delete(p.restored, endpointID)
	}
}

// RemoveRestoredRules removes all restored rules for 'endpointID'.
func (p *DNSProxy) RemoveRestoredRules(endpointID uint16) {
	p.Lock()
	defer p.Unlock()
	p.removeRestoredRulesLocked(uint64(endpointID))
}

// setPortRulesForID sets the matching rules for endpointID and destPort for
// later lookups. It converts newRules into a unified regexp that can be reused
// later.
func (allow perEPAllow) setPortRulesForID(endpointID uint64, destPort uint16, newRules policy.L7DataMap) error {
	// This is the delete case
	if len(newRules) == 0 {
		epPorts := allow[endpointID]
		delete(epPorts, destPort)
		if len(epPorts) == 0 {
			delete(allow, endpointID)
		}
		return nil
	}

	newRE, err := GetSelectorRegexMap(newRules)
	if err != nil {
		return err
	}

	epPorts, exist := allow[endpointID]
	if !exist {
		epPorts = make(portToSelectorAllow)
		allow[endpointID] = epPorts
	}

	epPorts[destPort] = newRE
	return nil
}

// setPortRulesForIDFromUnifiedFormat sets the matching rules for endpointID and destPort for
// later lookups.
func (allow perEPAllow) setPortRulesForIDFromUnifiedFormat(endpointID uint64, destPort uint16, newRules CachedSelectorREEntry) error {
	// This is the delete case
	if len(newRules) == 0 {
		epPorts := allow[endpointID]
		delete(epPorts, destPort)
		if len(epPorts) == 0 {
			delete(allow, endpointID)
		}
		return nil
	}

	epPorts, exist := allow[endpointID]
	if !exist {
		epPorts = make(portToSelectorAllow)
		allow[endpointID] = epPorts
	}

	epPorts[destPort] = newRules
	return nil
}

// getPortRulesForID returns a precompiled regex representing DNS rules for the
// passed-in endpointID and destPort with setPortRulesForID
func (allow perEPAllow) getPortRulesForID(endpointID uint64, destPort uint16) (rules CachedSelectorREEntry, exists bool) {
	rules, exists = allow[endpointID][destPort]
	return rules, exists
}

// LookupEndpointIDByIPFunc wraps logic to lookup an endpoint with any backend.
// See DNSProxy.LookupRegisteredEndpoint for usage.
type LookupEndpointIDByIPFunc func(ip net.IP) (endpoint *endpoint.Endpoint, err error)

// LookupSecIDByIPFunc Func wraps logic to lookup an IP's security ID from the
// ipcache.
// See DNSProxy.LookupSecIDByIP for usage.
type LookupSecIDByIPFunc func(ip net.IP) (secID ipcache.Identity, exists bool)

// LookupIPsBySecIDFunc Func wraps logic to lookup an IPs by security ID from the
// ipcache.
type LookupIPsBySecIDFunc func(nid identity.NumericIdentity) []string

// NotifyOnDNSMsgFunc handles propagating DNS response data
// See DNSProxy.LookupEndpointIDByIP for usage.
type NotifyOnDNSMsgFunc func(lookupTime time.Time, ep *endpoint.Endpoint, epIPPort string, serverID identity.NumericIdentity, serverAddr string, msg *dns.Msg, protocol string, allowed bool, stat *ProxyRequestContext) error

// errFailedAcquireSemaphore is an an error representing the DNS proxy's
// failure to acquire the semaphore. This is error is treated like a timeout.
type errFailedAcquireSemaphore struct {
	parallel int
}

func (e errFailedAcquireSemaphore) Timeout() bool { return true }

// Temporary is deprecated. Return false.
func (e errFailedAcquireSemaphore) Temporary() bool { return false }
func (e errFailedAcquireSemaphore) Error() string {
	return fmt.Sprintf(
		"failed to acquire DNS proxy semaphore, %d parallel requests already in-flight",
		e.parallel,
	)
}

// errTimedOutAcquireSemaphore is an an error representing the DNS proxy timing
// out when acquiring the semaphore. It is treated the same as
// errTimedOutAcquireSemaphore.
type errTimedOutAcquireSemaphore struct {
	errFailedAcquireSemaphore

	gracePeriod time.Duration
}

func (e errTimedOutAcquireSemaphore) Error() string {
	return fmt.Sprintf(
		"timed out after %v acquiring DNS proxy semaphore, %d parallel requests already in-flight",
		e.gracePeriod,
		e.parallel,
	)
}

// ProxyRequestContext proxy dns request context struct to send in the callback
type ProxyRequestContext struct {
	ProcessingTime spanstat.SpanStat // This is going to happen at the end of the second callback.
	// Error is a enum of [timeout, allow, denied, proxyerr].
	UpstreamTime         spanstat.SpanStat
	SemaphoreAcquireTime spanstat.SpanStat
	PolicyCheckTime      spanstat.SpanStat
	DataplaneTime        spanstat.SpanStat
	Success              bool
	Err                  error
}

// IsTimeout return true if the ProxyRequest timeout
func (proxyStat *ProxyRequestContext) IsTimeout() bool {
	var neterr net.Error
	if errors.As(proxyStat.Err, &neterr) {
		return neterr.Timeout()
	}
	return false
}

// StartDNSProxy starts a proxy used for DNS L7 redirects that listens on
// address and port.
// address is the bind address to listen on. Empty binds to all local
// addresses.
// port is the port to bind to for both UDP and TCP. 0 causes the kernel to
// select a free port.
// lookupEPFunc will be called with the source IP of DNS requests, and expects
// a unique identifier for the endpoint that made the request.
// notifyFunc will be called with DNS response data that is returned to a
// requesting endpoint. Note that denied requests will not trigger this
// callback.
func StartDNSProxy(address string, port uint16, enableDNSCompression bool, maxRestoreDNSIPs int, lookupEPFunc LookupEndpointIDByIPFunc, lookupSecIDFunc LookupSecIDByIPFunc, lookupIPsFunc LookupIPsBySecIDFunc, notifyFunc NotifyOnDNSMsgFunc, concurrencyLimit int) (*DNSProxy, error) {
	if err := re.InitRegexCompileLRU(option.Config.FQDNRegexCompileLRUSize); err != nil {
		return nil, fmt.Errorf("failed to start DNS proxy: %w", err)
	}

	if port == 0 {
		log.Debug("DNS Proxy port is configured to 0. A random port will be assigned by the OS.")
	}

	if lookupEPFunc == nil || notifyFunc == nil {
		return nil, errors.New("DNS proxy must have lookupEPFunc and notifyFunc provided")
	}

	p := &DNSProxy{
		LookupRegisteredEndpoint: lookupEPFunc,
		LookupSecIDByIP:          lookupSecIDFunc,
		LookupIPsBySecID:         lookupIPsFunc,
		NotifyOnDNSMsg:           notifyFunc,
		logLimiter:               logging.NewLimiter(10*time.Second, 1),
		lookupTargetDNSServer:    lookupTargetDNSServer,
		usedServers:              make(map[string]struct{}),
		allowed:                  make(perEPAllow),
		restored:                 make(perEPRestored),
		restoredEPs:              make(restoredEPs),
		EnableDNSCompression:     enableDNSCompression,
		maxIPsPerRestoredDNSRule: maxRestoreDNSIPs,
	}
	if concurrencyLimit > 0 {
		p.ConcurrencyLimit = semaphore.NewWeighted(int64(concurrencyLimit))
		p.ConcurrencyGracePeriod = option.Config.DNSProxyConcurrencyProcessingGracePeriod
	}
	atomic.StoreInt32(&p.rejectReply, dns.RcodeRefused)

	// Start the DNS listeners on UDP and TCP
	var (
		UDPConn     *net.UDPConn
		TCPListener *net.TCPListener
		err         error

		EnableIPv4, EnableIPv6 = option.Config.EnableIPv4, option.Config.EnableIPv6
	)

	start := time.Now()
	for time.Since(start) < ProxyBindTimeout {
		UDPConn, TCPListener, err = bindToAddr(address, port, EnableIPv4, EnableIPv6)
		if err == nil {
			break
		}
		log.WithError(err).Warnf("Attempt to bind DNS Proxy failed, retrying in %v", ProxyBindRetryInterval)
		time.Sleep(ProxyBindRetryInterval)
	}
	if err != nil {
		return nil, err
	}

	p.BindAddr = UDPConn.LocalAddr().String()
	p.BindPort = uint16(UDPConn.LocalAddr().(*net.UDPAddr).Port)
	p.UDPServer = &dns.Server{PacketConn: UDPConn, Addr: p.BindAddr, Net: "udp", Handler: p,
		SessionUDPFactory: &sessionUDPFactory{ipv4Enabled: EnableIPv4, ipv6Enabled: EnableIPv6},
	}
	p.TCPServer = &dns.Server{Listener: TCPListener, Addr: p.BindAddr, Net: "tcp", Handler: p}
	log.WithField("address", p.BindAddr).Debug("DNS Proxy bound to address")

	for _, s := range []*dns.Server{p.UDPServer, p.TCPServer} {
		go func(server *dns.Server) {
			// try 5 times during a single ProxyBindTimeout period. We fatal here
			// because we have no other way to indicate failure this late.
			start := time.Now()
			for time.Since(start) < ProxyBindTimeout {
				if err := server.ActivateAndServe(); err != nil {
					log.WithError(err).Errorf("Failed to start the %s DNS proxy on %s", server.Net, server.Addr)
				}
				time.Sleep(ProxyBindRetryInterval)
			}
			log.Fatalf("Failed to start %s DNS Proxy on %s", server.Net, server.Addr)
		}(s)
	}

	// Bind the DNS forwarding clients on UDP and TCP
	// Note: SingleInFlight should remain disabled. When enabled it folds DNS
	// retries into the previous lookup, suppressing them.
	p.UDPClient = &dns.Client{Net: "udp", Timeout: ProxyForwardTimeout, SingleInflight: false}
	p.TCPClient = &dns.Client{Net: "tcp", Timeout: ProxyForwardTimeout, SingleInflight: false}

	return p, nil
}

// LookupEndpointByIP wraps LookupRegisteredEndpoint by falling back to an restored EP, if available
func (p *DNSProxy) LookupEndpointByIP(ip net.IP) (endpoint *endpoint.Endpoint, err error) {
	endpoint, err = p.LookupRegisteredEndpoint(ip)
	if err != nil {
		// Check restored endpoints
		endpoint, found := p.restoredEPs[ip.String()]
		if found {
			return endpoint, nil
		}
	}
	return endpoint, err
}

// UpdateAllowed sets newRules for endpointID and destPort. It compiles the DNS
// rules into regexes that are then used in CheckAllowed.
func (p *DNSProxy) UpdateAllowed(endpointID uint64, destPort uint16, newRules policy.L7DataMap) error {
	p.Lock()
	defer p.Unlock()

	err := p.allowed.setPortRulesForID(endpointID, destPort, newRules)
	if err == nil {
		// Rules were updated based on policy, remove restored rules
		p.removeRestoredRulesLocked(endpointID)
	}
	return err
}

// UpdateAllowedFromSelectorRegexes sets newRules for endpointID and destPort.
func (p *DNSProxy) UpdateAllowedFromSelectorRegexes(endpointID uint64, destPort uint16, newRules CachedSelectorREEntry) error {
	p.Lock()
	defer p.Unlock()

	err := p.allowed.setPortRulesForIDFromUnifiedFormat(endpointID, destPort, newRules)
	if err == nil {
		// Rules were updated based on policy, remove restored rules
		p.removeRestoredRulesLocked(endpointID)
	}
	return err
}

// CheckAllowed checks endpointID, destPort, destID, destIP, and name against the rules
// added to the proxy or restored during restart, and only returns true if this all match
// something that was added (via UpdateAllowed or RestoreRules) previously.
func (p *DNSProxy) CheckAllowed(endpointID uint64, destPort uint16, destID identity.NumericIdentity, destIP net.IP, name string) (allowed bool, err error) {
	name = strings.ToLower(dns.Fqdn(name))
	p.RLock()
	defer p.RUnlock()

	epAllow, exists := p.allowed.getPortRulesForID(endpointID, destPort)
	if !exists {
		return p.checkRestored(endpointID, destPort, destIP.String(), name), nil
	}

	for selector, re := range epAllow {
		// The port was matched in getPortRulesForID, above.
		if selector.Selects(destID) && re.MatchString(name) {
			return true, nil
		}
	}

	return false, nil
}

// ServeDNS handles individual DNS requests forwarded to the proxy, and meets
// the dns.Handler interface.
// It will:
//  - Look up the endpoint that sent the request by IP, via LookupEndpointByIP.
//  - Look up the Sec ID of the destination server, via LookupSecIDByIP.
//  - Check that the endpoint ID, destination Sec ID, destination port and the
//  qname all match a rule. If not, the request is dropped.
//  - The allowed request is forwarded to the originally intended DNS server IP
//  - The response is shared via NotifyOnDNSMsg (this will go to a
//  fqdn/NameManager instance).
//  - Write the response to the endpoint.
func (p *DNSProxy) ServeDNS(w dns.ResponseWriter, request *dns.Msg) {
	requestID := request.Id // keep the original request ID
	qname := string(request.Question[0].Name)
	protocol := w.LocalAddr().Network()
	epIPPort := w.RemoteAddr().String()
	scopedLog := log.WithFields(logrus.Fields{
		logfields.DNSName:      qname,
		logfields.IPAddr:       epIPPort,
		logfields.DNSRequestID: requestID,
	})

	var stat ProxyRequestContext
	if p.ConcurrencyLimit != nil {
		// TODO: Consider plumbing the daemon context here.
		ctx, cancel := context.WithTimeout(context.TODO(), p.ConcurrencyGracePeriod)
		defer cancel()

		stat.SemaphoreAcquireTime.Start()
		// Enforce the concurrency limit by attempting to acquire the
		// semaphore.
		if err := p.enforceConcurrencyLimit(ctx); err != nil {
			stat.SemaphoreAcquireTime.End(false)
			if p.logLimiter.Allow() {
				scopedLog.WithError(err).Error("Dropping DNS request due to too many DNS requests already in-flight")
			}
			stat.Err = err
			p.NotifyOnDNSMsg(time.Now(), nil, epIPPort, 0, "", request, protocol, false, &stat)
			p.sendRefused(scopedLog, w, request)
			return
		}
		stat.SemaphoreAcquireTime.End(true)
		defer p.ConcurrencyLimit.Release(1)
	}
	stat.ProcessingTime.Start()

	scopedLog.Debug("Handling DNS query from endpoint")

	addr, _, err := net.SplitHostPort(epIPPort)
	if err != nil {
		scopedLog.WithError(err).Error("cannot extract endpoint IP from DNS request")
		stat.Err = fmt.Errorf("Cannot extract endpoint IP from DNS request: %w", err)
		stat.ProcessingTime.End(false)
		p.NotifyOnDNSMsg(time.Now(), nil, epIPPort, 0, "", request, protocol, false, &stat)
		p.sendRefused(scopedLog, w, request)
		return
	}
	ep, err := p.LookupEndpointByIP(net.ParseIP(addr))
	if err != nil {
		scopedLog.WithError(err).Error("cannot extract endpoint ID from DNS request")
		stat.Err = fmt.Errorf("Cannot extract endpoint ID from DNS request: %w", err)
		stat.ProcessingTime.End(false)
		p.NotifyOnDNSMsg(time.Now(), nil, epIPPort, 0, "", request, protocol, false, &stat)
		p.sendRefused(scopedLog, w, request)
		return
	}

	scopedLog = scopedLog.WithField(logfields.EndpointID, ep.StringID())

	targetServerIP, targetServerPort, targetServerAddr, err := p.lookupTargetDNSServer(w)
	if err != nil {
		log.WithError(err).Error("cannot extract destination IP:port from DNS request")
		stat.Err = fmt.Errorf("Cannot extract destination IP:port from DNS request: %w", err)
		stat.ProcessingTime.End(false)
		p.NotifyOnDNSMsg(time.Now(), ep, epIPPort, 0, targetServerAddr, request, protocol, false, &stat)
		p.sendRefused(scopedLog, w, request)
		return
	}

	targetServerID := identity.ReservedIdentityWorld
	if serverSecID, exists := p.LookupSecIDByIP(targetServerIP); !exists {
		scopedLog.WithField("server", targetServerAddr).Debug("cannot find server ip in ipcache, defaulting to WORLD")
	} else {
		targetServerID = serverSecID.ID
		scopedLog.WithField("server", targetServerAddr).Debugf("Found target server to of DNS request secID %+v", serverSecID)
	}

	// The allowed check is first because we don't want to use DNS responses that
	// endpoints are not allowed to see.
	// Note: The cache doesn't know about the source of the DNS data (yet) and so
	// it won't enforce any separation between results from different endpoints.
	// This isn't ideal but we are trusting the DNS responses anyway.
	stat.PolicyCheckTime.Start()
	allowed, err := p.CheckAllowed(uint64(ep.ID), targetServerPort, targetServerID, targetServerIP, qname)
	stat.PolicyCheckTime.End(err == nil)
	switch {
	case err != nil:
		scopedLog.WithError(err).Error("Rejecting DNS query from endpoint due to error")
		stat.Err = fmt.Errorf("Rejecting DNS query from endpoint due to error: %w", err)
		stat.ProcessingTime.End(false)
		p.NotifyOnDNSMsg(time.Now(), ep, epIPPort, targetServerID, targetServerAddr, request, protocol, false, &stat)
		p.sendRefused(scopedLog, w, request)
		return

	case !allowed:
		scopedLog.Debug("Rejecting DNS query from endpoint due to policy")
		stat.Err = p.sendRefused(scopedLog, w, request)
		stat.ProcessingTime.End(true)
		p.NotifyOnDNSMsg(time.Now(), ep, epIPPort, targetServerID, targetServerAddr, request, protocol, false, &stat)
		return
	}

	scopedLog.Debug("Forwarding DNS request for a name that is allowed")
	p.NotifyOnDNSMsg(time.Now(), ep, epIPPort, targetServerID, targetServerAddr, request, protocol, true, &stat)

	// Keep the same L4 protocol. This handles DNS re-requests over TCP, for
	// requests that were too large for UDP.
	var client *dns.Client
	switch protocol {
	case "udp":
		client = p.UDPClient
	case "tcp":
		client = p.TCPClient
	default:
		scopedLog.Error("Cannot parse DNS proxy client network to select forward client")
		stat.Err = fmt.Errorf("Cannot parse DNS proxy client network to select forward client: %w", err)
		stat.ProcessingTime.End(false)
		p.NotifyOnDNSMsg(time.Now(), ep, epIPPort, targetServerID, targetServerAddr, request, protocol, false, &stat)
		p.sendRefused(scopedLog, w, request)
		return
	}
	stat.ProcessingTime.End(true)
	stat.UpstreamTime.Start()

	request.Id = dns.Id() // force a random new ID for this request
	response, _, err := client.Exchange(request, targetServerAddr)
	stat.UpstreamTime.End(err == nil)
	if err != nil {
		stat.Err = err
		if stat.IsTimeout() {
			scopedLog.WithError(err).Warn("Timeout waiting for response to forwarded proxied DNS lookup")
		} else {
			scopedLog.WithError(err).Error("Cannot forward proxied DNS lookup")
			p.sendRefused(scopedLog, w, request)
			stat.Err = fmt.Errorf("Cannot forward proxied DNS lookup: %w", err)
		}
		p.NotifyOnDNSMsg(time.Now(), ep, epIPPort, targetServerID, targetServerAddr, request, protocol, false, &stat)
		return
	}

	scopedLog.WithField(logfields.Response, response).Debug("Received DNS response to proxied lookup")
	stat.Success = true

	scopedLog.Debug("Notifying with DNS response to original DNS query")
	p.NotifyOnDNSMsg(time.Now(), ep, epIPPort, targetServerID, targetServerAddr, response, protocol, true, &stat)

	scopedLog.Debug("Responding to original DNS query")
	// restore the ID to the one in the initial request so it matches what the requester expects.
	response.Id = requestID
	response.Compress = p.EnableDNSCompression && shouldCompressResponse(request, response)
	err = w.WriteMsg(response)
	if err != nil {
		scopedLog.WithError(err).Error("Cannot forward proxied DNS response")
		stat.Err = fmt.Errorf("Cannot forward proxied DNS response: %w", err)
		p.NotifyOnDNSMsg(time.Now(), ep, epIPPort, targetServerID, targetServerAddr, response, protocol, true, &stat)
	} else {
		p.Lock()
		// Add the server to the set of used DNS servers. This set is never GCd, but is limited by set
		// of DNS server IPs that are allowed by a policy and for which successful response was received.
		p.usedServers[targetServerIP.String()] = struct{}{}
		p.Unlock()
	}
}

func (p *DNSProxy) enforceConcurrencyLimit(ctx context.Context) error {
	if p.ConcurrencyGracePeriod == 0 {
		// No grace time configured. Failing to acquire semaphore means
		// immediately give up.
		if !p.ConcurrencyLimit.TryAcquire(1) {
			return errFailedAcquireSemaphore{
				parallel: option.Config.DNSProxyConcurrencyLimit,
			}
		}
	} else if err := p.ConcurrencyLimit.Acquire(ctx, 1); err != nil && errors.Is(err, context.DeadlineExceeded) {
		// We ignore err because errTimedOutAcquireSemaphore implements the
		// net.Error interface deeming it a timeout error which will be
		// treated the same as context.DeadlineExceeded.
		return errTimedOutAcquireSemaphore{
			errFailedAcquireSemaphore: errFailedAcquireSemaphore{
				parallel: option.Config.DNSProxyConcurrencyLimit,
			},
			gracePeriod: p.ConcurrencyGracePeriod,
		}
	}
	return nil
}

// sendRefused creates and sends a REFUSED response for request to w
// The returned error is logged with scopedLog and is returned for convenience
func (p *DNSProxy) sendRefused(scopedLog *logrus.Entry, w dns.ResponseWriter, request *dns.Msg) (err error) {
	refused := new(dns.Msg)
	refused.SetRcode(request, int(atomic.LoadInt32(&p.rejectReply)))

	if err = w.WriteMsg(refused); err != nil {
		scopedLog.WithError(err).Error("Cannot send REFUSED response")
		err = fmt.Errorf("cannot send REFUSED response: %w", err)
	}
	return err
}

// SetRejectReply sets the default reject reply on denied dns responses.
func (p *DNSProxy) SetRejectReply(opt string) {
	switch strings.ToLower(opt) {
	case strings.ToLower(option.FQDNProxyDenyWithNameError):
		atomic.StoreInt32(&p.rejectReply, dns.RcodeNameError)
	case strings.ToLower(option.FQDNProxyDenyWithRefused):
		atomic.StoreInt32(&p.rejectReply, dns.RcodeRefused)
	default:
		log.Infof("DNS reject response '%s' is not valid, available options are '%v'",
			opt, option.FQDNRejectOptions)
		return
	}
}

func (p *DNSProxy) GetBindPort() uint16 {
	return p.BindPort
}

// ExtractMsgDetails extracts a canonical query name, any IPs in a response,
// the lowest applicable TTL, rcode, anwer rr types and question types
// When a CNAME is returned the chain is collapsed down, keeping the lowest TTL,
// and CNAME targets are returned.
func ExtractMsgDetails(msg *dns.Msg) (qname string, responseIPs []net.IP, TTL uint32, CNAMEs []string, rcode int, answerTypes []uint16, qTypes []uint16, err error) {
	if len(msg.Question) == 0 {
		return "", nil, 0, nil, 0, nil, nil, errors.New("Invalid DNS message")
	}
	qname = strings.ToLower(string(msg.Question[0].Name))

	// rrName is the name the next RR should include.
	// This will change when we see CNAMEs.
	rrName := strings.ToLower(qname)

	TTL = math.MaxUint32 // a TTL must exist in the RRs

	answerTypes = make([]uint16, 0, len(msg.Answer))
	for _, ans := range msg.Answer {
		// Ensure we have records for DNS names we expect
		if strings.ToLower(ans.Header().Name) != rrName {
			return qname, nil, 0, nil, 0, nil, nil, fmt.Errorf("Unexpected name (%s) in RRs for %s (query for %s)", ans, rrName, qname)
		}

		// Handle A, AAAA and CNAME records by accumulating IPs and lowest TTL
		switch ans := ans.(type) {
		case *dns.A:
			responseIPs = append(responseIPs, ans.A)
			if TTL > ans.Hdr.Ttl {
				TTL = ans.Hdr.Ttl
			}
		case *dns.AAAA:
			responseIPs = append(responseIPs, ans.AAAA)
			if TTL > ans.Hdr.Ttl {
				TTL = ans.Hdr.Ttl
			}
		case *dns.CNAME:
			// We still track the TTL because the lowest TTL in the chain
			// determines the valid caching time for the whole response.
			if TTL > ans.Hdr.Ttl {
				TTL = ans.Hdr.Ttl
			}
			rrName = strings.ToLower(ans.Target)
			CNAMEs = append(CNAMEs, ans.Target)
		}
		answerTypes = append(answerTypes, ans.Header().Rrtype)
	}

	qTypes = make([]uint16, 0, len(msg.Question))
	for _, q := range msg.Question {
		qTypes = append(qTypes, q.Qtype)
	}

	return qname, responseIPs, TTL, CNAMEs, msg.Rcode, answerTypes, qTypes, nil
}

// bindToAddr attempts to bind to address and port for both UDP and TCP. If
// port is 0 a random open port is assigned and the same one is used for UDP
// and TCP.
// Note: This mimics what the dns package does EXCEPT for setting reuseport.
// This is ok for now but it would simplify proxy management in the future to
// have it set.
func bindToAddr(address string, port uint16, ipv4, ipv6 bool) (*net.UDPConn, *net.TCPListener, error) {
	var err error
	var listener net.Listener
	var conn net.PacketConn
	defer func() {
		if err != nil {
			if listener != nil {
				listener.Close()
			}
			if conn != nil {
				conn.Close()
			}
		}
	}()

	bindAddr := net.JoinHostPort(address, strconv.Itoa(int(port)))

	listener, err = listenConfig(linux_defaults.MagicMarkEgress, ipv4, ipv6).Listen(context.Background(),
		"tcp", bindAddr)
	if err != nil {
		return nil, nil, err
	}

	conn, err = listenConfig(linux_defaults.MagicMarkEgress, ipv4, ipv6).ListenPacket(context.Background(),
		"udp", listener.Addr().String())
	if err != nil {
		return nil, nil, err
	}

	return conn.(*net.UDPConn), listener.(*net.TCPListener), nil
}

// shouldCompressResponse returns true when the response needs to be compressed
// for a given request.
// Originally, DNS was limited to 512 byte responses. EDNS0 allows for larger
// sizes. In either case, responses can apply DNS compression, and the original
// RFCs require clients to accept this. In miekg/dns there is a comment that BIND
// does not support compression, so we retain the ability to suppress this.
func shouldCompressResponse(request, response *dns.Msg) bool {
	ednsOptions := request.IsEdns0()
	responseLenNoCompression := response.Len()

	switch {
	case ednsOptions != nil && responseLenNoCompression > int(ednsOptions.UDPSize()): // uint16 -> int cast should always be safe
		return true
	case responseLenNoCompression > 512:
		return true
	}

	return false
}

func GetSelectorRegexMap(l7 policy.L7DataMap) (CachedSelectorREEntry, error) {
	newRE := make(CachedSelectorREEntry)
	for selector, l7Rules := range l7 {
		if l7Rules == nil {
			l7Rules = &policy.PerSelectorPolicy{L7Rules: api.L7Rules{DNS: []api.PortRuleDNS{{MatchPattern: "*"}}}}
		}
		reStrings := make([]string, 0, len(l7Rules.DNS))
		for _, dnsRule := range l7Rules.DNS {
			if len(dnsRule.MatchName) > 0 {
				dnsRuleName := strings.ToLower(dns.Fqdn(dnsRule.MatchName))
				dnsPatternAsRE := matchpattern.ToRegexp(dnsRuleName)
				reStrings = append(reStrings, "("+dnsPatternAsRE+")")
			}
			if len(dnsRule.MatchPattern) > 0 {
				dnsPattern := matchpattern.Sanitize(dnsRule.MatchPattern)
				dnsPatternAsRE := matchpattern.ToRegexp(dnsPattern)
				reStrings = append(reStrings, "("+dnsPatternAsRE+")")
			}
		}
		mp := strings.Join(reStrings, "|")
		rei, err := re.CompileRegex(mp)
		if err != nil {
			return nil, err
		}
		newRE[selector] = rei
	}

	return newRE, nil
}
