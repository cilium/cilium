// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dnsproxy

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/semaphore"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn/matchpattern"
	"github.com/cilium/cilium/pkg/fqdn/re"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/identity"
	ippkg "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
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

	// DNSServers are the miekg/dns server instances.
	// Depending on the configuration, these might be
	// TCPv4, UDPv4, TCPv6 and/or UDPv4.
	// They handle DNS parsing etc. for us.
	DNSServers []*dns.Server

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
	// Note: Simple DNS names, e.g. bar.foo.com, will treat the "." as a literal.
	allowed perEPAllow

	// restored is a set of rules restored from a previous instance that can be
	// used until 'allowed' rules for an endpoint are first initialized after
	// a restart
	restored perEPRestored

	// cache is an internal structure to keep track of all the in use DNS rules. We do that
	// so that we avoid storing multiple similar versions of the same rules, so that we can improve
	// performance and reduce memory consumption when multiple endpoints or ports have similar rules.
	cache regexCache

	// mapping restored endpoint IP (both IPv4 and IPv6) to *Endpoint
	restoredEPs restoredEPs

	// rejectReply is the OPCode send from the DNS-proxy to the endpoint if the
	// DNS request is invalid
	rejectReply int32

	// UnbindAddress unbinds dns servers from socket in order to stop serving DNS traffic before proxy shutdown
	unbindAddress func()
}

// regexCacheEntry is a lookup entry used to cache a compiled regex
// and how many references it has
type regexCacheEntry struct {
	regex          *regexp.Regexp
	referenceCount int
}

// regexCache is a reference counted cache used for reusing the compiled regex when multiple policies
// have the same set of rules, or the same rule applies to multiple endpoints.
type regexCache map[string]*regexCacheEntry

// perEPAllow maps EndpointIDs to ports + selectors + rules
type perEPAllow map[uint64]portToSelectorAllow

// portToSelectorAllow maps port numbers to selectors + rules
type portToSelectorAllow map[uint16]CachedSelectorREEntry

// CachedSelectorREEntry maps port numbers to selectors to rules, mirroring
// policy.L7DataMap but the DNS rules are compiled into a regex
type CachedSelectorREEntry map[policy.CachedSelector]*regexp.Regexp

// structure for restored rules that can be used while Cilium agent is restoring endpoints
type perEPRestored map[uint64]map[uint16][]restoredIPRule

// restoredIPRule is the dnsproxy internal way of representing a restored IPRule
// where we also store the actual compiled regular expression as a, as well
// as the original restored IPRule
type restoredIPRule struct {
	restore.IPRule
	regex *regexp.Regexp
}

// map from EP IPs to *Endpoint
type restoredEPs map[string]*endpoint.Endpoint

// asIPRule returns a new restore.IPRule representing the rules, including the provided IP map.
func asIPRule(r *regexp.Regexp, IPs map[string]struct{}) restore.IPRule {
	pattern := "^-$"
	if r != nil {
		pattern = r.String()
	}
	return restore.IPRule{IPs: IPs, Re: restore.RuleRegex{Pattern: &pattern}}
}

// CheckRestored checks endpointID, destPort, destIP, and name against the restored rules,
// and only returns true if a restored rule matches.
func (p *DNSProxy) checkRestored(endpointID uint64, destPort uint16, destIP string, name string) bool {
	ipRules, exists := p.restored[endpointID][destPort]
	if !exists {
		return false
	}

	for i := range ipRules {
		ipRule := ipRules[i]
		if _, exists := ipRule.IPs[destIP]; exists || ipRule.IPs == nil {
			if ipRule.regex != nil && ipRule.regex.MatchString(name) {
				return true
			}
		}
	}
	return false
}

// skipIPInRestorationRLocked skips IPs that are allowed but have never been used,
// but only if at least one server has been used so far.
// Requires the RLock to be held.
func (p *DNSProxy) skipIPInRestorationRLocked(ip string) bool {
	if len(p.usedServers) > 0 {
		if _, used := p.usedServers[ip]; !used {
			return true
		}
	}
	return false
}

// GetRules creates a fresh copy of EP's DNS rules to be stored
// for later restoration.
func (p *DNSProxy) GetRules(endpointID uint16) (restore.DNSRules, error) {
	// Lock ordering note: Acquiring the IPCache read lock (as LookupIPsBySecID does) while holding
	// the proxy lock can lead to a deadlock. Avoid this by reading the state from DNSProxy while
	// holding the read lock, then perform the IPCache lookups.
	// Note that IPCache state may change in between calls to LookupIPsBySecID.
	p.RLock()

	type selRegex struct {
		re *regexp.Regexp
		cs policy.CachedSelector
	}

	portToSelRegex := make(map[uint16][]selRegex)
	for port, entries := range p.allowed[uint64(endpointID)] {
		var nidRules = make([]selRegex, 0, len(entries))
		// Copy the entries to avoid racy map accesses after we release the lock. We don't need
		// constant time access, hence a preallocated slice instead of another map.
		for cs, regex := range entries {
			nidRules = append(nidRules, selRegex{cs: cs, re: regex})
		}
		portToSelRegex[port] = nidRules
	}

	// We've read what we need from the proxy. The following IPCache lookups _must_ occur outside of
	// the critical section.
	p.RUnlock()

	restored := make(restore.DNSRules)
	for port, selRegexes := range portToSelRegex {
		var ipRules restore.IPRules
		for _, selRegex := range selRegexes {
			if selRegex.cs.IsWildcard() {
				ipRules = append(ipRules, asIPRule(selRegex.re, nil))
				continue
			}
			ips := make(map[string]struct{})
			count := 0
			nids := selRegex.cs.GetSelections()
		Loop:
			for _, nid := range nids {
				// Note: p.RLock must not be held during this call to IPCache
				nidIPs := p.LookupIPsBySecID(nid)
				p.RLock()
				for _, ip := range nidIPs {
					if p.skipIPInRestorationRLocked(ip) {
						continue
					}
					ips[ip] = struct{}{}
					count++
					if count > p.maxIPsPerRestoredDNSRule {
						log.WithFields(logrus.Fields{
							logfields.EndpointID:            endpointID,
							logfields.Port:                  port,
							logfields.EndpointLabelSelector: selRegex.cs,
							logfields.Limit:                 p.maxIPsPerRestoredDNSRule,
							logfields.Count:                 len(nidIPs),
						}).Warning("Too many IPs for a DNS rule, skipping the rest")
						p.RUnlock()
						break Loop
					}
				}
				p.RUnlock()
			}
			ipRules = append(ipRules, asIPRule(selRegex.re, ips))
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
	if ep.IPv4.IsValid() {
		p.restoredEPs[ep.IPv4.String()] = ep
	}
	if ep.IPv6.IsValid() {
		p.restoredEPs[ep.IPv6.String()] = ep
	}
	restoredRules := make(map[uint16][]restoredIPRule, len(ep.DNSRules))
	for port, dnsRule := range ep.DNSRules {
		ipRules := make([]restoredIPRule, 0, len(dnsRule))
		for _, ipRule := range dnsRule {
			if ipRule.Re.Pattern == nil {
				continue
			}
			regex, err := p.cache.lookupOrCompileRegex(*ipRule.Re.Pattern)
			if err != nil {
				log.WithFields(logrus.Fields{
					logfields.EndpointID: ep.ID,
					logfields.Rule:       *ipRule.Re.Pattern,
				}).Info("Disregarding restored DNS rule due to failure in compiling regex. Traffic to the FQDN may be disrupted.")
				continue
			}
			rule := restoredIPRule{
				IPRule: ipRule,
				regex:  regex,
			}
			ipRules = append(ipRules, rule)
		}
		restoredRules[port] = ipRules
	}
	p.restored[uint64(ep.ID)] = restoredRules

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
		for _, rule := range p.restored[endpointID] {
			for _, r := range rule {
				p.cache.releaseRegex(r.regex)
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

// lookupOrCompileRegex will check if the pattern is already compiled and present in another policy, and
// will reuse it in order to reduce memory consumption. The usage is reference counted, so all calls where
// lookupOrCompileRegex returns no error, a subsequent call to release it via releaseRegex has to
// be done when it's no longer being used by the policy.
func (c regexCache) lookupOrCompileRegex(pattern string) (*regexp.Regexp, error) {
	if entry, ok := c[pattern]; ok {
		entry.referenceCount += 1
		return entry.regex, nil
	}
	regex, err := re.CompileRegex(pattern)
	if err != nil {
		return nil, err
	}
	c[pattern] = &regexCacheEntry{regex: regex, referenceCount: 1}
	return regex, nil
}

// lookupOrInsertRegex is equivalent to lookupOrCompileRegex, but a compiled regex is provided
// instead of the pattern. In case a compiled regex with the same pattern as the provided regex is already present in
// the cache, the already present regex will be returned. By doing that, the duplicate can be garbage collected in case
// there are no other references to it. Trying to insert a nil value is a noop and will return nil
func (c regexCache) lookupOrInsertRegex(regex *regexp.Regexp) *regexp.Regexp {
	if regex == nil {
		return nil
	}
	pattern := regex.String()
	if entry, ok := c[pattern]; ok {
		entry.referenceCount += 1
		return entry.regex
	}
	c[pattern] = &regexCacheEntry{regex: regex, referenceCount: 1}
	return regex
}

// releaseRegex releases the provided regex. In case there are no longer any references to it,
// it will be freed. Running release on a nil value is a noop.
func (c regexCache) releaseRegex(regex *regexp.Regexp) {
	if regex == nil {
		return
	}
	pattern := regex.String()
	if indexEntry, ok := c[pattern]; ok {
		switch indexEntry.referenceCount {
		case 1:
			delete(c, pattern)
		default:
			indexEntry.referenceCount -= 1
		}
	}
}

// removeAndReleasePortRulesForID removes the old port rules for the given destPort on the given endpointID. It also
// releases the regexes so that unused regex can be freed from memory.
func (allow perEPAllow) removeAndReleasePortRulesForID(cache regexCache, endpointID uint64, destPort uint16) {
	epPorts, hasEpPorts := allow[endpointID]
	if !hasEpPorts {
		return
	}
	for _, m := range epPorts[destPort] {
		cache.releaseRegex(m)
	}
	delete(epPorts, destPort)
	if len(epPorts) == 0 {
		delete(allow, endpointID)
	}
}

// setPortRulesForID sets the matching rules for endpointID and destPort for
// later lookups. It converts newRules into a compiled regex
func (allow perEPAllow) setPortRulesForID(cache regexCache, endpointID uint64, destPort uint16, newRules policy.L7DataMap) error {
	if len(newRules) == 0 {
		allow.removeAndReleasePortRulesForID(cache, endpointID, destPort)
		return nil
	}
	cse := make(CachedSelectorREEntry, len(newRules))
	var err error
	for selector, newRuleset := range newRules {
		pattern := GeneratePattern(newRuleset)

		var regex *regexp.Regexp
		regex, err = cache.lookupOrCompileRegex(pattern)
		if err != nil {
			break
		}
		cse[selector] = regex
	}
	if err != nil {
		// Unregister the registered regexes before returning the error to avoid
		// leaving unused references in the cache
		for k, regex := range cse {
			cache.releaseRegex(regex)
			delete(cse, k)
		}
		return err
	}
	allow.removeAndReleasePortRulesForID(cache, endpointID, destPort)
	epPorts, exist := allow[endpointID]
	if !exist {
		epPorts = make(portToSelectorAllow)
		allow[endpointID] = epPorts
	}
	epPorts[destPort] = cse
	return nil
}

// setPortRulesForIDFromUnifiedFormat sets the matching rules for endpointID and destPort for
// later lookups. It does not guarantee it will reuse all the provided regexes, since it will reuse
// already existing regexes with the same pattern in case they are already in use.
func (allow perEPAllow) setPortRulesForIDFromUnifiedFormat(cache regexCache, endpointID uint64, destPort uint16, newRules CachedSelectorREEntry) error {
	if len(newRules) == 0 {
		allow.removeAndReleasePortRulesForID(cache, endpointID, destPort)
		return nil
	}
	cse := make(CachedSelectorREEntry, len(newRules))
	for selector, providedRegex := range newRules {
		// In case the regex is already compiled and in use in another regex, lookupOrInsertRegex
		// will return a ref. to the existing regex, and use that one.
		cse[selector] = cache.lookupOrInsertRegex(providedRegex)
	}

	allow.removeAndReleasePortRulesForID(cache, endpointID, destPort)
	epPorts, exist := allow[endpointID]
	if !exist {
		epPorts = make(portToSelectorAllow)
		allow[endpointID] = epPorts
	}
	epPorts[destPort] = cse
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
type LookupSecIDByIPFunc func(ip netip.Addr) (secID ipcache.Identity, exists bool)

// LookupIPsBySecIDFunc Func wraps logic to lookup an IPs by security ID from the
// ipcache.
type LookupIPsBySecIDFunc func(nid identity.NumericIdentity) []string

// NotifyOnDNSMsgFunc handles propagating DNS response data
// See DNSProxy.LookupEndpointIDByIP for usage.
type NotifyOnDNSMsgFunc func(lookupTime time.Time, ep *endpoint.Endpoint, epIPPort string, serverID identity.NumericIdentity, serverAddr string, msg *dns.Msg, protocol string, allowed bool, stat *ProxyRequestContext) error

// ErrFailedAcquireSemaphore is an an error representing the DNS proxy's
// failure to acquire the semaphore. This is error is treated like a timeout.
type ErrFailedAcquireSemaphore struct {
	parallel int
}

func (e ErrFailedAcquireSemaphore) Timeout() bool { return true }

// Temporary is deprecated. Return false.
func (e ErrFailedAcquireSemaphore) Temporary() bool { return false }
func (e ErrFailedAcquireSemaphore) Error() string {
	return fmt.Sprintf(
		"failed to acquire DNS proxy semaphore, %d parallel requests already in-flight",
		e.parallel,
	)
}

// ErrTimedOutAcquireSemaphore is an an error representing the DNS proxy timing
// out when acquiring the semaphore. It is treated the same as
// ErrTimedOutAcquireSemaphore.
type ErrTimedOutAcquireSemaphore struct {
	ErrFailedAcquireSemaphore

	gracePeriod time.Duration
}

func (e ErrTimedOutAcquireSemaphore) Error() string {
	return fmt.Sprintf(
		"timed out after %v acquiring DNS proxy semaphore, %d parallel requests already in-flight",
		e.gracePeriod,
		e.parallel,
	)
}

// ErrDNSRequestNoEndpoint represents an error when the local daemon cannot
// find the corresponding endpoint that triggered a DNS request processed by
// the local DNS proxy (FQDN proxy).
type ErrDNSRequestNoEndpoint struct{}

func (ErrDNSRequestNoEndpoint) Error() string {
	return "DNS request cannot be associated with an existing endpoint"
}

// ProxyRequestContext proxy dns request context struct to send in the callback
type ProxyRequestContext struct {
	TotalTime      spanstat.SpanStat
	ProcessingTime spanstat.SpanStat // This is going to happen at the end of the second callback.
	// Error is a enum of [timeout, allow, denied, proxyerr].
	UpstreamTime         spanstat.SpanStat
	SemaphoreAcquireTime spanstat.SpanStat
	PolicyCheckTime      spanstat.SpanStat
	PolicyGenerationTime spanstat.SpanStat
	DataplaneTime        spanstat.SpanStat
	Success              bool
	Err                  error
	DataSource           accesslog.DNSDataSource
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
func StartDNSProxy(
	address string, port uint16, enableDNSCompression bool, maxRestoreDNSIPs int,
	lookupEPFunc LookupEndpointIDByIPFunc,
	lookupSecIDFunc LookupSecIDByIPFunc,
	lookupIPsFunc LookupIPsBySecIDFunc,
	notifyFunc NotifyOnDNSMsgFunc,
	concurrencyLimit int, concurrencyGracePeriod time.Duration,
) (*DNSProxy, error) {
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
		cache:                    make(regexCache),
		EnableDNSCompression:     enableDNSCompression,
		maxIPsPerRestoredDNSRule: maxRestoreDNSIPs,
	}
	if concurrencyLimit > 0 {
		p.ConcurrencyLimit = semaphore.NewWeighted(int64(concurrencyLimit))
		p.ConcurrencyGracePeriod = concurrencyGracePeriod
	}
	atomic.StoreInt32(&p.rejectReply, dns.RcodeRefused)

	// Start the DNS listeners on UDP and TCP for IPv4 and/or IPv6
	var (
		dnsServers []*dns.Server
		bindPort   uint16
		err        error
	)

	start := time.Now()
	for time.Since(start) < ProxyBindTimeout {
		dnsServers, bindPort, err = bindToAddr(address, port, p, option.Config.EnableIPv4, option.Config.EnableIPv6)
		if err == nil {
			break
		}
		log.WithError(err).Warnf("Attempt to bind DNS Proxy failed, retrying in %v", ProxyBindRetryInterval)
		time.Sleep(ProxyBindRetryInterval)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to bind DNS proxy: %w", err)
	}

	p.BindPort = bindPort
	p.DNSServers = dnsServers

	log.WithField("port", bindPort).WithField("addresses", len(dnsServers)).Debug("DNS Proxy bound to addresses")

	for _, s := range p.DNSServers {
		go func(server *dns.Server) {
			// try 5 times during a single ProxyBindTimeout period. We fatal here
			// because we have no other way to indicate failure this late.
			start := time.Now()
			var err error
			for time.Since(start) < ProxyBindTimeout {
				log.Debugf("Trying to start the %s DNS proxy on %s", server.Net, server.Addr)

				if err = server.ActivateAndServe(); err != nil {
					log.WithError(err).Errorf("Failed to start the %s DNS proxy on %s", server.Net, server.Addr)
					time.Sleep(ProxyBindRetryInterval)
					continue
				}
				break // successful shutdown before timeout
			}
			if err != nil {
				log.WithError(err).Fatalf("Failed to start the %s DNS proxy on %s", server.Net, server.Addr)
			}
		}(s)
	}

	// This function is called in proxy.Cleanup, which is added to Daemon cleanup module in bootstrapFQDN
	p.unbindAddress = func() { shutdownServers(p.DNSServers) }

	return p, nil
}

func shutdownServers(dnsServers []*dns.Server) {
	for _, s := range dnsServers {
		if err := s.Shutdown(); err != nil {
			log.WithError(err).Errorf("Failed to stop the %s DNS proxy on %s", s.Net, s.Addr)
		}
	}
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

	err := p.allowed.setPortRulesForID(p.cache, endpointID, destPort, newRules)
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

	err := p.allowed.setPortRulesForIDFromUnifiedFormat(p.cache, endpointID, destPort, newRules)
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

	for selector, regex := range epAllow {
		// The port was matched in getPortRulesForID, above.
		if regex != nil && selector.Selects(destID) && (regex.String() == matchpattern.MatchAllAnchoredPattern || regex.MatchString(name)) {
			return true, nil
		}
	}

	return false, nil
}

func setSoMark(fd int, secId identity.NumericIdentity) error {
	mark := linux_defaults.MagicMarkIdentity
	mark |= int(uint32(secId&0xFFFF)<<16 | uint32((secId&0xFF0000)>>16))
	err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, mark)
	if err != nil {
		return fmt.Errorf("error setting SO_MARK: %w", err)
	}
	return nil
}

// ServeDNS handles individual DNS requests forwarded to the proxy, and meets
// the dns.Handler interface.
// It will:
//   - Look up the endpoint that sent the request by IP, via LookupEndpointByIP.
//   - Look up the Sec ID of the destination server, via LookupSecIDByIP.
//   - Check that the endpoint ID, destination Sec ID, destination port and the
//     qname all match a rule. If not, the request is dropped.
//   - The allowed request is forwarded to the originally intended DNS server IP
//   - The response is shared via NotifyOnDNSMsg (this will go to a
//     fqdn/NameManager instance).
//   - Write the response to the endpoint.
func (p *DNSProxy) ServeDNS(w dns.ResponseWriter, request *dns.Msg) {
	stat := ProxyRequestContext{DataSource: accesslog.DNSSourceProxy}
	stat.TotalTime.Start()
	requestID := request.Id // keep the original request ID
	qname := string(request.Question[0].Name)
	protocol := w.LocalAddr().Network()
	epIPPort := w.RemoteAddr().String()
	scopedLog := log.WithFields(logrus.Fields{
		logfields.DNSName:      qname,
		logfields.IPAddr:       epIPPort,
		logfields.DNSRequestID: requestID,
	})

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

	scopedLog = scopedLog.WithFields(logrus.Fields{
		logfields.EndpointID: ep.StringID(),
		logfields.Identity:   ep.GetIdentity(),
	})

	targetServerIP, targetServerPort, targetServerAddrStr, err := p.lookupTargetDNSServer(w)
	if err != nil {
		log.WithError(err).Error("cannot extract destination IP:port from DNS request")
		stat.Err = fmt.Errorf("Cannot extract destination IP:port from DNS request: %w", err)
		stat.ProcessingTime.End(false)
		p.NotifyOnDNSMsg(time.Now(), ep, epIPPort, 0, targetServerAddrStr, request, protocol, false, &stat)
		p.sendRefused(scopedLog, w, request)
		return
	}

	targetServerID := identity.ReservedIdentityWorld
	// Ignore invalid IP - getter will handle invalid value.
	targetServerAddr, _ := ippkg.AddrFromIP(targetServerIP)
	if serverSecID, exists := p.LookupSecIDByIP(targetServerAddr); !exists {
		scopedLog.WithField("server", targetServerAddrStr).Debug("cannot find server ip in ipcache, defaulting to WORLD")
	} else {
		targetServerID = serverSecID.ID
		scopedLog.WithField("server", targetServerAddrStr).Debugf("Found target server to of DNS request secID %+v", serverSecID)
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
		p.NotifyOnDNSMsg(time.Now(), ep, epIPPort, targetServerID, targetServerAddrStr, request, protocol, false, &stat)
		p.sendRefused(scopedLog, w, request)
		return

	case !allowed:
		scopedLog.Debug("Rejecting DNS query from endpoint due to policy")
		// Send refused msg before calling NotifyOnDNSMsg() because we know
		// that this DNS request is rejected anyway. NotifyOnDNSMsg depends on
		// stat.Err field to be set in order to propagate the correct
		// information for metrics.
		stat.Err = p.sendRefused(scopedLog, w, request)
		stat.ProcessingTime.End(true)
		p.NotifyOnDNSMsg(time.Now(), ep, epIPPort, targetServerID, targetServerAddrStr, request, protocol, false, &stat)
		return
	}

	scopedLog.Debug("Forwarding DNS request for a name that is allowed")
	p.NotifyOnDNSMsg(time.Now(), ep, epIPPort, targetServerID, targetServerAddrStr, request, protocol, true, &stat)

	// Keep the same L4 protocol. This handles DNS re-requests over TCP, for
	// requests that were too large for UDP.
	var client *dns.Client
	switch protocol {
	case "udp":
		client = &dns.Client{Net: "udp", Timeout: ProxyForwardTimeout, SingleInflight: false}
	case "tcp":
		client = &dns.Client{Net: "tcp", Timeout: ProxyForwardTimeout, SingleInflight: false}
	default:
		scopedLog.Error("Cannot parse DNS proxy client network to select forward client")
		stat.Err = fmt.Errorf("Cannot parse DNS proxy client network to select forward client: %w", err)
		stat.ProcessingTime.End(false)
		p.NotifyOnDNSMsg(time.Now(), ep, epIPPort, targetServerID, targetServerAddrStr, request, protocol, false, &stat)
		p.sendRefused(scopedLog, w, request)
		return
	}
	stat.ProcessingTime.End(true)
	stat.UpstreamTime.Start()

	dialer := net.Dialer{
		Timeout: 2 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			var soerr error
			if err := c.Control(func(su uintptr) {
				soerr = setSoMark(int(su), ep.GetIdentity())
			}); err != nil {
				return err
			}
			return soerr
		}}
	client.Dialer = &dialer

	conn, err := client.Dial(targetServerAddrStr)
	if err != nil {
		err := fmt.Errorf("failed to dial connection to %v: %w", targetServerAddrStr, err)
		stat.Err = err
		scopedLog.WithError(err).Error("Failed to dial connection to the upstream DNS server, cannot service DNS request")
		p.NotifyOnDNSMsg(time.Now(), ep, epIPPort, targetServerID, targetServerAddrStr, request, protocol, false, &stat)
		p.sendRefused(scopedLog, w, request)
		return
	}
	defer conn.Close()

	request.Id = dns.Id() // force a random new ID for this request
	response, _, err := client.ExchangeWithConn(request, conn)
	stat.UpstreamTime.End(err == nil)
	if err != nil {
		stat.Err = err
		if stat.IsTimeout() {
			scopedLog.WithError(err).Warn("Timeout waiting for response to forwarded proxied DNS lookup")
			p.NotifyOnDNSMsg(time.Now(), ep, epIPPort, targetServerID, targetServerAddrStr, request, protocol, false, &stat)
			return
		}
		scopedLog.WithError(err).Error("Cannot forward proxied DNS lookup")
		stat.Err = fmt.Errorf("cannot forward proxied DNS lookup: %w", err)
		p.NotifyOnDNSMsg(time.Now(), ep, epIPPort, targetServerID, targetServerAddrStr, request, protocol, false, &stat)
		p.sendRefused(scopedLog, w, request)
		return
	}

	scopedLog.WithField(logfields.Response, response).Debug("Received DNS response to proxied lookup")
	stat.Success = true

	scopedLog.Debug("Notifying with DNS response to original DNS query")
	p.NotifyOnDNSMsg(time.Now(), ep, epIPPort, targetServerID, targetServerAddrStr, response, protocol, true, &stat)

	scopedLog.Debug("Responding to original DNS query")
	// restore the ID to the one in the initial request so it matches what the requester expects.
	response.Id = requestID
	response.Compress = p.EnableDNSCompression && shouldCompressResponse(request, response)
	err = w.WriteMsg(response)
	if err != nil {
		scopedLog.WithError(err).Error("Cannot forward proxied DNS response")
		stat.Err = fmt.Errorf("Cannot forward proxied DNS response: %w", err)
		p.NotifyOnDNSMsg(time.Now(), ep, epIPPort, targetServerID, targetServerAddrStr, response, protocol, true, &stat)
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
			return ErrFailedAcquireSemaphore{
				parallel: option.Config.DNSProxyConcurrencyLimit,
			}
		}
	} else if err := p.ConcurrencyLimit.Acquire(ctx, 1); err != nil && errors.Is(err, context.DeadlineExceeded) {
		// We ignore err because errTimedOutAcquireSemaphore implements the
		// net.Error interface deeming it a timeout error which will be
		// treated the same as context.DeadlineExceeded.
		return ErrTimedOutAcquireSemaphore{
			ErrFailedAcquireSemaphore: ErrFailedAcquireSemaphore{
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

// bindToAddr attempts to bind to address and port for both UDP and TCP on IPv4 and/or IPv6.
// If address is empty it automatically binds to the loopback interfaces on IPv4 and/or IPv6.
// If port is 0 a random open port is assigned and the same one is used for UDP and TCP.
// Note: This mimics what the dns package does EXCEPT for setting reuseport.
// This is ok for now but it would simplify proxy management in the future to
// have it set.
func bindToAddr(address string, port uint16, handler dns.Handler, ipv4, ipv6 bool) (dnsServers []*dns.Server, bindPort uint16, err error) {
	defer func() {
		if err != nil {
			shutdownServers(dnsServers)
		}
	}()

	// Global singleton sessionUDPFactory which is used for IPv4 & IPv6
	sessUdpFactory := &sessionUDPFactory{ipv4Enabled: ipv4, ipv6Enabled: ipv6}

	var ipFamilies []ipFamily
	if ipv4 {
		ipFamilies = append(ipFamilies, ipv4Family())
	}
	if ipv6 {
		ipFamilies = append(ipFamilies, ipv6Family())
	}

	for _, ipf := range ipFamilies {
		lc := listenConfig(linux_defaults.MagicMarkEgress, ipf.IPv4Enabled, ipf.IPv6Enabled)

		tcpListener, err := lc.Listen(context.Background(), ipf.TCPAddress, evaluateAddress(address, port, bindPort, ipf))
		if err != nil {
			return nil, 0, fmt.Errorf("failed to listen on %s: %w", ipf.TCPAddress, err)
		}
		dnsServers = append(dnsServers, &dns.Server{
			Listener: tcpListener, Handler: handler,
			// Net & Addr are only set for logging purposes and aren't used if using ActivateAndServe.
			Net: ipf.TCPAddress, Addr: tcpListener.Addr().String(),
		})

		bindPort = uint16(tcpListener.Addr().(*net.TCPAddr).Port)

		udpConn, err := lc.ListenPacket(context.Background(), ipf.UDPAddress, evaluateAddress(address, port, bindPort, ipf))
		if err != nil {
			return nil, 0, fmt.Errorf("failed to listen on %s: %w", ipf.UDPAddress, err)
		}
		dnsServers = append(dnsServers, &dns.Server{
			PacketConn: udpConn, Handler: handler, SessionUDPFactory: sessUdpFactory,
			// Net & Addr are only set for logging purposes and aren't used if using ActivateAndServe.
			Net: ipf.UDPAddress, Addr: udpConn.LocalAddr().String(),
		})
	}

	return dnsServers, bindPort, nil
}

func evaluateAddress(address string, port uint16, bindPort uint16, ipFamily ipFamily) string {
	addr := ipFamily.Localhost

	if address != "" {
		addr = address
	}

	if bindPort == 0 {
		return net.JoinHostPort(addr, strconv.Itoa(int(port)))
	} else {
		// Already bound to a port by a previous server -> reuse same port
		return net.JoinHostPort(addr, strconv.Itoa(int(bindPort)))
	}
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

// GeneratePattern takes a set of l7Rules and returns a regular expression pattern for matching the
// provided l7 rules.
func GeneratePattern(l7Rules *policy.PerSelectorPolicy) (pattern string) {
	if l7Rules == nil || len(l7Rules.DNS) == 0 {
		return matchpattern.MatchAllAnchoredPattern
	}
	reStrings := make([]string, 0, len(l7Rules.DNS))
	for _, dnsRule := range l7Rules.DNS {
		if len(dnsRule.MatchName) > 0 {
			dnsRuleName := strings.ToLower(dns.Fqdn(dnsRule.MatchName))
			dnsRuleNameAsRE := matchpattern.ToUnAnchoredRegexp(dnsRuleName)
			reStrings = append(reStrings, dnsRuleNameAsRE)
		}
		if len(dnsRule.MatchPattern) > 0 {
			dnsPattern := matchpattern.Sanitize(dnsRule.MatchPattern)
			dnsPatternAsRE := matchpattern.ToUnAnchoredRegexp(dnsPattern)
			if dnsPatternAsRE == matchpattern.MatchAllUnAnchoredPattern {
				return matchpattern.MatchAllAnchoredPattern
			}
			reStrings = append(reStrings, dnsPatternAsRE)
		}
	}
	return "^(?:" + strings.Join(reStrings, "|") + ")$"
}

func (p *DNSProxy) Cleanup() {
	if p.unbindAddress != nil {
		p.unbindAddress()
	}
}
