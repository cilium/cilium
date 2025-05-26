// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dnsproxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/dns"
	"go4.org/netipx"
	"golang.org/x/sync/semaphore"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/container/versioned"
	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn/matchpattern"
	"github.com/cilium/cilium/pkg/fqdn/proxy/ipfamily"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/revert"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/u8proto"
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
	logger *slog.Logger

	cfg DNSProxyConfig

	// BindPort is the port in BindAddr. This may be different from
	// the port specified in cfg.
	BindPort uint16

	// ipcache exposes information about IP addresses and identities
	ipcache IPCache

	// LookupRegisteredEndpoint is a provided callback that returns the endpoint ID
	// as a uint16.
	// Note: this is a little pointless since this proxy is in-process but it is
	// intended to allow us to switch to an external proxy process by forcing the
	// design now.
	LookupRegisteredEndpoint LookupEndpointIDByIPFunc

	// NotifyOnDNSMsg is a provided callback by which the proxy can emit DNS
	// response data. It is intended to wire into a DNS cache and a
	// fqdn.NameManager.
	// Note: this is a little pointless since this proxy is in-process but it is
	// intended to allow us to switch to an external proxy process by forcing the
	// design now.
	NotifyOnDNSMsg NotifyOnDNSMsgFunc

	// DNSServers are the cilium/dns server instances.
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
	lookupTargetDNSServer func(w dns.ResponseWriter) (network u8proto.U8proto, server netip.AddrPort, err error)

	// maxIPsPerRestoredDNSRule is the maximum number of IPs to maintain for each
	// restored DNS rule.
	maxIPsPerRestoredDNSRule int

	// this mutex protects variables below this point
	lock.RWMutex

	// DNSClients is a container for dns.SharedClient instances.
	DNSClients *SharedClients

	// usedServers is the set of DNS servers that have been allowed and used successfully.
	// This is used to limit the number of IPs we store for restored DNS rules.
	usedServers map[netip.Addr]struct{}

	// allowed tracks all allowed L7 DNS rules by endpointID, destination port,
	// and L3 Selector. All must match for a query to be allowed.
	//
	// Note: Simple DNS names, e.g. bar.foo.com, will treat the "." as a literal.
	allowed perEPAllow

	// Current rules enforced by 'allowed', used for reverting
	currentRules perEPPolicy

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

	// FIXME: host endpoint does not have an IP address yet
	restoredHost *endpoint.Endpoint

	// rejectReply is the OPCode send from the DNS-proxy to the endpoint if the
	// DNS request is invalid
	rejectReply int

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

// perEPAllow maps EndpointIDs to protocols + ports + selectors + rules
type perEPAllow map[uint64]portProtoToSelectorAllow

// perEPPolicy stores the policy rules.
type perEPPolicy map[uint64]policy.L7DataMap

// portProtoToSelectorAllow maps protocol-port numbers to selectors + rules
type portProtoToSelectorAllow map[restore.PortProto]CachedSelectorREEntry

// CachedSelectorREEntry maps port numbers to selectors to rules, mirroring
// policy.L7DataMap but the DNS rules are compiled into a regex
type CachedSelectorREEntry map[policy.CachedSelector]*regexp.Regexp

// structure for restored rules that can be used while Cilium agent is restoring endpoints
type perEPRestored map[uint64]map[restore.PortProto][]restoredIPRule

// restoredIPRule is the dnsproxy internal way of representing a restored IPRule
// where we also store the actual compiled regular expression as a, as well
// as the original restored IPRule
type restoredIPRule struct {
	restore.IPRule
	regex *regexp.Regexp
}

// map from EP IPs to *Endpoint
type restoredEPs map[netip.Addr]*endpoint.Endpoint

// asIPRule returns a new restore.IPRule representing the rules, including the provided IP map.
func asIPRule(r *regexp.Regexp, IPs map[restore.RuleIPOrCIDR]struct{}) restore.IPRule {
	pattern := "^-$"
	if r != nil {
		pattern = r.String()
	}
	return restore.IPRule{IPs: IPs, Re: restore.RuleRegex{Pattern: &pattern}}
}

// CheckRestored checks endpointID, destPort, destIP, and name against the restored rules,
// and only returns true if a restored rule matches.
func (p *DNSProxy) checkRestored(endpointID uint64, destPortProto restore.PortProto, destIP string, name string) bool {
	ipRules, exists := p.restored[endpointID][destPortProto]
	if !exists && destPortProto.IsPortV2() {
		// Check if there is a Version 1 restore.
		ipRules, exists = p.restored[endpointID][destPortProto.ToV1()]
		p.logger.Debug(
			"Checking if restored V1 IP rules exists for endpoint",
			logfields.EndpointID, endpointID,
			logfields.Port, destPortProto.Port(),
			logfields.Protocol, destPortProto.Protocol(),
			logfields.Exists, exists,
			logfields.IPRules, ipRules,
		)
		if !exists {
			return false
		}
	}

	dest, err := restore.ParseRuleIPOrCIDR(destIP)
	if err != nil || !dest.IsAddr() {
		return false
	}

	for i := range ipRules {
		ipRule := ipRules[i]
		if IPs := ipRule.IPs; len(IPs) == 0 {
			// ok
		} else if _, exists := IPs[dest]; exists {
			// ok
		} else if _, exists := IPs[dest.ToSingleCIDR()]; exists {
			// ok
		} else {
			for ip := range IPs {
				if ip.ContainsAddr(dest) {
					exists = true
					break
				}
			}
			if !exists {
				continue
			}
		}
		if ipRule.regex != nil && ipRule.regex.MatchString(name) {
			return true
		}
	}
	return false
}

// skipIPInRestorationRLocked skips IPs that are allowed but have never been used,
// but only if at least one server has been used so far.
// Requires the RLock to be held.
func (p *DNSProxy) skipIPInRestorationRLocked(ip netip.Addr) bool {
	if len(p.usedServers) > 0 {
		if _, used := p.usedServers[ip]; !used {
			return true
		}
	}
	return false
}

// GetRules creates a fresh copy of EP's DNS rules to be stored
// for later restoration.
func (p *DNSProxy) GetRules(version *versioned.VersionHandle, endpointID uint16) (restore.DNSRules, error) {
	// Lock ordering note: Acquiring the IPCache read lock (as LookupIPsBySecID does) while holding
	// the proxy lock can lead to a deadlock. Avoid this by reading the state from DNSProxy while
	// holding the read lock, then perform the IPCache lookups.
	// Note that IPCache state may change in between calls to LookupIPsBySecID.
	p.RLock()

	type selRegex struct {
		re *regexp.Regexp
		cs policy.CachedSelector
	}

	portProtoToSelRegex := make(map[restore.PortProto][]selRegex)
	for pp, entries := range p.allowed[uint64(endpointID)] {
		nidRules := make([]selRegex, 0, len(entries))
		// Copy the entries to avoid racy map accesses after we release the lock. We don't need
		// constant time access, hence a preallocated slice instead of another map.
		for cs, regex := range entries {
			nidRules = append(nidRules, selRegex{cs: cs, re: regex})
		}
		portProtoToSelRegex[pp] = nidRules
	}

	// We've read what we need from the proxy. The following IPCache lookups _must_ occur outside of
	// the critical section.
	p.RUnlock()

	restored := make(restore.DNSRules)
	for pp, selRegexes := range portProtoToSelRegex {
		var ipRules restore.IPRules
		for _, selRegex := range selRegexes {
			if selRegex.cs.IsWildcard() {
				ipRules = append(ipRules, asIPRule(selRegex.re, nil))
				continue
			}
			ips := make(map[restore.RuleIPOrCIDR]struct{})
			count := 0
			nids := selRegex.cs.GetSelections(version)
		Loop:
			for _, nid := range nids {
				// Note: p.RLock must not be held during this call to IPCache
				nidIPs := p.ipcache.LookupByIdentity(nid)
				p.RLock()
				for _, ip := range nidIPs {
					rip, err := restore.ParseRuleIPOrCIDR(ip)
					if err != nil {
						if errors.Is(err, restore.ErrRemoteClusterAddr) {
							// ignore non-local IPs or CIDRs
							continue
						}
						p.logger.Warn(
							"Could not parse IP for a DNS rule (?!), skipping",
							logfields.EndpointID, endpointID,
							logfields.Port, pp.Port(),
							logfields.Protocol, pp.Protocol(),
							logfields.EndpointLabelSelector, selRegex.cs,
							logfields.IPAddr, ip,
						)
						continue
					}
					if rip.IsAddr() && p.skipIPInRestorationRLocked(rip.Addr()) {
						continue
					}
					ips[rip] = struct{}{}
					count++
					if count > p.maxIPsPerRestoredDNSRule {
						p.logger.Warn(
							"Too many IPs for a DNS rule, skipping the rest",
							logfields.EndpointID, endpointID,
							logfields.Port, pp.Port(),
							logfields.Protocol, pp.Protocol(),
							logfields.Limit, p.maxIPsPerRestoredDNSRule,
							logfields.Count, len(nidIPs),
						)
						p.RUnlock()
						break Loop
					}
				}
				p.RUnlock()
			}
			ipRules = append(ipRules, asIPRule(selRegex.re, ips))
		}
		restored[pp] = ipRules
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
		p.restoredEPs[ep.IPv4] = ep
	}
	if ep.IPv6.IsValid() {
		p.restoredEPs[ep.IPv6] = ep
	}
	if ep.IsHost() {
		p.restoredHost = ep
	}
	// Use V2 if it is populated, otherwise
	// use V1.
	dnsRules := ep.DNSRulesV2
	if len(dnsRules) == 0 && len(ep.DNSRules) > 0 {
		dnsRules = ep.DNSRules
	}
	restoredRules := make(map[restore.PortProto][]restoredIPRule, len(ep.DNSRules))
	for pp, dnsRule := range dnsRules {
		ipRules := make([]restoredIPRule, 0, len(dnsRule))
		for _, ipRule := range dnsRule {
			if ipRule.Re.Pattern == nil {
				continue
			}
			regex, err := p.cache.lookupOrCompileRegex(*ipRule.Re.Pattern)
			if err != nil {
				p.logger.Info(
					"Disregarding restored DNS rule due to failure in compiling regex. Traffic to the FQDN may be disrupted.",
					logfields.EndpointID, ep.ID,
					logfields.Rule, *ipRule.Re.Pattern,
				)
				continue
			}
			rule := restoredIPRule{
				IPRule: ipRule,
				regex:  regex,
			}
			ipRules = append(ipRules, rule)
		}
		restoredRules[pp] = ipRules
	}
	p.restored[uint64(ep.ID)] = restoredRules

	p.logger.Debug(
		"Restored rules for endpoint",
		logfields.EndpointID, ep.ID,
		logfields.Rule, dnsRules,
	)
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
		if p.restoredHost != nil && p.restoredHost.ID == uint16(endpointID) {
			p.restoredHost = nil
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
	regex, err := regexp.Compile(pattern)
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

func (allow perEPAllow) removeAndReleasePortRulesForID(cache regexCache, endpointID uint64, destPortProto restore.PortProto) {
	epPortProtos, hasEpPortProtos := allow[endpointID]
	if !hasEpPortProtos {
		return
	}
	for _, m := range epPortProtos[destPortProto] {
		cache.releaseRegex(m)
	}
	delete(epPortProtos, destPortProto)
	if len(epPortProtos) == 0 {
		delete(allow, endpointID)
	}
}

// setPortRulesForID sets the matching rules for endpointID and destPort for
// later lookups. It converts newRules into a compiled regex
func (allow perEPAllow) setPortRulesForID(cache regexCache, endpointID uint64, destPortProto restore.PortProto, newRules policy.L7DataMap) error {
	if len(newRules) == 0 {
		allow.removeAndReleasePortRulesForID(cache, endpointID, destPortProto)
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
	allow.removeAndReleasePortRulesForID(cache, endpointID, destPortProto)
	epPortProtos, exist := allow[endpointID]
	if !exist {
		epPortProtos = make(portProtoToSelectorAllow)
		allow[endpointID] = epPortProtos
	}
	epPortProtos[destPortProto] = cse
	return nil
}

// setPortRulesForIDFromUnifiedFormat sets the matching rules for endpointID and destPort for
// later lookups. It does not guarantee it will reuse all the provided regexes, since it will reuse
// already existing regexes with the same pattern in case they are already in use.
func (allow perEPAllow) setPortRulesForIDFromUnifiedFormat(cache regexCache, endpointID uint64, destPortProto restore.PortProto, newRules CachedSelectorREEntry) {
	if len(newRules) == 0 {
		allow.removeAndReleasePortRulesForID(cache, endpointID, destPortProto)
		return
	}
	cse := make(CachedSelectorREEntry, len(newRules))
	for selector, providedRegex := range newRules {
		// In case the regex is already compiled and in use in another regex, lookupOrInsertRegex
		// will return a ref. to the existing regex, and use that one.
		cse[selector] = cache.lookupOrInsertRegex(providedRegex)
	}

	allow.removeAndReleasePortRulesForID(cache, endpointID, destPortProto)
	epPortProtos, exist := allow[endpointID]
	if !exist {
		epPortProtos = make(portProtoToSelectorAllow)
		allow[endpointID] = epPortProtos
	}
	epPortProtos[destPortProto] = cse
}

// getPortRulesForID returns a precompiled regex representing DNS rules for the
// passed-in endpointID and destPort with setPortRulesForID
func (allow perEPAllow) getPortRulesForID(logger *slog.Logger, endpointID uint64, destPortProto restore.PortProto) (rules CachedSelectorREEntry, exists bool) {
	rules, exists = allow[endpointID][destPortProto]
	if !exists && destPortProto.Protocol() != 0 {
		rules, exists = allow[endpointID][destPortProto.ToV1()]

		logger.Debug(
			"Checking for V1 port rule exists for endpoint",
			logfields.EndpointID, endpointID,
			logfields.Port, destPortProto.Port(),
			logfields.Protocol, destPortProto.Protocol(),
			logfields.Exists, exists,
			logfields.Rules, rules,
		)
	}
	return
}

// DNSProxyConfig is the configuration for the DNS proxy.
type DNSProxyConfig struct {
	Logger                 *slog.Logger
	Address                string
	IPv4                   bool
	IPv6                   bool
	EnableDNSCompression   bool
	MaxRestoreDNSIPs       int
	ConcurrencyLimit       int
	ConcurrencyGracePeriod time.Duration
	RejectReply            string
}

// NewDNSProxy creates a proxy used for DNS L7 redirects that listens on
// address and port on IPv4 and/or IPv6 depending on the values of ipv4/ipv6.
// address is the bind address to listen on. Empty binds to all local
// addresses.
// port is the port to bind to for both UDP and TCP. 0 causes the kernel to
// select a free port.
func NewDNSProxy(dnsProxyConfig DNSProxyConfig, ipc IPCache, lookupEPFunc LookupEndpointIDByIPFunc, notifyFunc NotifyOnDNSMsgFunc) *DNSProxy {

	p := &DNSProxy{
		logger:                   dnsProxyConfig.Logger,
		cfg:                      dnsProxyConfig,
		ipcache:                  ipc,
		LookupRegisteredEndpoint: lookupEPFunc,
		NotifyOnDNSMsg:           notifyFunc,
		logLimiter:               logging.NewLimiter(10*time.Second, 1),
		lookupTargetDNSServer:    lookupTargetDNSServer,
		usedServers:              make(map[netip.Addr]struct{}),
		allowed:                  make(perEPAllow),
		currentRules:             make(perEPPolicy),
		restored:                 make(perEPRestored),
		restoredEPs:              make(restoredEPs),
		cache:                    make(regexCache),
		EnableDNSCompression:     dnsProxyConfig.EnableDNSCompression,
		maxIPsPerRestoredDNSRule: dnsProxyConfig.MaxRestoreDNSIPs,
		DNSClients:               NewSharedClients(),
		rejectReply:              dns.RcodeRefused,
	}
	if dnsProxyConfig.ConcurrencyLimit > 0 {
		p.ConcurrencyLimit = semaphore.NewWeighted(int64(dnsProxyConfig.ConcurrencyLimit))
		p.ConcurrencyGracePeriod = dnsProxyConfig.ConcurrencyGracePeriod
	}

	switch strings.ToLower(dnsProxyConfig.RejectReply) {
	case strings.ToLower(option.FQDNProxyDenyWithNameError):
		p.rejectReply = dns.RcodeNameError
	case strings.ToLower(option.FQDNProxyDenyWithRefused), "":
		p.rejectReply = dns.RcodeRefused
	default:
		p.logger.Info(fmt.Sprintf("DNS reject response '%s' is not valid, available options are '%v'",
			dnsProxyConfig.RejectReply, option.FQDNRejectOptions))
	}

	return p
}

func (p *DNSProxy) Listen(port uint16) error {
	if port == 0 {
		p.logger.Debug("DNS Proxy port is configured to 0. A random port will be assigned by the OS.")
	}
	// Start the DNS listeners on UDP and TCP for IPv4 and/or IPv6
	var (
		dnsServers []*dns.Server
		bindPort   uint16
		err        error
	)

	start := time.Now()
	for time.Since(start) < ProxyBindTimeout {
		dnsServers, bindPort, err = bindToAddr(p.logger, p.cfg.Address, port, p, p.cfg.IPv4, p.cfg.IPv6, p.DNSClients)
		if err == nil {
			break
		}
		p.logger.Warn(
			"Attempt to bind DNS Proxy failed, retrying",
			logfields.RetryDelay, ProxyBindRetryInterval,
			logfields.Error, err,
		)
		time.Sleep(ProxyBindRetryInterval)
	}
	if err != nil {
		return fmt.Errorf("failed to bind DNS proxy: %w", err)
	}

	p.BindPort = bindPort
	p.DNSServers = dnsServers

	p.logger.Debug(
		"DNS Proxy bound to addresses",
		logfields.Addresses, len(dnsServers),
		logfields.Port, bindPort,
	)

	for _, s := range p.DNSServers {
		go func(server *dns.Server) {
			// try 5 times during a single ProxyBindTimeout period. We fatal here
			// because we have no other way to indicate failure this late.
			start := time.Now()
			var err error
			for time.Since(start) < ProxyBindTimeout {
				p.logger.Debug("Trying to start the DNS proxy",
					logfields.ProxyType, server.Net,
					logfields.Address, server.Addr,
				)

				if err = server.ActivateAndServe(); err != nil {
					p.logger.Error(
						"Failed to start the DNS proxy",
						logfields.Error, err,
						logfields.ProxyType, server.Net,
						logfields.Address, server.Addr,
					)
					time.Sleep(ProxyBindRetryInterval)
					continue
				}
				break // successful shutdown before timeout
			}
			if err != nil {
				logging.Fatal(
					p.logger,
					"Failed to start the DNS proxy",
					logfields.ProxyType, server.Net,
					logfields.Address, server.Addr,
					logfields.Error, err,
				)
			}
		}(s)
	}

	// This function is called in proxy.Cleanup, which is added to Daemon cleanup module in bootstrapFQDN
	p.unbindAddress = func() { shutdownServers(p.logger, p.DNSServers) }

	return nil
}

func shutdownServers(logger *slog.Logger, dnsServers []*dns.Server) {
	for _, s := range dnsServers {
		if err := s.Shutdown(); err != nil {
			logger.Error(
				"Failed to stop the DNS proxy",
				logfields.ProxyType, s.Net,
				logfields.Address, s.Addr,
				logfields.Error, err,
			)
		}
	}
}

// LookupEndpointByIP wraps LookupRegisteredEndpoint by falling back to an restored EP, if available
func (p *DNSProxy) LookupEndpointByIP(ip netip.Addr) (endpoint *endpoint.Endpoint, isHost bool, err error) {
	if endpoint, isHost, err = p.LookupRegisteredEndpoint(ip); err != nil {
		// Check restored endpoints
		var found bool
		if endpoint, found = p.restoredEPs[ip]; found {
			return endpoint, endpoint.IsHost(), nil
		}
		if isHost && p.restoredHost != nil {
			return p.restoredHost, true, nil
		}
	}
	return
}

// UpdateAllowed sets newRules for endpointID and destPort. It compiles the DNS
// rules into regexes that are then used in CheckAllowed.
func (p *DNSProxy) UpdateAllowed(endpointID uint64, destPortProto restore.PortProto, newRules policy.L7DataMap) (revert.RevertFunc, error) {
	p.Lock()
	defer p.Unlock()

	err := p.allowed.setPortRulesForID(p.cache, endpointID, destPortProto, newRules)
	if err != nil {
		return nil, err
	}

	// Rules were updated based on policy, remove restored rules
	p.removeRestoredRulesLocked(endpointID)

	// Get current rules for reverting
	oldRules := p.currentRules[endpointID]
	p.currentRules[endpointID] = newRules

	revert := func() error {
		p.Lock()
		defer p.Unlock()
		return p.allowed.setPortRulesForID(p.cache, endpointID, destPortProto, oldRules)
	}
	return revert, nil
}

// UpdateAllowedFromSelectorRegexes sets newRules for endpointID and destPort.
func (p *DNSProxy) UpdateAllowedFromSelectorRegexes(endpointID uint64, destPortProto restore.PortProto, newRules CachedSelectorREEntry) error {
	p.Lock()
	defer p.Unlock()

	p.allowed.setPortRulesForIDFromUnifiedFormat(p.cache, endpointID, destPortProto, newRules)
	// Rules were updated based on policy, remove restored rules
	p.removeRestoredRulesLocked(endpointID)
	return nil
}

// CheckAllowed checks endpointID, destPortProto, destID, destIP, and name against the rules
// added to the proxy or restored during restart, and only returns true if this all match
// something that was added (via UpdateAllowed or RestoreRules) previously.
func (p *DNSProxy) CheckAllowed(endpointID uint64, destPortProto restore.PortProto, destID identity.NumericIdentity, destIP netip.Addr, name string) (allowed bool, err error) {
	name = strings.ToLower(dns.Fqdn(name))
	p.RLock()
	defer p.RUnlock()

	epAllow, exists := p.allowed.getPortRulesForID(p.logger, endpointID, destPortProto)
	if !exists {
		return p.checkRestored(endpointID, destPortProto, destIP.String(), name), nil
	}

	for selector, regex := range epAllow {
		// The port was matched in getPortRulesForID, above.
		if regex != nil && selector.Selects(versioned.Latest(), destID) && (regex.String() == matchpattern.MatchAllAnchoredPattern || regex.MatchString(name)) {
			return true, nil
		}
	}

	return false, nil
}

// setSoMarks sets the socket options needed for a transparent proxy to integrate it's upstream
// (forwarded) connection with Cilium datapath. Some considerations for this design:
//
//   - Since a transparent proxy must reuse the original source IP address (and we must also
//     intercept the responses), we instruct the host networking namespace to allow binding the
//     local address to a foreign address and to receive packets destined to a non-local (foreign)
//     IP address of the source pod via the IP_TRANSPARENT socket option.
//
//   - In order to NOT hijack some random by-standing traffic going to the original pod, we must also
//     use the original port number.
//
//   - (DNS) clients use ephemeral source ports, i.e., the port can be different in every
//     request. Typically, a DNS resolver library uses the same ephemeral port only for requests
//     from a single "gethostbyname" API call, or equivalent.
//
//   - To be able to receive responses to the ephemeral source port, we must have a socket bound to
//     that address:port (for UDP), or a connection from that address:port to the DNS server
//     address:port (for TCP).
//
//   - This leads to a new DNS client and socket for every different original source address -
//     ephemeral port pair we see. We also need to make sure these were actually used to communicate
//     with the DNS server, so we use the whole 5-tuple as a key.
//
// Why can't we keep DNS clients pooled and ready to receive traffic between client requests?
//
//   - We have no guarantees that the source pod will keep on using the same ephemeral port in
//     future. We've had upstream socket bind errors (in Envoy, where we have operated in this mode
//     for years already) when a client pod has rapidly cycled through its ephemeral port space,
//     e.g. when performing netperf CRR or similar performance tests.
//
//   - We could try to keep the client and its bound socket around for some minimal time to save
//     resources when a DNS resolver is enumerating through its domain suffix list, where it seems
//     likely that the same source ephemeral port is going to be reused until the resolver gets an
//     actual result with an IPv4/6 address or quits trying. It might be safe to close the client
//     socket only after a response with the `A`/`AAAA` records have been passed back to the pod,
//     or after a timeout of a few milliseconds. This would be something we currently don't do and
//     is prone to socket bind errors, so this is left for a later exercise.
//
//   - So the client socket can not be left lingering around, as it causes network traffic destined
//     for the source pod to be intercepted to the dnsproxy, which is exactly what we want but only
//     until a DNS response has been received.
func setSoMarks(fd int, ipFamily ipfamily.IPFamily, secId identity.NumericIdentity) error {
	// Set SO_MARK to allow datapath to know these upstream packets from an egress proxy
	mark := linux_defaults.MagicMarkEgress
	mark |= uint32(secId&0xFFFF)<<16 | uint32((secId&0xFF0000)>>16)
	err := unix.SetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_MARK, uint64(mark))
	if err != nil {
		return fmt.Errorf("error setting SO_MARK: %w", err)
	}

	// Rest of the options are only set in the transparent mode.
	if !option.Config.DNSProxyEnableTransparentMode {
		return nil
	}

	// Set IP_TRANSPARENT to be able to use a non-host address as the source address
	if err := unix.SetsockoptInt(fd, ipFamily.SocketOptsFamily, ipFamily.SocketOptsTransparent, 1); err != nil {
		return fmt.Errorf("setsockopt(IP_TRANSPARENT) for %s failed: %w", ipFamily.Name, err)
	}

	// Set SO_REUSEADDR to allow binding to an address that is already used by some other
	// connection in a lingering state. This is needed in cases where we close a client
	// connection but the client issues new requests re-using its source port. In that case we
	// need to be able to reuse the address likely very soon after the prior close, which may
	// not be allowed without this option.
	if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
		return fmt.Errorf("setsockopt(SO_REUSEADDR) failed: %w", err)
	}

	// Set SO_REUSEPORT to allow two active connections to bind to the same address and
	// port. Normally this would not be needed, but is set to allow a new connection to be
	// created on a port where the old connection may not yet be closed. If two UDP sockets
	// using the same port due to this option were reading at the same time, the OS stack would
	// distribute incoming packets to them essentially randomly. We do not want that, so we
	// strive to avoid that situation. This may be helpful in avoiding bind errors in some cases
	// regardless.
	if !option.Config.EnableBPFTProxy {
		if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
			return fmt.Errorf("setsockopt(SO_REUSEPORT) failed: %w", err)
		}
	}

	// Set SO_LINGER to ensure the TCP socket is closed and ready to be re-used in case
	// the client reuses the same source port in short succession (this is e.g. the case
	// with glibc). If SO_LINGER is not used, the old socket might have not yet reached
	// the TIME_WAIT state by the time we are trying to reuse the port on a new socket.
	// If that happens, the connect() call will fail with EADDRNOTAVAIL.
	// Note that the linger timeout can also be set to 0, in which case the socket is
	// terminated forcefully with a TCP RST and thus can also be reused immediately.
	if linger := option.Config.DNSProxySocketLingerTimeout; linger >= 0 {
		err = unix.SetsockoptLinger(fd, unix.SOL_SOCKET, unix.SO_LINGER, &unix.Linger{
			Onoff:  1,
			Linger: int32(linger),
		})
		if err != nil {
			return fmt.Errorf("setsockopt(SO_LINGER) failed: %w", err)
		}
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
	requestID := request.Id // save the original request ID
	qname := string(request.Question[0].Name)
	protocol := w.LocalAddr().Network()
	epIPPort := w.RemoteAddr().String()
	scopedLog := p.logger.With(
		logfields.DNSName, qname,
		logfields.IPAddr, epIPPort,
		logfields.DNSRequestID, requestID,
	)

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
				scopedLog.Error("Dropping DNS request due to too many DNS requests already in-flight", logfields.Error, err)
			}
			stat.Err = err
			p.NotifyOnDNSMsg(time.Now(), nil, epIPPort, 0, netip.AddrPort{}, request, protocol, false, &stat)
			p.sendErrorResponse(scopedLog, w, request, false)
			return
		}
		stat.SemaphoreAcquireTime.End(true)
		defer p.ConcurrencyLimit.Release(1)
	}
	stat.ProcessingTime.Start()

	scopedLog.Debug("Handling DNS query from endpoint")

	addrPort, err := netip.ParseAddrPort(epIPPort)
	if err != nil {
		scopedLog.Error("cannot extract endpoint IP from DNS request", logfields.Error, err)
		stat.Err = fmt.Errorf("Cannot extract endpoint IP from DNS request: %w", err)
		stat.ProcessingTime.End(false)
		p.NotifyOnDNSMsg(time.Now(), nil, epIPPort, 0, netip.AddrPort{}, request, protocol, false, &stat)
		p.sendErrorResponse(scopedLog, w, request, false)
		return
	}
	epAddr := addrPort.Addr()
	ep, _, err := p.LookupEndpointByIP(epAddr)
	if err != nil {
		scopedLog.Error("cannot extract endpoint ID from DNS request", logfields.Error, err)
		stat.Err = fmt.Errorf("Cannot extract endpoint ID from DNS request: %w", err)
		stat.ProcessingTime.End(false)
		p.NotifyOnDNSMsg(time.Now(), nil, epIPPort, 0, netip.AddrPort{}, request, protocol, false, &stat)
		p.sendErrorResponse(scopedLog, w, request, false)
		return
	}

	scopedLog = scopedLog.With(
		logfields.EndpointID, ep.StringID(),
		logfields.Identity, ep.GetIdentity(),
	)

	proto, targetServer, err := p.lookupTargetDNSServer(w)
	if err != nil {
		p.logger.Error("cannot extract destination IP:port from DNS request", logfields.Error, err)
		stat.Err = fmt.Errorf("Cannot extract destination IP:port from DNS request: %w", err)
		stat.ProcessingTime.End(false)
		p.NotifyOnDNSMsg(time.Now(), ep, epIPPort, 0, targetServer, request, protocol, false, &stat)
		p.sendErrorResponse(scopedLog, w, request, false)
		return
	}
	targetServerPortProto := restore.MakeV2PortProto(targetServer.Port(), proto)

	// Ignore invalid IP - getter will handle invalid value.
	targetServerID := identity.GetWorldIdentityFromIP(targetServer.Addr())
	if serverSecID, exists := p.ipcache.LookupSecIDByIP(targetServer.Addr()); !exists {
		scopedLog.Debug(
			"cannot find server ip in ipcache, defaulting to WORLD",
			logfields.Server, targetServer.Addr(),
		)
	} else {
		targetServerID = serverSecID.ID
		scopedLog.Debug(
			"Found target server to of DNS request secID",
			logfields.SecID, serverSecID,
			logfields.Server, targetServer.Addr(),
		)
	}

	// The allowed check is first because we don't want to use DNS responses that
	// endpoints are not allowed to see.
	// Note: The cache doesn't know about the source of the DNS data (yet) and so
	// it won't enforce any separation between results from different endpoints.
	// This isn't ideal but we are trusting the DNS responses anyway.
	stat.PolicyCheckTime.Start()
	allowed, err := p.CheckAllowed(uint64(ep.ID), targetServerPortProto, targetServerID, targetServer.Addr(), qname)
	stat.PolicyCheckTime.End(err == nil)
	switch {
	case err != nil:
		scopedLog.Error("Rejecting DNS query from endpoint due to error", logfields.Error, err)
		stat.Err = fmt.Errorf("Rejecting DNS query from endpoint due to error: %w", err)
		stat.ProcessingTime.End(false)
		p.NotifyOnDNSMsg(time.Now(), ep, epIPPort, targetServerID, targetServer, request, protocol, false, &stat)
		p.sendErrorResponse(scopedLog, w, request, false)
		return

	case !allowed:
		scopedLog.Debug("Rejecting DNS query from endpoint due to policy")
		// Send refused msg before calling NotifyOnDNSMsg() because we know
		// that this DNS request is rejected anyway. NotifyOnDNSMsg depends on
		// stat.Err field to be set in order to propagate the correct
		// information for metrics.
		stat.Err = p.sendErrorResponse(scopedLog, w, request, true)
		stat.ProcessingTime.End(true)
		p.NotifyOnDNSMsg(time.Now(), ep, epIPPort, targetServerID, targetServer, request, protocol, false, &stat)
		return
	}

	scopedLog.Debug("Forwarding DNS request for a name that is allowed")
	if err := p.NotifyOnDNSMsg(time.Now(), ep, epIPPort, targetServerID, targetServer, request, protocol, true, &stat); err != nil {
		scopedLog.Error("Failed to process DNS query", logfields.Error, err)
		p.sendErrorResponse(scopedLog, w, request, false)
		return
	}

	// Keep the same L4 protocol. This handles DNS re-requests over TCP, for
	// requests that were too large for UDP.
	switch protocol {
	case "udp":
	case "tcp":
	default:
		scopedLog.Error("Cannot parse DNS proxy client network to select forward client")
		stat.Err = fmt.Errorf("Cannot parse DNS proxy client network to select forward client: %w", err)
		stat.ProcessingTime.End(false)
		p.NotifyOnDNSMsg(time.Now(), ep, epIPPort, targetServerID, targetServer, request, protocol, false, &stat)
		p.sendErrorResponse(scopedLog, w, request, false)
		return
	}
	stat.ProcessingTime.End(true)
	stat.UpstreamTime.Start()

	var ipFamily ipfamily.IPFamily
	if targetServer.Addr().Is4() {
		ipFamily = ipfamily.IPv4()
	} else {
		ipFamily = ipfamily.IPv6()
	}

	dialer := net.Dialer{
		Timeout: ProxyForwardTimeout,
		Control: func(network, address string, c syscall.RawConn) error {
			var soerr error
			if err := c.Control(func(su uintptr) {
				soerr = setSoMarks(int(su), ipFamily, ep.GetIdentity())
			}); err != nil {
				return err
			}
			return soerr
		},
	}

	var key string
	targetServerAddrStr := targetServer.String()
	// Do not use original source address if
	// - not configured, or if
	// - the source is known to be in the host networking namespace, or
	// - the destination is known to be outside of the cluster, or
	// - is the local host
	if option.Config.DNSProxyEnableTransparentMode && !ep.IsHost() && !epAddr.IsLoopback() && ep.ID != uint16(identity.ReservedIdentityHost) && targetServerID.IsCluster() && targetServerID != identity.ReservedIdentityHost {
		dialer.LocalAddr = w.RemoteAddr()
		key = sharedClientKey(protocol, epIPPort, targetServerAddrStr)
	}

	conf := &dns.Client{
		Net:            protocol,
		Dialer:         &dialer,
		Timeout:        ProxyForwardTimeout,
		SingleInflight: false,
	}

	response, _, closer, err := p.DNSClients.Exchange(key, conf, request, targetServerAddrStr)
	defer closer()

	stat.UpstreamTime.End(err == nil)
	if err != nil {
		stat.Err = err
		if stat.IsTimeout() {
			scopedLog.Warn("Timeout waiting for response to forwarded proxied DNS lookup", logfields.Error, err)
			p.NotifyOnDNSMsg(time.Now(), ep, epIPPort, targetServerID, targetServer, request, protocol, false, &stat)
			return
		}
		scopedLog.Error("Cannot forward proxied DNS lookup", logfields.Error, err)
		stat.Err = fmt.Errorf("cannot forward proxied DNS lookup: %w", err)
		p.NotifyOnDNSMsg(time.Now(), ep, epIPPort, targetServerID, targetServer, request, protocol, false, &stat)
		p.sendErrorResponse(scopedLog, w, request, false)
		return
	}

	scopedLog.Debug("Received DNS response to proxied lookup", logfields.Response, response)
	stat.Success = true

	scopedLog.Debug("Notifying with DNS response to original DNS query")
	if err := p.NotifyOnDNSMsg(time.Now(), ep, epIPPort, targetServerID, targetServer, response, protocol, true, &stat); err != nil {
		scopedLog.Error(
			"Failed to process DNS response",
			logfields.Error, err,
			logfields.Response, response,
		)
		p.sendErrorResponse(scopedLog, w, request, false)
		return
	}

	scopedLog.Debug("Responding to original DNS query")
	// Ensure the ID matches the initial request - the upstream query may have changed the ID to avoid duplicates.
	response.Id = requestID
	response.Compress = p.EnableDNSCompression && shouldCompressResponse(request, response)
	err = w.WriteMsg(response)
	if err != nil {
		scopedLog.Error("Cannot forward proxied DNS response", logfields.Error, err)
		stat.Err = fmt.Errorf("Cannot forward proxied DNS response: %w", err)
		p.NotifyOnDNSMsg(time.Now(), ep, epIPPort, targetServerID, targetServer, response, protocol, true, &stat)
	} else {
		p.Lock()
		// Add the server to the set of used DNS servers. This set is never GCd, but is limited by set
		// of DNS server IPs that are allowed by a policy and for which successful response was received.
		p.usedServers[targetServer.Addr()] = struct{}{}
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

// sendErrorResponse creates and sends an error response for request to w
// In case of policy rejection, the response code will be based on the rejectReply option.
// For all other errors, the response will be a SERVFAIL.
func (p *DNSProxy) sendErrorResponse(scopedLog *slog.Logger, w dns.ResponseWriter, request *dns.Msg, policyRejection bool) (err error) {
	response := new(dns.Msg)
	rcode := dns.RcodeServerFailure
	if policyRejection {
		rcode = p.rejectReply
	}
	response.SetRcode(request, rcode)

	if err = w.WriteMsg(response); err != nil {
		scopedLog.Error("Cannot send REFUSED response",
			logfields.Code, rcode,
			logfields.Error, err,
		)
		err = fmt.Errorf("cannot send error response (rcode=%d): %w", rcode, err)
	}
	return err
}

func (p *DNSProxy) GetBindPort() uint16 {
	return p.BindPort
}

// ExtractMsgDetails extracts a canonical query name, any IPs in a response,
// the lowest applicable TTL, rcode, anwer rr types and question types
// When a CNAME is returned the chain is collapsed down, keeping the lowest TTL,
// and CNAME targets are returned.
func ExtractMsgDetails(msg *dns.Msg) (
	qname string,
	responseIPs []netip.Addr,
	TTL uint32,
	CNAMEs []string,
	rcode int,
	answerTypes []uint16,
	qTypes []uint16,
	err error,
) {
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
			ip, ok := netipx.FromStdIP(ans.A)
			if !ok {
				return qname, nil, 0, nil, 0, nil, nil, errors.New("invalid IP in A record")
			}
			responseIPs = append(responseIPs, ip)
			if TTL > ans.Hdr.Ttl {
				TTL = ans.Hdr.Ttl
			}
		case *dns.AAAA:
			ip, ok := netipx.FromStdIP(ans.AAAA)
			if !ok {
				return qname, nil, 0, nil, 0, nil, nil, errors.New("invalid IP in AAAA record")
			}
			responseIPs = append(responseIPs, ip)
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
func bindToAddr(logger *slog.Logger, address string, port uint16, handler dns.Handler, ipv4, ipv6 bool, sc *SharedClients) (dnsServers []*dns.Server, bindPort uint16, err error) {
	defer func() {
		if err != nil {
			shutdownServers(logger, dnsServers)
		}
	}()

	var ipFamilies []ipfamily.IPFamily
	if ipv4 {
		ipFamilies = append(ipFamilies, ipfamily.IPv4())
	}
	if ipv6 {
		ipFamilies = append(ipFamilies, ipfamily.IPv6())
	}

	for _, ipFamily := range ipFamilies {
		lc := listenConfig(linux_defaults.MagicMarkEgress, ipFamily)

		tcpListener, err := lc.Listen(context.Background(), ipFamily.TCPAddress, evaluateAddress(address, port, bindPort, ipFamily))
		if err != nil {
			return nil, 0, fmt.Errorf("failed to listen on %s: %w", ipFamily.TCPAddress, err)
		}
		if option.Config.DNSProxyEnableTransparentMode {
			// The wrapper is only necessary to forward the closing signal in transparent mode.
			tcpListener = &wrappedTCPListener{sc: sc, Listener: tcpListener}
		}
		dnsServers = append(dnsServers, &dns.Server{
			Listener: tcpListener, Handler: handler,
			// Explicitly set a noop factory to prevent data race detection when InitPool is called
			// multiple times on the default factory even for TCP (IPv4 & IPv6).
			SessionUDPFactory: &noopSessionUDPFactory{},
			// Net & Addr are only set for logging purposes and aren't used if using ActivateAndServe.
			Net: ipFamily.TCPAddress, Addr: tcpListener.Addr().String(),
		})

		bindPort = uint16(tcpListener.Addr().(*net.TCPAddr).Port)

		udpConn, err := lc.ListenPacket(context.Background(), ipFamily.UDPAddress, evaluateAddress(address, port, bindPort, ipFamily))
		if err != nil {
			return nil, 0, fmt.Errorf("failed to listen on %s: %w", ipFamily.UDPAddress, err)
		}
		sessionUDPFactory, err := NewSessionUDPFactory(logger, ipFamily)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to create UDP session factory for %s: %w", ipFamily.UDPAddress, err)
		}
		dnsServers = append(dnsServers, &dns.Server{
			PacketConn: udpConn, Handler: handler, SessionUDPFactory: sessionUDPFactory,
			// Net & Addr are only set for logging purposes and aren't used if using ActivateAndServe.
			Net: ipFamily.UDPAddress, Addr: udpConn.LocalAddr().String(),
		})
	}

	return dnsServers, bindPort, nil
}

type wrappedTCPListener struct {
	net.Listener
	sc *SharedClients
}

func (w *wrappedTCPListener) Accept() (net.Conn, error) {
	c, err := w.Listener.Accept()
	if err != nil {
		return c, err
	}

	wc := &wrappedTCPConn{c.(*net.TCPConn), w.sc}
	return wc, err
}

type wrappedTCPConn struct {
	*net.TCPConn
	sc *SharedClients
}

func (w *wrappedTCPConn) key() string {
	return sharedClientKey("tcp", w.RemoteAddr().String(), w.LocalAddr().String())
}

func (w *wrappedTCPConn) Read(b []byte) (int, error) {
	n, err := w.TCPConn.Read(b)
	if err != nil {
		// Any error is reason enough to close the upstream conn.
		w.sc.ShutdownTCPClient(w.key())
	}
	return n, err
}
func (w *wrappedTCPConn) Write(b []byte) (int, error) {
	n, err := w.TCPConn.Write(b)
	if err != nil {
		w.sc.ShutdownTCPClient(w.key())
	}
	return n, err
}

// Close closes the wrapped connection, but also forwards the closing signal to
// shared clients, so that the upstream connection is closed too.
func (w *wrappedTCPConn) Close() error {
	// It's possible that there is no shared client behind this key, as we don't
	// always use the original source address. That's okay, since ShutdownClient
	// does nothing for keys it doesn't know.
	w.sc.ShutdownTCPClient(w.key())
	return w.TCPConn.Close()
}

func evaluateAddress(address string, port uint16, bindPort uint16, ipFamily ipfamily.IPFamily) string {
	// If the address is ever changed, ensure that the change is also reflected
	// where the proxy bind address is referenced in the iptables rules. See
	// (*IptablesManager).doGetProxyPort().

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
// RFCs require clients to accept this. In cilium/dns there is a comment that BIND
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
