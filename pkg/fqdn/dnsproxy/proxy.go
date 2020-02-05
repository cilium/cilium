// Copyright 2018 Authors of Cilium
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
	"time"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn/matchpattern"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/spanstat"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
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

	// LookupEndpointIDByIP is a provided callback that returns the endpoint ID
	// as a uint16.
	// Note: this is a little pointless since this proxy is in-process but it is
	// intended to allow us to switch to an external proxy process by forcing the
	// design now.
	LookupEndpointIDByIP LookupEndpointIDByIPFunc

	// LookupSecIDByIP is a provided callback that returns the IP's security ID
	// from the ipcache.
	// Note: this is a little pointless since this proxy is in-process but it is
	// intended to allow us to switch to an external proxy process by forcing the
	// design now.
	LookupSecIDByIP LookupSecIDByIPFunc

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

	// lookupTargetDNSServer extracts the originally intended target of a DNS
	// query. It is always set to lookupTargetDNSServer in
	// helpers.go but is modified during testing.
	lookupTargetDNSServer func(w dns.ResponseWriter) (serverIP net.IP, serverPort uint16, addrStr string, err error)

	// this mutex protects variables below this point
	lock.Mutex

	// allowed tracks all allowed L7 DNS rules by endpointID, destination port,
	// and L3 Selector. All must match for a query to be allowed.
	//
	// matchNames with no regexp wildcards are still compiled, internally.
	// Note: Simple DNS names, e.g. bar.foo.com, will treat the "." as a literal.
	allowed perEPAllow

	// rejectReply is the OPCode send from the DNS-proxy to the endpoint if the
	// DNS request is invalid
	rejectReply int
}

// perEPAllow maps EndpointIDs to ports + selectors + rules
type perEPAllow map[uint64]portToSelectorAllow

// portToSelectorAllow maps port numbers to selectors + rules
type portToSelectorAllow map[uint16]cachedSelectorREEntry

// cachedSelectorREEntry maps port numbers to selectors to rules, mirroring
// policy.L7DataMap but the DNS rules are compiled into a single regexp
type cachedSelectorREEntry map[policy.CachedSelector]*regexp.Regexp

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

	newRE := make(cachedSelectorREEntry)
	for selector, l7Rules := range newRules {
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
		re, err := regexp.Compile(strings.Join(reStrings, "|"))
		if err != nil {
			return err
		}
		newRE[selector] = re
	}

	epPorts, exist := allow[endpointID]
	if !exist {
		epPorts = make(portToSelectorAllow)
		allow[endpointID] = epPorts
	}

	epPorts[destPort] = newRE
	return nil
}

// getPortRulesForID returns a precompiled regex representing DNS rules for the
// passed-in endpointID and destPort with setPortRulesForID
func (allow perEPAllow) getPortRulesForID(endpointID uint64, destPort uint16) (rules cachedSelectorREEntry, exists bool) {
	rules, exists = allow[endpointID][destPort]
	return rules, exists
}

// LookupEndpointIDByIPFunc wraps logic to lookup an endpoint with any backend.
// See DNSProxy.LookupEndpointIDByIP for usage.
type LookupEndpointIDByIPFunc func(ip net.IP) (endpoint *endpoint.Endpoint, err error)

// LookupSecIDByIPFunc Func wraps logic to lookup an IP's security ID from the
// ipcache.
// See DNSProxy.LookupSecIDByIP for usage.
type LookupSecIDByIPFunc func(ip net.IP) (secID ipcache.Identity, exists bool, err error)

// NotifyOnDNSMsgFunc handles propagating DNS response data
// See DNSProxy.LookupEndpointIDByIP for usage.
type NotifyOnDNSMsgFunc func(lookupTime time.Time, ep *endpoint.Endpoint, epIPPort string, serverAddr string, msg *dns.Msg, protocol string, allowed bool, stat ProxyRequestContext) error

// ProxyRequestContext proxy dns request context struct to send in the callback
type ProxyRequestContext struct {
	ProcessingTime spanstat.SpanStat // This is going to happen at the end of the second callback.
	// Error is a enum of [timeout, allow, denied, proxyerr].
	UpstreamTime spanstat.SpanStat
	Success      bool
	Err          error
}

// IsTimeout return true if the ProxyRequest timeout
func (proxyStat *ProxyRequestContext) IsTimeout() bool {
	netErr, isNetErr := proxyStat.Err.(net.Error)
	if isNetErr && netErr.Timeout() {
		return true

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
func StartDNSProxy(address string, port uint16, lookupEPFunc LookupEndpointIDByIPFunc, lookupSecIDFunc LookupSecIDByIPFunc, notifyFunc NotifyOnDNSMsgFunc) (*DNSProxy, error) {
	if port == 0 {
		log.Debug("DNS Proxy port is configured to 0. A random port will be assigned by the OS.")
	}

	if lookupEPFunc == nil || notifyFunc == nil {
		return nil, errors.New("DNS proxy must have lookupEPFunc and notifyFunc provided")
	}

	p := &DNSProxy{
		LookupEndpointIDByIP:  lookupEPFunc,
		LookupSecIDByIP:       lookupSecIDFunc,
		NotifyOnDNSMsg:        notifyFunc,
		lookupTargetDNSServer: lookupTargetDNSServer,
		allowed:               make(perEPAllow),
		rejectReply:           dns.RcodeRefused,
	}

	// Start the DNS listeners on UDP and TCP
	var (
		UDPConn                *net.UDPConn
		TCPListener            *net.TCPListener
		err                    error
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

// UpdateAllowed sets newRules for endpointID and destPort. It compiles the DNS
// rules into regexes that are then used in CheckAllowed.
func (p *DNSProxy) UpdateAllowed(endpointID uint64, destPort uint16, newRules policy.L7DataMap) error {
	p.Lock()
	defer p.Unlock()

	return p.allowed.setPortRulesForID(endpointID, destPort, newRules)
}

// CheckAllowed checks endpointID, destPort, destID, and name against the rules
// added to the proxy, and only returns true if this all match something that
// was added (via SetAllowed) previously.
func (p *DNSProxy) CheckAllowed(endpointID uint64, destPort uint16, destID identity.NumericIdentity, name string) (allowed bool, err error) {
	name = strings.ToLower(dns.Fqdn(name))
	p.Lock()
	defer p.Unlock()

	epAllow, exists := p.allowed.getPortRulesForID(endpointID, destPort)
	if !exists {
		return false, nil
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
//  - Look up the endpoint that sent the request by IP, via LookupEndpointIDByIP.
//  - Look up the Sec ID of the destination server, via LookupSecIDByIP.
//  - Check that the endpoint ID, destination Sec ID, destination port and the
//  qname all match a rule. If not, the request is dropped.
//  - The allowed request is forwarded to the originally intended DNS server IP
//  - The response is shared via NotifyOnDNSMsg (this will go to a
//  fqdn/NameManager instance).
//  - Write the response to the endpoint.
func (p *DNSProxy) ServeDNS(w dns.ResponseWriter, request *dns.Msg) {
	stat := ProxyRequestContext{}
	stat.ProcessingTime.Start()
	requestID := request.Id // keep the original request ID
	qname := string(request.Question[0].Name)
	protocol := w.LocalAddr().Network()
	scopedLog := log.WithFields(logrus.Fields{
		logfields.DNSName:      qname,
		logfields.IPAddr:       w.RemoteAddr(),
		logfields.DNSRequestID: request.Id})
	scopedLog.Debug("Handling DNS query from endpoint")

	epIPPort := w.RemoteAddr().String()
	addr, _, err := net.SplitHostPort(epIPPort)
	if err != nil {
		scopedLog.WithError(err).Error("cannot extract endpoint IP from DNS request")
		stat.Err = fmt.Errorf("Cannot extract endpoint IP from DNS request: %s", err)
		stat.ProcessingTime.End(false)
		p.NotifyOnDNSMsg(time.Now(), nil, epIPPort, "", request, protocol, false, stat)
		p.sendRefused(scopedLog, w, request)
		return
	}
	ep, err := p.LookupEndpointIDByIP(net.ParseIP(addr))
	if err != nil {
		scopedLog.WithError(err).Error("cannot extract endpoint ID from DNS request")
		stat.Err = fmt.Errorf("Cannot extract endpoint ID from DNS request: %s", err)
		stat.ProcessingTime.End(false)
		p.NotifyOnDNSMsg(time.Now(), nil, epIPPort, "", request, protocol, false, stat)
		p.sendRefused(scopedLog, w, request)
		return
	}

	scopedLog = scopedLog.WithField(logfields.EndpointID, ep.StringID())

	targetServerIP, targetServerPort, targetServerAddr, err := p.lookupTargetDNSServer(w)
	if err != nil {
		log.WithError(err).Error("cannot extract destination IP:port from DNS request")
		stat.Err = fmt.Errorf("Cannot extract destination IP:port from DNS request: %s", err)
		stat.ProcessingTime.End(false)
		p.NotifyOnDNSMsg(time.Now(), ep, epIPPort, targetServerAddr, request, protocol, false, stat)
		p.sendRefused(scopedLog, w, request)
		return
	}

	serverSecID, exists, err := p.LookupSecIDByIP(targetServerIP)
	if !exists || err != nil {
		scopedLog.WithError(err).WithField("server", targetServerAddr).Debug("cannot find server ip in ipcache")
		stat.Err = fmt.Errorf("Cannot find server ip in ipcache: %s", err)
		stat.ProcessingTime.End(false)
		p.NotifyOnDNSMsg(time.Now(), ep, epIPPort, targetServerAddr, request, protocol, false, stat)
		p.sendRefused(scopedLog, w, request)
		return
	}
	scopedLog.WithField("server", targetServerAddr).Debugf("Found target server to of DNS request secID %+v", serverSecID)

	// The allowed check is first because we don't want to use DNS responses that
	// endpoints are not allowed to see.
	// Note: The cache doesn't know about the source of the DNS data (yet) and so
	// it won't enforce any separation between results from different endpoints.
	// This isn't ideal but we are trusting the DNS responses anyway.
	allowed, err := p.CheckAllowed(uint64(ep.ID), targetServerPort, serverSecID.ID, qname)
	switch {
	case err != nil:
		scopedLog.WithError(err).Error("Rejecting DNS query from endpoint due to error")
		stat.Err = fmt.Errorf("Rejecting DNS query from endpoint due to error: %s", err)
		stat.ProcessingTime.End(false)
		p.NotifyOnDNSMsg(time.Now(), ep, epIPPort, targetServerAddr, request, protocol, false, stat)
		p.sendRefused(scopedLog, w, request)
		return

	case !allowed:
		scopedLog.Debug("Rejecting DNS query from endpoint due to policy")
		stat.Err = p.sendRefused(scopedLog, w, request)
		stat.ProcessingTime.End(true)
		p.NotifyOnDNSMsg(time.Now(), ep, epIPPort, targetServerAddr, request, protocol, false, stat)
		return
	}

	scopedLog.Debug("Forwarding DNS request for a name that is allowed")
	p.NotifyOnDNSMsg(time.Now(), ep, epIPPort, targetServerAddr, request, protocol, true, stat)

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
		stat.Err = fmt.Errorf("Cannot parse DNS proxy client network to select forward client: %s", err)
		stat.ProcessingTime.End(false)
		p.NotifyOnDNSMsg(time.Now(), ep, epIPPort, targetServerAddr, request, protocol, false, stat)
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
			stat.Err = fmt.Errorf("Cannot forward proxied DNS lookup: %s", err)
		}
		p.NotifyOnDNSMsg(time.Now(), ep, epIPPort, targetServerAddr, request, protocol, false, stat)
		return
	}

	scopedLog.WithField(logfields.Response, response).Debug("Received DNS response to proxied lookup")
	stat.Success = true

	scopedLog.Debug("Notifying with DNS response to original DNS query")
	p.NotifyOnDNSMsg(time.Now(), ep, epIPPort, targetServerAddr, response, protocol, true, stat)

	scopedLog.Debug("Responding to original DNS query")
	// restore the ID to the one in the initial request so it matches what the requester expects.
	response.Id = requestID
	err = w.WriteMsg(response)
	if err != nil {
		scopedLog.WithError(err).Error("Cannot forward proxied DNS response")
		stat.Err = fmt.Errorf("Cannot forward proxied DNS response: %s", err)
		p.NotifyOnDNSMsg(time.Now(), ep, epIPPort, targetServerAddr, response, protocol, true, stat)
	}
}

// sendRefused creates and sends a REFUSED response for request to w
// The returned error is logged with scopedLog and is returned for convenience
func (p *DNSProxy) sendRefused(scopedLog *logrus.Entry, w dns.ResponseWriter, request *dns.Msg) (err error) {
	refused := new(dns.Msg)
	refused.SetRcode(request, p.rejectReply)

	if err = w.WriteMsg(refused); err != nil {
		scopedLog.WithError(err).Error("Cannot send REFUSED response")
		err = fmt.Errorf("cannot send REFUSED response: %s", err)
	}
	return err
}

// SetRejectReply sets the default reject reply on denied dns responses.
func (p *DNSProxy) SetRejectReply(opt string) {
	switch strings.ToLower(opt) {
	case strings.ToLower(option.FQDNProxyDenyWithNameError):
		p.rejectReply = dns.RcodeNameError
	case strings.ToLower(option.FQDNProxyDenyWithRefused):
		p.rejectReply = dns.RcodeRefused
	default:
		log.Infof("DNS reject response '%s' is not valid, available options are '%v'",
			opt, option.FQDNRejectOptions)
		return
	}
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
