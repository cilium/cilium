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
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/fqdn/regexpmap"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/sirupsen/logrus"

	"github.com/miekg/dns"
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
	// Note: unlike the other proxies, this server listens on a fixed, shared,
	// port.
	BindAddr string

	// BindPort is the port in BindAddr.
	BindPort uint16

	// LookupendpointIDByIP is a provided callback that returns the endpoint ID
	// as a string.
	// Note: this is a little pointless since this proxy is in-process but it is
	// intended to allow us to switch to an external proxy process by forcing the
	// design now.
	LookupEndpointIDByIP LookupEndpointIDByIPFunc

	// NotifyOnDNSMsg is a provided callback by which the proxy can emit DNS
	// response data. It is intended to wire into a DNS cache and a fqdn.RuleGen.
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
	// query via proxymap. It is always set to lookupTargetDNSServer in
	// helpers.go but is modified during testing.
	lookupTargetDNSServer func(w dns.ResponseWriter) (server string, err error)

	// this mutex protects variables below this point
	lock.Mutex

	// allowed tracks all allowed matchNames. These are regexps, even simple
	// matchNames with no regexp wildcards are compiled. We ensure a unique value
	// per source policy of a matchName because the RegexpMap handles the
	// reference counting of unique values but will de-dupe repeats.
	// Note: Simple DNS names, e.g. bar.foo.com, will treat the "." as a literal.
	// We convert these "." in regexps that only contain dots (and alphanumeric
	// characters) into a regexp "." literal. This is because the more common use
	// case will be these simple literals.
	// To insert a wildcard ".", use .{1} to indicate a single wildcard character.
	allowed *regexpmap.RegexpMap
}

// LookupEndpointIDByIPFunc wraps logic to lookup an endpoint with any backend.
// See DNSProxy.LookupEndpointIDByIP for usage.
type LookupEndpointIDByIPFunc func(ip net.IP) (endpointID string, err error)

// NotifyOnDNSMsgFunc handles propagating DNS response data
// See DNSProxy.LookupEndpointIDByIP for usage.
type NotifyOnDNSMsgFunc func(lookupTime time.Time, srcAddr, dstAddr string, msg *dns.Msg, protocol string, allowed bool, proxyErr error) error

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
func StartDNSProxy(address string, port uint16, lookupEPFunc LookupEndpointIDByIPFunc, notifyFunc NotifyOnDNSMsgFunc) (*DNSProxy, error) {
	if port == 0 {
		log.Debug("DNS Proxy port is configured to 0. A random port will be assigned by the OS.")
	}

	if lookupEPFunc == nil || notifyFunc == nil {
		return nil, errors.New("DNS proxy must have lookupEPFunc and notifyFunc provided")
	}

	p := &DNSProxy{
		LookupEndpointIDByIP:  lookupEPFunc,
		NotifyOnDNSMsg:        notifyFunc,
		lookupTargetDNSServer: lookupTargetDNSServer,
		allowed:               regexpmap.NewRegexpMap(),
	}

	// Start the DNS listeners on UDP and TCP
	var (
		UDPConn     *net.UDPConn
		TCPListener *net.TCPListener
		err         error
	)

	start := time.Now()
	for time.Since(start) < ProxyBindTimeout {
		UDPConn, TCPListener, err = bindToAddr(address, port)
		if err == nil {
			break
		}
		log.WithError(err).Warn("Attempt to bind DNS Proxy failed")
	}
	if err != nil {
		return nil, err
	}

	p.UDPServer = &dns.Server{PacketConn: UDPConn, Addr: p.BindAddr, Net: "udp", Handler: p}
	p.TCPServer = &dns.Server{Listener: TCPListener, Addr: p.BindAddr, Net: "tcp", Handler: p}
	p.BindAddr = UDPConn.LocalAddr().String()
	p.BindPort = uint16(UDPConn.LocalAddr().(*net.UDPAddr).Port)
	log.WithField("address", UDPConn.LocalAddr().String()).Debug("DNS Proxy bound to address")

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
	p.UDPClient = &dns.Client{Net: "udp", Timeout: ProxyForwardTimeout, SingleInflight: true}
	p.TCPClient = &dns.Client{Net: "tcp", Timeout: ProxyForwardTimeout, SingleInflight: true}

	return p, nil
}

// AddAllowed adds reStr, a regexp, to the DNS lookups the proxy allows.
func (p *DNSProxy) AddAllowed(reStr, endpointID string) {
	log.WithField(logfields.DNSName, reStr).Debug("Adding allowed DNS FQDN pattern")
	p.UpdateAllowed([]string{reStr}, nil, endpointID)
}

// RemoveAllowed removes reStr from the DNS lookups the proxy allows. It must
// match the form in AddAllowed exactly (i.e. this isn't removing by regex, but
// by direct equivalence).
func (p *DNSProxy) RemoveAllowed(reStr, endpointID string) {
	log.WithField(logfields.DNSName, reStr).Debug("Removing allowed DNS FQDN pattern")
	p.UpdateAllowed(nil, []string{reStr}, endpointID)
}

// UpdateAllowed adds and removes reStr while holding the lock. This is a bit
// of a hack to ensure atomic updates of rules until we replace the tracking
// with something better.
func (p *DNSProxy) UpdateAllowed(reStrToAdd, reStrToRemove []string, endpointID string) {
	for i := range reStrToAdd {
		reStrToAdd[i] = prepareNameMatch(reStrToAdd[i])
	}
	for i := range reStrToRemove {
		reStrToRemove[i] = prepareNameMatch(reStrToRemove[i])
	}

	p.Lock()
	defer p.Unlock()
	for _, reStr := range reStrToRemove {
		p.allowed.Remove(reStr, endpointID)
	}
	for _, reStr := range reStrToAdd {
		p.allowed.Add(reStr, endpointID)
	}
}

// CheckAllowed checks name against the rules added to the proxy, and only
// returns true if this endpointID was added (via AddAllowed) previously.
func (p *DNSProxy) CheckAllowed(name, endpointID string) bool {
	name = strings.ToLower(name)
	p.Lock()
	defer p.Unlock()
	return p.allowed.LookupContainsValue(name, endpointID)
}

// ServeDNS handles individual DNS requests forwarded to the proxy, and meets
// the dns.Handler interface.
// It will:
//  - Look up the endpoint that sent the request by IP, via LookupEndpointIDByIP.
//  - Check that the endpoint ID is in the set of values associated with the
//  DNS query (lowercased). If not, the request is dropped.
//  - The allowed request is forwarded to the originally intended DNS server IP
//  - The response is shared via NotifyOnDNSMsg (this will go to a
//  fqdn/RuleGen instance).
//  - Write the response to the endpoint.
func (p *DNSProxy) ServeDNS(w dns.ResponseWriter, request *dns.Msg) {
	requestID := request.Id // keep the original request ID
	qname := string(request.Question[0].Name)
	protocol := w.LocalAddr().Network()
	endpointAddr := w.RemoteAddr().String()
	scopedLog := log.WithFields(logrus.Fields{
		logfields.DNSName: qname,
		logfields.IPAddr:  w.RemoteAddr()})

	scopedLog.Debug("Handling DNS query from endpoint")

	endpointIPStr, _, err := net.SplitHostPort(w.RemoteAddr().String())
	if err != nil {
		scopedLog.WithError(err).Error("cannot extract endpoint IP from DNS request")
		p.NotifyOnDNSMsg(time.Now(), endpointAddr, "", request, protocol, false,
			fmt.Errorf("Cannot extract endpoint IP from DNS request: %s", err))
		sendRefused(scopedLog, w, request)
		return
	}
	endpointID, err := p.LookupEndpointIDByIP(net.ParseIP(endpointIPStr))
	if err != nil {
		scopedLog.WithError(err).Error("cannot extract endpoint ID from DNS request")
		p.NotifyOnDNSMsg(time.Now(), endpointAddr, "", request, protocol, false,
			fmt.Errorf("Cannot extract endpoint ID from DNS request: %s", err))
		sendRefused(scopedLog, w, request)
		return
	}
	scopedLog = scopedLog.WithField(logfields.EndpointID, endpointID)

	targetServerAddr, err := p.lookupTargetDNSServer(w)
	if err != nil {
		scopedLog.WithError(err).Error("Cannot extract target server address to forward DNS request to")
		p.NotifyOnDNSMsg(time.Now(), endpointAddr, targetServerAddr, request, protocol, false,
			fmt.Errorf("Cannot extract target server address to forward DNS request to: %s", err))
		sendRefused(scopedLog, w, request)
		return
	}
	scopedLog.WithField("server", targetServerAddr).Debug("Found target server to of DNS request")

	// The allowed check is first because we don't want to use DNS responses that
	// endpoints are not allowed to see.
	// Note: The cache doesn't know about the source of the DNS data (yet) and so
	// it won't enforce any separation between results from different endpoints.
	// This isn't ideal but we are trusting the DNS responses anyway.
	if !p.CheckAllowed(qname, endpointID) {
		scopedLog.Debug("Rejecting DNS query from endpoint due to policy")
		err = sendRefused(scopedLog, w, request)
		p.NotifyOnDNSMsg(time.Now(), endpointAddr, targetServerAddr, request, protocol, false, err)
		return
	}

	scopedLog.Debug("Forwarding DNS request for a name that is allowed")
	p.NotifyOnDNSMsg(time.Now(), endpointAddr, targetServerAddr, request, protocol, true, nil)

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
		p.NotifyOnDNSMsg(time.Now(), endpointAddr, targetServerAddr, request, protocol, false,
			fmt.Errorf("Cannot parse DNS proxy client network to select forward client: %s", err))
		sendRefused(scopedLog, w, request)
		return
	}

	request.Id = dns.Id() // force a random new ID for this request
	response, _, err := client.Exchange(request, targetServerAddr)
	if err != nil {
		scopedLog.WithError(err).Error("Cannot forward proxied DNS lookup")
		p.NotifyOnDNSMsg(time.Now(), endpointAddr, targetServerAddr, request, protocol, false,
			fmt.Errorf("Cannot forward proxied DNS lookup: %s", err))
		sendRefused(scopedLog, w, request)
		return
	}

	scopedLog.WithField(logfields.Response, response).Debug("Received DNS response to proxied lookup")
	p.NotifyOnDNSMsg(time.Now(), targetServerAddr, endpointAddr, response, protocol, true, nil)

	scopedLog.Debug("Responding to original DNS query")
	// restore the ID to the one in the inital request so it matches what the requester expects.
	response.Id = requestID
	err = w.WriteMsg(response)
	if err != nil {
		scopedLog.WithError(err).Error("Cannot forward proxied DNS response")
		p.NotifyOnDNSMsg(time.Now(), targetServerAddr, endpointAddr, response, protocol, true,
			fmt.Errorf("Cannot forward proxied DNS response: %s", err))
	}
}

// ExtractMsgDetails extracts a canonical query name, any IPs in a response and
// the lowest applicable TTL. When a CNAME is returned the chain is collapsed
// down, keeping the lowest TTL, and CNAME targets are returned.
func ExtractMsgDetails(msg *dns.Msg) (qname string, responseIPs []net.IP, TTL uint32, CNAMEs []string, err error) {
	if len(msg.Question) == 0 {
		return "", nil, 0, nil, errors.New("Invalid DNS message")
	}
	qname = strings.ToLower(string(msg.Question[0].Name))

	// rrName is the name the next RR should include.
	// This will change when we see CNAMEs.
	rrName := strings.ToLower(qname)

	TTL = math.MaxUint32 // a TTL must exist in the RRs

	for _, ans := range msg.Answer {
		// Ensure we have records for DNS names we expect
		if strings.ToLower(ans.Header().Name) != rrName {
			return qname, nil, 0, nil, fmt.Errorf("Unexpected name (%s) in RRs for %s (query for %s)", ans, rrName, qname)
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
	}

	return qname, responseIPs, TTL, CNAMEs, nil
}

// bindToAddr attempts to bind to address and port for both UDP and TCP. If
// port is 0 a random open port is assigned and the same one is used for UDP
// and TCP.
// Note: This mimics what the dns package does EXCEPT for setting reuseport.
// This is ok for now but it would simplify proxy management in the future to
// have it set.
func bindToAddr(address string, port uint16) (UDPConn *net.UDPConn, TCPListener *net.TCPListener, err error) {
	defer func() {
		if err == nil {
			return
		}
		if TCPListener != nil {
			TCPListener.Close()
			TCPListener = nil
		}
		if UDPConn != nil {
			UDPConn.Close()
			UDPConn = nil
		}
	}()

	bindAddr := net.JoinHostPort(address, strconv.Itoa(int(port)))

	TCPAddr, err := net.ResolveTCPAddr("tcp", bindAddr)
	if err != nil {
		return nil, nil, err
	}
	TCPListener, err = net.ListenTCP("tcp", TCPAddr)
	if err != nil {
		return nil, nil, err
	}
	UDPAddr, err := net.ResolveUDPAddr("udp", TCPListener.Addr().String())
	if err != nil {
		return nil, nil, err
	}
	UDPConn, err = net.ListenUDP("udp", UDPAddr)
	if err != nil {
		return nil, nil, err
	}

	return UDPConn, TCPListener, nil
}

// sendRefused creates and sends a REFUSED response for request to w
// The returned error is logged with scopedLog and is returned for convenience
func sendRefused(scopedLog *logrus.Entry, w dns.ResponseWriter, request *dns.Msg) (err error) {
	refused := new(dns.Msg)
	refused.SetRcode(request, dns.RcodeRefused)

	if err = w.WriteMsg(refused); err != nil {
		scopedLog.WithError(err).Error("Cannot send REFUSED response")
		err = fmt.Errorf("cannot send REFUSED response: %s", err)
	}
	return err
}
