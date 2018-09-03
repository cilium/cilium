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
	"strings"
	"time"

	"github.com/cilium/cilium/pkg/fqdn/regexpmap"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/sirupsen/logrus"

	"github.com/miekg/dns"
)

// ProxyForwardTimeout is the maximum time to wait for DNS responses to
// forwarded DNS requests. This is needed since UDP queries have no way to
// indicate that the client has stopped expecting a response.
const ProxyForwardTimeout = 10 * time.Second

// DNSProxy is a L7 proxy for DNS traffic. It keeps a list of allowed DNS
// lookups that can be regexps and blocks lookups that are not allowed.
// A singleton is always running inside cilium-agent.
type DNSProxy struct {
	lock.Mutex

	// BindAddr is the local address we bind to to listen for DNS requests.
	// Note: unlike the other proxies, this server listens on a fixed, shared,
	// port.
	BindAddr string

	// NotifyOnDNSResponse is the callback by which the proxy can emit DNS
	// response data.
	// Note: this is a little pointless since this proxy is in-process but it is
	// intended to allow us to switch to an external proxy process by forcing the
	// design now.
	NotifyOnDNSResponse NotifyOnDNSResponseFunc

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

type NotifyOnDNSResponseFunc func(lookupTime time.Time, name string, ips []net.IP, ttl int) error

// StartDNSProxy starts a proxy used for DNS L7 redirects
func StartDNSProxy(address string, port uint16, notifyFunc NotifyOnDNSResponseFunc) (*DNSProxy, error) {
	if port == 0 {
		return nil, errors.New("DNS proxy port not configured")
	}

	p := &DNSProxy{
		BindAddr:            fmt.Sprintf("%s:%d", address, port),
		NotifyOnDNSResponse: notifyFunc,
		allowed:             regexpmap.NewRegexpMap(),
	}

	// Start the DNS listeners on UDP and TCP
	p.UDPServer = &dns.Server{Addr: p.BindAddr, Net: "udp", Handler: p}
	p.TCPServer = &dns.Server{Addr: p.BindAddr, Net: "tcp", Handler: p}

	for _, s := range []*dns.Server{p.UDPServer, p.TCPServer} {
		go func(server *dns.Server) {
			if err := server.ListenAndServe(); err != nil {
				log.WithError(err).Errorf("Failed to start the %s DNS proxy on %s", server.Net, server.Addr)
			}
		}(s)
	}

	// Bind the DNS forwarding clients on UDP and TCP
	p.UDPClient = &dns.Client{Net: "udp", Timeout: ProxyForwardTimeout, SingleInflight: true}
	p.TCPClient = &dns.Client{Net: "tcp", Timeout: ProxyForwardTimeout, SingleInflight: true}

	return p, nil
}

// AddAllowed adds reStr, a regexp, to the DNS lookups the proxy allows.
func (p *DNSProxy) AddAllowed(reStr, endpointID string) {
	log.WithField("name", reStr).Debug("Adding allowed DNS FQDN pattern")
	reStr = prepareNameMatch(reStr)

	p.Lock()
	defer p.Unlock()
	p.allowed.Add(reStr, endpointID)
}

// RemoveAllowed removes reStr from the DNS lookups the proxy allows. It must
// match the form in AddAllowed exactly (i.e. this isn't removing by regex, but
// by direct equivalence).
func (p *DNSProxy) RemoveAllowed(reStr, endpointID string) {
	log.WithField("name", reStr).Debug("Removing allowed DNS FQDN pattern")
	reStr = prepareNameMatch(reStr)

	p.Lock()
	defer p.Unlock()
	p.allowed.Remove(reStr, endpointID)
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
func (p *DNSProxy) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	qname := string(r.Question[0].Name)
	scopedLog := log.WithFields(logrus.Fields{
		logfields.DNSName: qname,
		logfields.IPAddr:  w.RemoteAddr()})

	scopedLog.Debug("Handling DNS query from endpoint")

	endpointID, err := extractEndpointID(w)
	if err != nil {
		scopedLog.WithError(err).Error("cannot find endpoint ID for DNS request")
		return
	}
	scopedLog = log.WithField(logfields.EndpointID, endpointID)

	// The allowed check is first because we don't want to use DNS responses that
	// endpoints are not allowed to see.
	// Note: The cache doesn't know about the source of the DNS data (yet) and so
	// it won't enforce any separation between results from different endpoints.
	// This isn't ideal but we are trusting the DNS responses anyway.
	if !p.CheckAllowed(qname, fmt.Sprintf("%d", endpointID)) {
		scopedLog.Info("Rejecting DNS query from endpoint")
		return
	}

	scopedLog.Debug("Forwarding DNS name that is allowed")

	targetServer, err := lookupTargetDNSServer(w)
	if err != nil {
		scopedLog.WithError(err).Error("Cannot extract target server to forward DNS request to")
		return
	}
	scopedLog.WithField("server", targetServer).Debug("Found target server to forward DNS request to")

	var client *dns.Client
	switch w.LocalAddr().Network() {
	case "udp":
		client = p.UDPClient
	case "tcp":
		client = p.TCPClient
	default:
		scopedLog.Error("Cannot parse DNS proxy client network to select forward client")
		return
	}

	lookupTime := time.Now()
	response, _, err := client.Exchange(r, targetServer)
	if err != nil {
		scopedLog.WithError(err).Error("Error forwarding proxied DNS lookup")
		return
	}
	scopedLog.WithField(logfields.Response, response).Debug("Recieved DNS response to proxied lookup")

	// emit the response via p.NotifyOnDNSResponse
	scopedLog.Debug("Updating DNS name in cache from response to to query")
	if err := p.notifyWithResponse(lookupTime, qname, response); err != nil {
		scopedLog.WithError(err).Error("Error notifying on DNS response in DNSProxy")
	}

	scopedLog.Debug("Responding to original DNS query")
	w.WriteMsg(response)
}

func (p *DNSProxy) notifyWithResponse(lookupTime time.Time, qname string, response *dns.Msg) error {
	var (
		// rrName is the name the next RR should include.
		// This will change when we see CNAMEs.
		rrName      = strings.ToLower(qname)
		responseIPs []net.IP
		TTL         uint32 = math.MaxUint32
	)
	for _, ans := range response.Answer {
		// Ensure we have records for DNS names we expect
		if strings.ToLower(ans.Header().Name) != rrName {
			return fmt.Errorf("Unexpected name (%s) in RRs for %s (query for %s)", ans, rrName, qname)
		}

		// Handle A, AAAA and CNAME records by accumulating IPs and TTLs
		switch ans := ans.(type) {
		case *dns.A:
			responseIPs = append(responseIPs, ans.A)
			if TTL < ans.Hdr.Ttl {
				TTL = ans.Hdr.Ttl
			}
		case *dns.AAAA:
			responseIPs = append(responseIPs, ans.AAAA)
			if TTL < ans.Hdr.Ttl {
				TTL = ans.Hdr.Ttl
			}
		case *dns.CNAME:
			// We still track the TTL because the lowest TTL in the chain
			// determines the valid caching time for the whole response.
			if TTL < ans.Hdr.Ttl {
				TTL = ans.Hdr.Ttl
			}
			rrName = strings.ToLower(ans.Target)
		}
	}

	return p.NotifyOnDNSResponse(lookupTime, qname, responseIPs, int(TTL))
}
