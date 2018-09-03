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
	"github.com/cilium/cilium/pkg/maps/proxymap"
	"github.com/sirupsen/logrus"

	"github.com/miekg/dns"
)

const ProxyForwardTimeout = 10 * time.Second

type DNSProxy struct {
	lock.Mutex

	BindAddr             string
	NotifyOnDNSResponse  NotifyOnDNSResponseFunc
	UDPServer, TCPServer *dns.Server
	UDPClient, TCPClient *dns.Client
	allowed              *regexpmap.RegexpMap
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
	p.UDPServer = &dns.Server{Addr: p.BindAddr, Net: "udp", Handler: p}
	p.TCPServer = &dns.Server{Addr: p.BindAddr, Net: "tcp", Handler: p}

	p.UDPClient = &dns.Client{Net: "udp", Timeout: ProxyForwardTimeout, SingleInflight: true}
	p.TCPClient = &dns.Client{Net: "tcp", Timeout: ProxyForwardTimeout, SingleInflight: true}

	for _, s := range []*dns.Server{p.UDPServer, p.TCPServer} {
		go func(server *dns.Server) {
			if err := server.ListenAndServe(); err != nil {
				log.WithError(err).Errorf("Failed to start the %s DNS proxy on %d", server.Net, server.Addr)
			}
		}(s)
	}

	return p, nil
}

// AddAllowed adds name to the DNS lookups the proxy allows. It can be a regex.
func (p *DNSProxy) AddAllowed(name, source string) {
	log.WithField("name", name).Debug("DNS Proxy: Adding allowed pattern")
	name = prepareNameMatch(name)

	p.Lock()
	defer p.Unlock()
	p.allowed.Add(name, source)
}

// AddAllowed removes name from the DNS lookups the proxy allows. It must match
// the form in AddAllowed exactly, even if it is a regex.
func (p *DNSProxy) RemoveAllowed(name, source string) {
	log.WithField("name", name).Debug("DNS Proxy: Removing allowed pattern")
	name = prepareNameMatch(name)

	p.Lock()
	defer p.Unlock()
	p.allowed.Remove(name, source)
}

// CheckAllowed checks name against the rules added to the proxy.
func (p *DNSProxy) CheckAllowed(name string) bool {
	p.Lock()
	defer p.Unlock()
	return len(p.allowed.Lookup(name)) > 0
}

// ServeDNS handles individual DNS requests forwarded to the proxy, and meets
// the dns.Handler interface.
func (p *DNSProxy) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	var (
		err       error
		qname     = dns.Fqdn(string(r.Question[0].Name))
		scopedLog = log.WithFields(logrus.Fields{
			logfields.DNSName: qname,
			logfields.IPAddr:  w.RemoteAddr()})
	)

	scopedLog.Debug("DNS Proxy: Handling query from endpoint")

	targetServer, err := lookupTargetDNSServer(w)
	if err != nil {
		scopedLog.WithError(err).Error("cannot forward DNS request")
		return
	}

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
		log.WithError(err).Error("Error doing DNS lookup")
		return
	}
	scopedLog.WithField(logfields.Response, response).Debug("DNS Proxy: Saw response")

	// emit the response via p.NotifyOnDNSResponse
	scopedLog.Debug("DNS Proxy: Updating DNS name in cache from response to to query")
	if err := p.notifyWithResponse(lookupTime, qname, response); err != nil {
		scopedLog.WithError(err).Error("DNS Proxy: Error notifying on DNS response in DNSProxy")
	}

	// This check is after the actual lookup to allow emitting the notification
	// and populating caches with information even when it isn't returned.
	if !p.CheckAllowed(qname) {
		scopedLog.Debug("DNS Proxy: Rejecting query from endpoint")
		return
	}

	scopedLog.Debug("DNS Proxy: Responding to query")
	w.WriteMsg(response)
}

// prepareNameMatch ensures that a name is an anchored regexp.
func prepareNameMatch(name string) string {
	out := make([]string, 0, 3)
	if !strings.HasPrefix(name, "^") {
		out = append(out, "^")
	}
	out = append(out, dns.Fqdn(name))
	if !strings.HasSuffix(name, "$") {
		out = append(out, "$")
	}
	return strings.Join(out, "")
}

// lookupTargetDNSServer finds the intended DNS target server for a specific
// request (passed in via ServeDNS) in proxymap. The IP:port combination is
// returned.
func lookupTargetDNSServer(w dns.ResponseWriter) (server string, err error) {
	key, err := createProxyMapKey(w)
	if err != nil {
		return "", fmt.Errorf("cannot create proxymap key: %s", err)
	}

	val, err := proxymap.Lookup(key)
	if err != nil {
		return "", fmt.Errorf("proxymap lookup failed: %s", err)
	}

	return val.HostPort(), nil
}

// splitPortHostProto returns the IP, port and protocol of a net.Addr in native
// form.
func splitPortHostProto(addr net.Addr) (ip net.IP, port uint16, proto string, err error) {
	switch addr := addr.(type) {
	case *net.TCPAddr:
		return addr.IP, uint16(addr.Port), addr.Network(), nil
	case *net.UDPAddr:
		return addr.IP, uint16(addr.Port), addr.Network(), nil
	default:
		return nil, 0, "", fmt.Errorf("unknown address type: %v", addr)
	}
}

// createProxyMapKey creates a lookup key from a dns.ResponseWriter, using the
// .RemoteAddr, .LocalAddr and .Network calls.
// This function is similar to proxy.createProxyMapKey.
func createProxyMapKey(w dns.ResponseWriter) (mapKey proxymap.ProxyMapKey, err error) {
	clientSourceIP, clientSourcePort, _, err := splitPortHostProto(w.RemoteAddr())
	if err != nil {
		return nil, fmt.Errorf("invalid remote address '%s'", w.RemoteAddr().String())
	}

	_, proxyListenPort, protocolStr, err := splitPortHostProto(w.LocalAddr())
	if err != nil {
		return nil, fmt.Errorf("invalid proxy address '%s'", w.LocalAddr().String())
	}

	// TODO: These are determined by experiment. Find where they are defined.
	var protocol uint8
	switch protocolStr {
	case "udp":
		protocol = uint8(17)
	case "tcp":
		protocol = uint8(6)
	default:
		return nil, fmt.Errorf("Unsupported network protocol %s", w.RemoteAddr().Network())
	}

	if clientSourceIP.To4() != nil {
		key := proxymap.Proxy4Key{
			SPort:   uint16(clientSourcePort),
			DPort:   proxyListenPort,
			Nexthdr: protocol,
		}

		copy(key.SAddr[:], clientSourceIP.To4())
		return key, nil
	}

	key := proxymap.Proxy6Key{
		SPort:   uint16(clientSourcePort),
		DPort:   proxyListenPort,
		Nexthdr: protocol,
	}

	copy(key.SAddr[:], clientSourceIP.To16())
	return key, nil
}

func (p *DNSProxy) notifyWithResponse(lookupTime time.Time, qname string, response *dns.Msg) error {
	var (
		// rrName is the name each RRs should include.
		// This will change when we see CNAMEs.
		rrName      = qname
		responseIPs []net.IP
		Ttl         uint32 = math.MaxUint32
	)
	for _, ans := range response.Answer {
		// Ensure we have records for DNS names we expect
		if ans.Header().Name != rrName {
			return fmt.Errorf("Unexpected name (%s) in RRs for %s (query for %s)", ans, rrName, qname)
		}

		// Handle A, AAAA and CNAME records by accumulating IPs and TTLs
		switch ans := ans.(type) {
		case *dns.A:
			responseIPs = append(responseIPs, ans.A)
			if Ttl < ans.Hdr.Ttl {
				Ttl = ans.Hdr.Ttl
			}
		case *dns.AAAA:
			responseIPs = append(responseIPs, ans.AAAA)
			if Ttl < ans.Hdr.Ttl {
				Ttl = ans.Hdr.Ttl
			}
		case *dns.CNAME:
			// We still track the TTL because the lowest TTL in the chain
			// determines the valid caching time for the whole response.
			if Ttl < ans.Hdr.Ttl {
				Ttl = ans.Hdr.Ttl
			}
			rrName = ans.Target
		}
	}

	return p.NotifyOnDNSResponse(lookupTime, qname, responseIPs, int(Ttl))
}
