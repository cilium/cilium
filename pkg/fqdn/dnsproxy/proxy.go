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
	"net"
	"time"

	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/fqdn/regexpmap"
	"github.com/cilium/cilium/pkg/lock"

	"github.com/miekg/dns"
)

type DNSProxy struct {
	lock.Mutex

	BindAddr             string
	NotifyOnDNSResponse  NotifyOnDNSResponseFunc
	UDPServer, TCPServer *dns.Server
	allowed              *regexpmap.RegexpMap
}

type NotifyOnDNSResponseFunc func(lookupTime time.Time, name string, ips []net.IP, ttl int) error

// StartDNSProxy starts a proxy used for DNS L7 redirects
func StartDNSProxy(address string, port uint16, notifyFunc NotifyOnDNSResponseFunc) (*DNSProxy, error) {
	if port == 0 {
		return nil, errors.New("DNS proxy port not configured")
	}

	p := &DNSProxy{
		BindAddr: fmt.Sprintf("%s:%d", address, port),
		allowed:  regexpmap.NewRegexpMap(),
	}
	p.UDPServer = &dns.Server{Addr: p.BindAddr, Net: "udp", Handler: p}
	p.TCPServer = &dns.Server{Addr: p.BindAddr, Net: "tcp", Handler: p}

	for _, s := range []*dns.Server{p.UDPServer, p.TCPServer} {
		go func(server *dns.Server) {
			if err := server.ListenAndServe(); err != nil {
				log.WithError(err).Errorf("Failed to start the %s DNS proxy on %d", server.Net, server.Addr)
			}
		}(s)
	}

	return p, nil
}

func (p *DNSProxy) AddAllowed(name, source string) {
	log.WithField("name", name).Debug("DNS Proxy: Adding allowed pattern")

	p.Lock()
	defer p.Unlock()
	p.allowed.Add(name, source)
}

func (p *DNSProxy) RemoveAllowed(name, source string) {
	log.WithField("name", name).Debug("DNS Proxy: Removing allowed pattern")

	p.Lock()
	defer p.Unlock()
	p.allowed.Add(name, source)
}

func (p *DNSProxy) CheckAllowed(name string) bool {
	p.Lock()
	defer p.Unlock()
	return len(p.allowed.Lookup(name)) > 0
}

func (p *DNSProxy) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	qname := dns.Fqdn(string(r.Question[0].Name))
	log.Infof("DNS Proxy: Handling query for %s from %s on %s", qname, w.RemoteAddr(), w.LocalAddr())

	now := time.Now()
	responses, errors := fqdn.DNSLookupDefaultResolver([]string{qname})
	for _, err := range errors {
		log.WithError(err).Errorf("cannot do DNS lookup for %s", qname)
		return
	}
	for respName, response := range responses {
		if respName != qname {
			log.Warnf("Unexpected name in DNS response %s, qname was %s", respName, qname)
			continue
		}
		for _, ip := range response.IPs {
			switch {
			case ip.To4() != nil && r.Question[0].Qtype == dns.TypeA:
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: uint32(response.TTL)},
					A:   ip,
				})
			case ip.To4() == nil && r.Question[0].Qtype == dns.TypeAAAA:
				m.Answer = append(m.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: qname, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: uint32(response.TTL)},
					AAAA: ip,
				})
			}
		}

		log.Infof("DNS Proxy: Updating %s in cache from response to to query from %s", qname, w.RemoteAddr())
		err := p.NotifyOnDNSResponse(now, respName, response.IPs, response.TTL)
		if err != nil {
			log.WithError(err).Error("Error notifying on DNS response in DNSProxy")
		}
	}

	// This check is after the actual lookup to allow emitting the notification
	// and populate caches with information even when it isn't used.
	if !p.CheckAllowed(qname) {
		log.Warnf("DNS Proxy: Rejecting query for %s from %s on %s", qname, w.RemoteAddr(), w.LocalAddr())
		return
	}

	log.Infof("DNS Proxy: Responding to query for %s from %s on %s with %+v", qname, w.RemoteAddr(), w.LocalAddr(), m)
	w.WriteMsg(m)
}
