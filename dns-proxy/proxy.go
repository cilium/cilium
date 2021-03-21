// Copyright 2021 Authors of Cilium
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

package main

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"

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

	// lookupTargetDNSServer extracts the originally intended target of a DNS
	// query. It is always set to lookupTargetDNSServer in
	// helpers.go but is modified during testing.
	lookupTargetDNSServer func(w dns.ResponseWriter) (serverIP net.IP, serverPort uint16, addrStr string, err error)

	notifyPair func(net.IP, string)

	// this mutex protects variables below this point
	lock.Mutex

	// rejectReply is the OPCode send from the DNS-proxy to the endpoint if the
	// DNS request is invalid
	rejectReply int32
}

// StartDNSProxy starts a proxy used for DNS L7 redirects that listens on
// address and port.
// address is the bind address to listen on. Empty binds to all local
// addresses.
// port is the port to bind to for both UDP and TCP. 0 causes the kernel to
// select a free port.
// notifyFunc will be called with DNS response data that is returned to a
// requesting endpoint. Note that denied requests will not trigger this
// callback.
func StartDNSProxy(address string, port uint16, enableDNSCompression bool, maxRestoreDNSIPs int, notifyPair func(net.IP, string)) (*DNSProxy, error) {
	if port == 0 {
		log.Debug("DNS Proxy port is configured to 0. A random port will be assigned by the OS.")
	}

	p := &DNSProxy{
		lookupTargetDNSServer: dnsproxy.LookupTargetDNSServer,
		EnableDNSCompression:  enableDNSCompression,
		notifyPair:            notifyPair,
	}
	atomic.StoreInt32(&p.rejectReply, dns.RcodeRefused)

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
	stat := dnsproxy.ProxyRequestContext{}
	stat.ProcessingTime.Start()
	requestID := request.Id // keep the original request ID
	qname := string(request.Question[0].Name)
	protocol := w.LocalAddr().Network()
	scopedLog := log.WithFields(logrus.Fields{
		logfields.DNSName:      qname,
		logfields.IPAddr:       w.RemoteAddr(),
		logfields.DNSRequestID: request.Id})
	scopedLog.Debug("Handling DNS query from endpoint")

	_, _, targetServerAddr, err := p.lookupTargetDNSServer(w)
	if err != nil {
		log.WithError(err).Error("cannot extract destination IP:port from DNS request")
		stat.Err = fmt.Errorf("Cannot extract destination IP:port from DNS request: %s", err)
		stat.ProcessingTime.End(false)
		p.sendRefused(scopedLog, w, request)
		return
	}

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
		} else {
			scopedLog.WithError(err).Error("Cannot forward proxied DNS lookup")
			p.sendRefused(scopedLog, w, request)
			stat.Err = fmt.Errorf("Cannot forward proxied DNS lookup: %s", err)
		}
		return
	}

	scopedLog.WithField(logfields.Response, response).Debug("Received DNS response to proxied lookup")
	stat.Success = true

	qname, ips, _, _, _, _, _, err := ExtractMsgDetails(response)
	if err != nil {
		scopedLog.WithError(err).Warn("Unable to extract msg details")
		return
	}

	if len(ips) == 0 {
		scopedLog.WithError(err).WithField("fqdn", qname).Warn("empty ips")
		return
	}

	p.notifyPair(ips[0], qname)

	scopedLog.Debug("Responding to original DNS query")
	// restore the ID to the one in the initial request so it matches what the requester expects.
	response.Id = requestID
	response.Compress = p.EnableDNSCompression && shouldCompressResponse(request, response)
	err = w.WriteMsg(response)
	if err != nil {
		scopedLog.WithError(err).Error("Cannot forward proxied DNS response")
		stat.Err = fmt.Errorf("Cannot forward proxied DNS response: %s", err)
	}
}

// sendRefused creates and sends a REFUSED response for request to w
// The returned error is logged with scopedLog and is returned for convenience
func (p *DNSProxy) sendRefused(scopedLog *logrus.Entry, w dns.ResponseWriter, request *dns.Msg) (err error) {
	refused := new(dns.Msg)
	refused.SetRcode(request, int(atomic.LoadInt32(&p.rejectReply)))

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
		atomic.StoreInt32(&p.rejectReply, dns.RcodeNameError)
	case strings.ToLower(option.FQDNProxyDenyWithRefused):
		atomic.StoreInt32(&p.rejectReply, dns.RcodeRefused)
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
