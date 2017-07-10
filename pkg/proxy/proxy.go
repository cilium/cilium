// Copyright 2016-2017 Authors of Cilium
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

package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/nodeaddress"
	"github.com/cilium/cilium/pkg/policy"

	log "github.com/Sirupsen/logrus"
	"github.com/braintree/manners"
	"github.com/spf13/viper"
	"github.com/vulcand/oxy/forward"
	"github.com/vulcand/route"
)

type Redirect struct {
	id       string
	FromPort uint16
	ToPort   uint16
	epID     uint64
	Rules    []policy.AuxRule
	source   ProxySource
	server   *manners.GracefulServer
	router   route.Router
	l4       policy.L4Filter // stale copy, ignore rules
	nodeInfo NodeAddressInfo
}

func (r *Redirect) updateRules(rules []policy.AuxRule) {
	for _, v := range r.Rules {
		r.router.RemoveRoute(v.Expr)
	}

	r.Rules = make([]policy.AuxRule, len(rules))
	copy(r.Rules, rules)

	for _, v := range r.Rules {
		r.router.AddRoute(v.Expr, v)
	}
}

type ProxySource interface {
	GetID() uint64
	RLock()
	GetLabels() []string
	GetIdentity() policy.NumericIdentity
	GetIPv4Address() string
	GetIPv6Address() string
	RUnlock()
}

type Proxy struct {
	// mutex is the lock required when modifying any proxy datastructure
	mutex sync.RWMutex

	// rangeMin is the minimum port used for proxy port allocation
	rangeMin uint16

	// rangeMax is the maximum port used for proxy port allocation.
	// If port is unspecified, the proxy will automatically allocate
	// ports out of the rangeMin-rangeMax range.
	rangeMax uint16

	// nextPort is the next available proxy port to use
	nextPort uint16

	// allocatedPorts is a map of all allocated proxy ports pointing
	// to the redirect rules attached to that port
	allocatedPorts map[uint16]*Redirect

	// redirects is a map of all redirect configurations indexed by
	// the redirect identifier
	redirects map[string]*Redirect
}

func NewProxy(minPort uint16, maxPort uint16) *Proxy {
	return &Proxy{
		rangeMin:       minPort,
		rangeMax:       maxPort,
		nextPort:       minPort,
		redirects:      make(map[string]*Redirect),
		allocatedPorts: make(map[uint16]*Redirect),
	}
}

func (p *Proxy) allocatePort() (uint16, error) {
	port := p.nextPort

	for {
		resPort := port
		port++
		if port >= p.rangeMax {
			port = p.rangeMin
		}

		if _, ok := p.allocatedPorts[resPort]; !ok {
			return resPort, nil
		}

		if port == p.nextPort {
			return 0, fmt.Errorf("no available proxy ports")
		}
	}
}

func lookupNewDest(req *http.Request, dport uint16) (string, error) {
	ip, port, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return "", fmt.Errorf("invalid remote address: %s", err)
	}

	pIP := net.ParseIP(ip)
	if pIP == nil {
		return "", fmt.Errorf("unable to parse IP %s", ip)
	}

	sport, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return "", fmt.Errorf("unable to parse port string: %s", err)
	}

	if pIP.To4() != nil {
		key := &Proxy4Key{
			SPort:   uint16(sport),
			DPort:   dport,
			Nexthdr: 6,
		}

		copy(key.SAddr[:], pIP.To4())

		val, err := LookupEgress4(key)
		if err != nil {
			return "", fmt.Errorf("Unable to find IPv4 proxy entry for %s: %s", key, err)
		}

		log.Debugf("Found IPv4 proxy entry: %+v", val)
		return val.HostPort(), nil
	}

	key := &Proxy6Key{
		SPort:   uint16(sport),
		DPort:   dport,
		Nexthdr: 6,
	}

	copy(key.SAddr[:], pIP.To16())

	val, err := LookupEgress6(key)
	if err != nil {
		return "", fmt.Errorf("Unable to find IPv6 proxy entry for %s: %s", key, err)
	}

	log.Debugf("Found IPv6 proxy entry: %+v", val)
	return val.HostPort(), nil
}

func generateURL(req *http.Request, hostport string) *url.URL {
	newUrl := *req.URL
	newUrl.Scheme = "http"
	newUrl.Host = hostport

	return &newUrl
}

var gcOnce sync.Once

// Configuration is used to pass configuration into CreateOrUpdateRedirect
type Configuration struct {
}

func (r *Redirect) localEndpointInfo(info *EndpointInfo) {
	r.source.RLock()
	info.ID = r.epID
	info.IPv4 = r.source.GetIPv4Address()
	info.IPv6 = r.source.GetIPv6Address()
	info.Labels = r.source.GetLabels()
	info.Identity = uint64(r.source.GetIdentity())
	r.source.RUnlock()
}

func parseIPPort(ipstr string, info *EndpointInfo) {
	ip := net.ParseIP(ipstr)
	if ip != nil {
		if ip.To4() != nil {
			info.IPv4 = ip.String()
			if nodeaddress.GetIPv4ClusterRange().Contains(ip) {
				c := addressing.DeriveCiliumIPv4(ip)
				ep := endpointmanager.LookupIPv4(c.String())
				if ep != nil {
					info.ID = uint64(ep.ID)
					info.Labels = ep.GetLabels()
					info.Identity = uint64(ep.GetIdentity())
				}
			}
		} else {
			info.IPv6 = ip.String()
			if nodeaddress.GetIPv6ClusterRange().Contains(ip) {
				c := addressing.DeriveCiliumIPv6(ip)
				id := c.EndpointID()
				info.ID = uint64(id)

				ep := endpointmanager.LookupCiliumID(id)
				ep.RLock()
				if ep != nil {
					info.Labels = ep.GetLabels()
					info.Identity = uint64(ep.GetIdentity())
				}
				ep.RUnlock()
			}
		}
	}
}

func (r *Redirect) getSourceInfo(req *http.Request) (EndpointInfo, IPVersion) {
	info := EndpointInfo{}
	version := VersionIPv4

	ipstr, port, err := net.SplitHostPort(req.RemoteAddr)
	if err == nil {
		p, err := strconv.ParseUint(port, 10, 16)
		if err == nil {
			info.Port = uint16(p)
		}

		ip := net.ParseIP(ipstr)
		if ip != nil && ip.To4() == nil {
			version = VersionIPV6
		}
	}

	// At egress, the local origin endpoint is the source
	if !r.l4.Ingress {
		r.localEndpointInfo(&info)
	} else if err == nil {
		parseIPPort(ipstr, &info)
	}

	return info, version
}

func (r *Redirect) getDestinationInfo(dstIPPort string) EndpointInfo {
	info := EndpointInfo{}

	ipstr, port, err := net.SplitHostPort(dstIPPort)
	if err == nil {
		p, err := strconv.ParseUint(port, 10, 16)
		if err == nil {
			info.Port = uint16(p)
		}
	}

	// At ingress the local origin endpoint is the source
	if r.l4.Ingress {
		r.localEndpointInfo(&info)
	} else if err == nil {
		parseIPPort(ipstr, &info)
	}

	return info
}

const identityKey int = 0

func newIdentityContext(ctx context.Context, id int) context.Context {
	return context.WithValue(ctx, identityKey, id)
}

func identityFromContext(ctx context.Context) (int, bool) {
	val, ok := ctx.Value(identityKey).(int)
	return val, ok
}

// CreateOrUpdateRedirect creates or updates a L4 redirect with corresponding
// proxy configuration. This will allocate a proxy port as required and launch
// a proxy instance. If the redirect is aleady in place, only the rules will be
// updated.
func (p *Proxy) CreateOrUpdateRedirect(l4 *policy.L4Filter, id string, source ProxySource) (*Redirect, error) {
	customDialer := func(ctx context.Context, network, address string) (net.Conn, error) {
		d := &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}

		c, err := d.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}

		if id, ok := identityFromContext(ctx); ok {
			if tc, ok := c.(*net.TCPConn); ok {
				if f, err := tc.File(); err == nil {
					defer f.Close()
					fd := int(f.Fd())
					err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, id)
					if err != nil {
						log.Debugf("Unable to set SO_MARK socket option: %s", err)
					}
				}
			}
		}

		return c, err
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           customDialer,
		MaxIdleConns:          2048,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	fwd, err := forward.New(forward.RoundTripper(transport))
	if err != nil {
		return nil, err
	}

	if strings.ToLower(l4.L7Parser) != "http" {
		return nil, fmt.Errorf("unknown L7 protocol \"%s\"", l4.L7Parser)
	}

	for _, r := range l4.L7Rules {
		if !route.IsValid(r.Expr) {
			return nil, fmt.Errorf("invalid filter expression: %s", r.Expr)
		}
	}

	gcOnce.Do(func() {
		if lf := viper.GetString("access-log"); lf != "" {
			if err := OpenLogfile(lf); err != nil {
				log.Warningf("cannot open access log: %s", err)
			}
		}

		if labels := viper.GetStringSlice("agent-labels"); len(labels) != 0 {
			SetMetadata(labels)
		}

		go func() {
			for {
				time.Sleep(time.Duration(10) * time.Second)
				if deleted := GC(); deleted > 0 {
					log.Debugf("Evicted %d entries from proxy table\n", deleted)
				}
			}
		}()
	})

	p.mutex.Lock()

	if r, ok := p.redirects[id]; ok {
		r.updateRules(l4.L7Rules)
		log.Debugf("updated existing proxy instance %+v", r)
		p.mutex.Unlock()
		return r, nil
	}

	to, err := p.allocatePort()
	if err != nil {
		p.mutex.Unlock()
		return nil, err
	}

	redir := &Redirect{
		id:       id,
		FromPort: uint16(l4.Port),
		ToPort:   to,
		source:   source,
		router:   route.New(),
		l4:       *l4,
		nodeInfo: NodeAddressInfo{
			IPv4: nodeaddress.GetExternalIPv4().String(),
			IPv6: nodeaddress.GetIPv6().String(),
		},
	}

	redir.epID = source.GetID()

	redirect := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		record := &LogRecord{
			request:         *req,
			Timestamp:       time.Now().UTC().Format(time.RFC3339Nano),
			NodeAddressInfo: redir.nodeInfo,
		}

		info, version := redir.getSourceInfo(req)
		record.SourceEndpoint = info
		record.IPVersion = version

		if redir.l4.Ingress {
			record.ObservationPoint = Ingress
		} else {
			record.ObservationPoint = Egress
		}

		dstIPPort, err := lookupNewDest(req, to)
		if err != nil {
			// FIXME: What do we do here long term?
			log.Errorf("%s", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			record.Info = fmt.Sprintf("cannot generate url: %s", err)
			Log(record, TypeRequest, VerdictError, http.StatusBadRequest)
			return
		}

		record.DestinationEndpoint = redir.getDestinationInfo(dstIPPort)

		// Validate access to L4/L7 resource
		p.mutex.Lock()
		if len(redir.Rules) > 0 {
			rule, _ := redir.router.Route(req)
			if rule == nil {
				http.Error(w, "Access denied", http.StatusForbidden)
				p.mutex.Unlock()
				Log(record, TypeRequest, VerdictDenied, http.StatusForbidden)
				return
			} else {
				ar := rule.(policy.AuxRule)
				log.Debugf("Allowing request based on rule %+v\n", ar)
				record.Info = fmt.Sprintf("rule: %+v", ar)
			}
		}
		p.mutex.Unlock()

		// Reconstruct original URL used for the request
		req.URL = generateURL(req, dstIPPort)

		// log valid request
		Log(record, TypeRequest, VerdictForwared, http.StatusOK)

		ctx := req.Context()
		if ctx != nil {
			req = req.WithContext(newIdentityContext(ctx, int(record.SourceEndpoint.Identity)))
		}

		fwd.ServeHTTP(w, req)

		// log valid response
		record.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
		Log(record, TypeResponse, VerdictForwared, http.StatusOK)
	})

	redir.server = manners.NewWithServer(&http.Server{
		Addr:    fmt.Sprintf("[::]:%d", to),
		Handler: redirect,
	})

	redir.updateRules(l4.L7Rules)
	p.allocatedPorts[to] = redir
	p.redirects[id] = redir

	p.mutex.Unlock()

	log.Debugf("Created new proxy intance %+v", redir)

	go redir.server.ListenAndServe()

	return redir, nil
}

func (p *Proxy) RemoveRedirect(id string) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if r, ok := p.redirects[id]; !ok {
		return fmt.Errorf("unable to find redirect %s", id)
	} else {
		r.server.Close()

		delete(p.redirects, r.id)
		delete(p.allocatedPorts, r.ToPort)
	}

	return nil
}
