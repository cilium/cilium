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
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/nodeaddress"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/proxy/accesslog"

	"github.com/braintree/manners"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/vulcand/oxy/forward"
	"github.com/vulcand/route"
)

// Magic markers are attached to each packet. The upper 16 bits are used to
// identify packets which have gone through the proxy and to determine whether
// the packet is coming from a proxy at ingress or egress. The lower 16 bits
// can be used to carry the security identity.
const (
	magicMarkIngress int = 0xFEFA << 16
	magicMarkEgress  int = 0xFEFB << 16
)

// field names used while logging
const (
	fieldMarker = "marker"
	fieldSocket = "socket"
	fieldFd     = "fd"
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
	nodeInfo accesslog.NodeAddressInfo
}

// GetMagicMark returns the magic marker with which each packet must be marked.
// The mark is different depending on whether the proxy is injected at ingress
// or egress.
func (r *Redirect) GetMagicMark() int {
	if r.l4.Ingress {
		return magicMarkIngress
	}

	return magicMarkEgress
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
	GetLabelsSHA() string
	GetIdentity() policy.NumericIdentity
	ResolveIdentity(policy.NumericIdentity) *policy.Identity
	GetIPv4Address() string
	GetIPv6Address() string
	RUnlock()
}

type Proxy struct {
	// mutex is the lock required when modifying any proxy datastructure
	mutex lock.RWMutex

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

func lookupNewDest(req *http.Request, dport uint16) (uint32, string, error) {
	ip, port, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return 0, "", fmt.Errorf("invalid remote address: %s", err)
	}

	pIP := net.ParseIP(ip)
	if pIP == nil {
		return 0, "", fmt.Errorf("unable to parse IP %s", ip)
	}

	sport, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return 0, "", fmt.Errorf("unable to parse port string: %s", err)
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
			return 0, "", fmt.Errorf("Unable to find IPv4 proxy entry for %s: %s", key, err)
		}

		log.Debugf("Found IPv4 proxy entry: %+v", val)
		return val.SourceIdentity, val.HostPort(), nil
	}

	key := &Proxy6Key{
		SPort:   uint16(sport),
		DPort:   dport,
		Nexthdr: 6,
	}

	copy(key.SAddr[:], pIP.To16())

	val, err := LookupEgress6(key)
	if err != nil {
		return 0, "", fmt.Errorf("Unable to find IPv6 proxy entry for %s: %s", key, err)
	}

	log.Debugf("Found IPv6 proxy entry: %+v", val)
	return val.SourceIdentity, val.HostPort(), nil
}

func generateURL(req *http.Request, hostport string) *url.URL {
	newURL := *req.URL
	newURL.Scheme = "http"
	newURL.Host = hostport

	return &newURL
}

var gcOnce sync.Once

// Configuration is used to pass configuration into CreateOrUpdateRedirect
type Configuration struct {
}

func (r *Redirect) localEndpointInfo(info *accesslog.EndpointInfo) {
	r.source.RLock()
	info.ID = r.epID
	info.IPv4 = r.source.GetIPv4Address()
	info.IPv6 = r.source.GetIPv6Address()
	info.Labels = r.source.GetLabels()
	info.LabelsSHA256 = r.source.GetLabelsSHA()
	info.Identity = uint64(r.source.GetIdentity())
	r.source.RUnlock()
}

// fillReservedIdentity resolves the labels of the specified identity if known
// locally and fills in the following info member fields:
//  - info.Identity
//  - info.Labels
//  - info.LabelsSHA256
func (r *Redirect) fillReservedIdentity(info *accesslog.EndpointInfo, id policy.NumericIdentity) {
	info.Identity = uint64(id)

	if c := policy.GetConsumableCache().Lookup(id); c != nil {
		if c.Labels != nil {
			info.Labels = c.Labels.Labels.GetModel()
			info.LabelsSHA256 = c.Labels.GetLabelsSHA256()
		}
	}
}

// egressDestinationInfo returns the destination EndpointInfo for a flow
// leaving the proxy at egress.
func (r *Redirect) egressDestinationInfo(ipstr string, info *accesslog.EndpointInfo) {
	ip := net.ParseIP(ipstr)
	if ip != nil {
		if ip.To4() != nil {
			info.IPv4 = ip.String()

			if nodeaddress.IsHostIPv4(ip) {
				r.fillReservedIdentity(info, policy.ReservedIdentityHost)
				return
			}

			if nodeaddress.GetIPv4ClusterRange().Contains(ip) {
				c := addressing.DeriveCiliumIPv4(ip)
				ep := endpointmanager.LookupIPv4(c.String())
				if ep != nil {
					info.ID = uint64(ep.ID)
					info.Labels = ep.GetLabels()
					info.LabelsSHA256 = ep.GetLabelsSHA()
					info.Identity = uint64(ep.GetIdentity())
				} else {
					r.fillReservedIdentity(info, policy.ReservedIdentityCluster)
				}
			} else {
				r.fillReservedIdentity(info, policy.ReservedIdentityWorld)
			}
		} else {
			info.IPv6 = ip.String()

			if nodeaddress.IsHostIPv6(ip) {
				r.fillReservedIdentity(info, policy.ReservedIdentityHost)
				return
			}

			if nodeaddress.GetIPv6ClusterRange().Contains(ip) {
				c := addressing.DeriveCiliumIPv6(ip)
				id := c.EndpointID()
				info.ID = uint64(id)

				ep := endpointmanager.LookupCiliumID(id)
				if ep != nil {
					ep.RLock()
					info.Labels = ep.GetLabels()
					info.LabelsSHA256 = ep.GetLabelsSHA()
					info.Identity = uint64(ep.GetIdentity())
					ep.RUnlock()
				} else {
					r.fillReservedIdentity(info, policy.ReservedIdentityCluster)
				}
			} else {
				r.fillReservedIdentity(info, policy.ReservedIdentityWorld)
			}
		}
	}
}

// getInfoFromConsumable fills the accesslog.EndpointInfo fields, by fetching
// the consumable from the consumable cache of endpoint using identity sent by
// source. This is needed in ingress proxy while logging the source endpoint
// info.  Since there will be 2 proxies on the same host, if both egress and
// ingress policies are set, the ingress policy cannot determine the source
// endpoint info based on ip address, as the ip address would be that of the
// egress proxy i.e host.
func (r *Redirect) getInfoFromConsumable(ipstr string, info *accesslog.EndpointInfo, srcIdentity policy.NumericIdentity) {
	ep := r.source
	ip := net.ParseIP(ipstr)
	if ip != nil {
		if ip.To4() != nil {
			info.IPv4 = ip.String()
		} else {
			info.IPv6 = ip.String()
		}
	}
	secIdentity := ep.ResolveIdentity(srcIdentity)

	if secIdentity != nil {
		info.Labels = secIdentity.Labels.GetModel()
		info.LabelsSHA256 = secIdentity.Labels.SHA256Sum()
		info.Identity = uint64(srcIdentity)
	}
}

func (r *Redirect) getSourceInfo(req *http.Request, srcIdentity policy.NumericIdentity) (accesslog.EndpointInfo, accesslog.IPVersion) {
	info := accesslog.EndpointInfo{}
	version := accesslog.VersionIPv4
	ipstr, port, err := net.SplitHostPort(req.RemoteAddr)
	if err == nil {
		p, err := strconv.ParseUint(port, 10, 16)
		if err == nil {
			info.Port = uint16(p)
		}

		ip := net.ParseIP(ipstr)
		if ip != nil && ip.To4() == nil {
			version = accesslog.VersionIPV6
		}
	}

	// At egress, the local origin endpoint is the source
	if !r.l4.Ingress {
		r.localEndpointInfo(&info)
	} else if err == nil {
		if srcIdentity != 0 {
			r.getInfoFromConsumable(ipstr, &info, srcIdentity)
		} else {
			// source security identity 0 is possible when somebody else other than the BPF datapath attempts to
			// connect to the proxy.
			// We should log no source information in that case, in the proxy log.
			log.Warn("Missing security identity in source endpoint info")
		}

	}

	return info, version
}

func (r *Redirect) getDestinationInfo(dstIPPort string) accesslog.EndpointInfo {
	info := accesslog.EndpointInfo{}
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
		r.egressDestinationInfo(ipstr, &info)
	}

	return info
}

type proxyIdentity int

const identityKey proxyIdentity = 0

func newIdentityContext(ctx context.Context, id int) context.Context {
	return context.WithValue(ctx, identityKey, id)
}

func identityFromContext(ctx context.Context) (int, bool) {
	val, ok := ctx.Value(identityKey).(int)
	return val, ok
}

func setFdMark(fd, mark int) {
	log.WithFields(log.Fields{
		fieldFd:     fd,
		fieldMarker: mark,
	}).Debug("Setting packet marker of socket")

	err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_MARK, mark)
	if err != nil {
		log.WithFields(log.Fields{
			fieldFd:     fd,
			fieldMarker: mark,
		}).WithError(err).Warning("Unable to set SO_MARK")
	}
}

func setSocketMark(c net.Conn, mark int) {
	if tc, ok := c.(*net.TCPConn); ok {
		if f, err := tc.File(); err == nil {
			defer f.Close()
			setFdMark(int(f.Fd()), mark)
		}
	}
}

func listenSocket(address string, mark int) (net.Listener, error) {
	addr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		return nil, err
	}

	family := syscall.AF_INET
	if addr.IP.To4() == nil {
		family = syscall.AF_INET6
	}

	fd, err := syscall.Socket(family, syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}

	if err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		return nil, fmt.Errorf("unable to set SO_REUSEADDR socket option: %s", err)
	}

	setFdMark(fd, mark)

	sockAddr, err := ipToSockaddr(family, addr.IP, addr.Port, addr.Zone)
	if err != nil {
		syscall.Close(fd)
		return nil, err
	}

	if err := syscall.Bind(fd, sockAddr); err != nil {
		syscall.Close(fd)
		return nil, err
	}

	if err := syscall.Listen(fd, 128); err != nil {
		syscall.Close(fd)
		return nil, err
	}

	f := os.NewFile(uintptr(fd), addr.String())
	defer f.Close()

	return net.FileListener(f)
}

// CreateOrUpdateRedirect creates or updates a L4 redirect with corresponding
// proxy configuration. This will allocate a proxy port as required and launch
// a proxy instance. If the redirect is already in place, only the rules will be
// updated.
func (p *Proxy) CreateOrUpdateRedirect(l4 *policy.L4Filter, id string, source ProxySource) (*Redirect, error) {
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           ciliumDialer,
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
			if err := accesslog.OpenLogfile(lf); err != nil {
				log.WithFields(log.Fields{
					accesslog.FieldFilePath: lf,
				}).WithError(err).Warning("Cannot open L7 access log")
			}
		}

		if labels := viper.GetStringSlice("agent-labels"); len(labels) != 0 {
			accesslog.SetMetadata(labels)
		}

		go func() {
			for {
				time.Sleep(time.Duration(10) * time.Second)
				if deleted := GC(); deleted > 0 {
					log.Debugf("Evicted %d entries from proxy table", deleted)
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
		nodeInfo: accesslog.NodeAddressInfo{
			IPv4: nodeaddress.GetExternalIPv4().String(),
			IPv6: nodeaddress.GetIPv6().String(),
		},
	}

	redir.epID = source.GetID()

	redirect := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		record := &accesslog.LogRecord{
			Request:           req,
			Timestamp:         time.Now().UTC().Format(time.RFC3339Nano),
			NodeAddressInfo:   redir.nodeInfo,
			TransportProtocol: 6, // TCP's IANA-assigned protocol number
		}

		if redir.l4.Ingress {
			record.ObservationPoint = accesslog.Ingress
		} else {
			record.ObservationPoint = accesslog.Egress
		}

		srcIdentity, dstIPPort, err := lookupNewDest(req, to)
		if err != nil {
			// FIXME: What do we do here long term?
			log.Errorf("%s", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			record.Info = fmt.Sprintf("cannot generate url: %s", err)
			accesslog.Log(record, accesslog.TypeRequest, accesslog.VerdictError, http.StatusBadRequest)
			return
		}

		info, version := redir.getSourceInfo(req, policy.NumericIdentity(srcIdentity))
		record.SourceEndpoint = info
		record.IPVersion = version

		if srcIdentity != 0 {
			record.SourceEndpoint.Identity = uint64(srcIdentity)
		}

		record.DestinationEndpoint = redir.getDestinationInfo(dstIPPort)

		// Validate access to L4/L7 resource
		p.mutex.Lock()
		if len(redir.Rules) > 0 {
			rule, _ := redir.router.Route(req)
			if rule == nil {
				http.Error(w, "Access denied", http.StatusForbidden)
				p.mutex.Unlock()
				accesslog.Log(record, accesslog.TypeRequest, accesslog.VerdictDenied, http.StatusForbidden)
				return
			}
			ar := rule.(policy.AuxRule)
			log.Debugf("Allowing request based on rule %+v", ar)
			record.Info = fmt.Sprintf("rule: %+v", ar)
		} else {
			log.Debugf("Allowing request as there are no rules")
		}
		p.mutex.Unlock()

		// Reconstruct original URL used for the request
		req.URL = generateURL(req, dstIPPort)

		// log valid request
		accesslog.Log(record, accesslog.TypeRequest, accesslog.VerdictForwarded, http.StatusOK)

		ctx := req.Context()
		if ctx != nil {
			marker := redir.GetMagicMark() | int(record.SourceEndpoint.Identity)
			req = req.WithContext(newIdentityContext(ctx, marker))
		}

		fwd.ServeHTTP(w, req)

		// log valid response
		record.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
		accesslog.Log(record, accesslog.TypeResponse, accesslog.VerdictForwarded, http.StatusOK)
	})

	redir.server = manners.NewWithServer(&http.Server{
		Addr:    fmt.Sprintf("[::]:%d", to),
		Handler: redirect,

		// Set a large timeout for ReadTimeout. This timeout controls
		// the time that can pass between accepting the connection and
		// reading the entire request. The default 10 seconds is not
		// long enough.
		ReadTimeout: 120 * time.Second,
	})

	redir.updateRules(l4.L7Rules)
	p.allocatedPorts[to] = redir
	p.redirects[id] = redir

	p.mutex.Unlock()

	log.Debugf("Created new proxy instance %+v", redir)

	// The following code up until the go-routine is from manners/sever.go:ListenAndServe()
	// It was extracted in order to keep the listening on the TCP socket synchronous so that
	// when policies are regenerated, the port is listening for connections before policy
	// revisions get bumped for an endpoint.
	addr := redir.server.Addr
	if addr == "" {
		addr = ":http"
	}

	marker := redir.GetMagicMark()

	// As ingress proxy, all replies to incoming requests must have the
	// identity of the endpoint we are proxying for
	if redir.l4.Ingress {
		marker |= int(source.GetIdentity())
	}

	// Listen needs to be in the synchronous part of this function to ensure that
	// the proxy port is never refusing connections.
	listener, err := listenSocket(addr, marker)
	if err != nil {
		return nil, err
	}

	go func() {
		err := redir.server.Serve(listener)
		if err != nil {
			log.Errorf("Unable to listen and serve proxy: %s", err)
		}
	}()

	return redir, nil
}

func (p *Proxy) RemoveRedirect(id string) error {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	r, ok := p.redirects[id]
	if !ok {
		return fmt.Errorf("unable to find redirect %s", id)
	}

	log.Debugf("removing proxy redirect %s", id)
	r.server.Close()

	delete(p.redirects, r.id)
	delete(p.allocatedPorts, r.ToPort)

	return nil
}
