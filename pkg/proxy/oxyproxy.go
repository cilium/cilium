// Copyright 2017 Authors of Cilium
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
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logfields"
	"github.com/cilium/cilium/pkg/nodeaddress"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/proxy/accesslog"

	"github.com/braintree/manners"
	log "github.com/sirupsen/logrus"
	"github.com/vulcand/oxy/forward"
	"github.com/vulcand/route"
)

// OxyRedirect implements the Redirect interface for a l7 proxy
type OxyRedirect struct {
	id       string
	toPort   uint16
	epID     uint64
	source   ProxySource
	server   *manners.GracefulServer
	ingress  bool
	nodeInfo accesslog.NodeAddressInfo

	mutex  lock.RWMutex // protecting the fields below
	rules  []string
	router route.Router
}

// ToPort returns the redirect port of an OxyRedirect
func (r *OxyRedirect) ToPort() uint16 {
	return r.toPort
}

func (r *OxyRedirect) updateRules(rules []string) {
	for _, v := range r.rules {
		r.router.RemoveRoute(v)
	}

	r.rules = make([]string, len(rules))
	copy(r.rules, rules)

	for _, v := range r.rules {
		r.router.AddRoute(v, v)
	}
}

func (r *OxyRedirect) localEndpointInfo(info *accesslog.EndpointInfo) {
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
func (r *OxyRedirect) fillReservedIdentity(info *accesslog.EndpointInfo, id policy.NumericIdentity) {
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
func (r *OxyRedirect) egressDestinationInfo(ipstr string, info *accesslog.EndpointInfo) {
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
func (r *OxyRedirect) getInfoFromConsumable(ipstr string, info *accesslog.EndpointInfo, srcIdentity policy.NumericIdentity) {
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

func (r *OxyRedirect) getSourceInfo(req *http.Request, srcIdentity policy.NumericIdentity) (accesslog.EndpointInfo, accesslog.IPVersion) {
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
	if !r.ingress {
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

func (r *OxyRedirect) getDestinationInfo(dstIPPort string) accesslog.EndpointInfo {
	info := accesslog.EndpointInfo{}
	ipstr, port, err := net.SplitHostPort(dstIPPort)
	if err == nil {
		p, err := strconv.ParseUint(port, 10, 16)
		if err == nil {
			info.Port = uint16(p)
		}
	}

	// At ingress the local origin endpoint is the source
	if r.ingress {
		r.localEndpointInfo(&info)
	} else if err == nil {
		r.egressDestinationInfo(ipstr, &info)
	}

	return info
}

func getOxyPolicyRules(rules []api.PortRuleHTTP) ([]string, error) {
	var l7rules []string

	for _, h := range rules {
		var r string

		if h.Path != "" {
			r = "PathRegexp(\"" + h.Path + "\")"
		}

		if h.Method != "" {
			if r != "" {
				r += " && "
			}
			r += "MethodRegexp(\"" + h.Method + "\")"
		}

		if h.Host != "" {
			if r != "" {
				r += " && "
			}
			r += "HostRegexp(\"" + h.Host + "\")"
		}

		for _, hdr := range h.Headers {
			s := strings.SplitN(hdr, " ", 2)
			if r != "" {
				r += " && "
			}
			r += "Header(\""
			if len(s) == 2 {
				// Remove ':' in "X-Key: true"
				key := strings.TrimRight(s[0], ":")
				r += key + "\",\"" + s[1]
			} else {
				r += s[0]
			}
			r += "\")"
		}

		if !route.IsValid(r) {
			return nil, fmt.Errorf("invalid filter expression: %s", r)
		}
		l7rules = append(l7rules, r)
	}

	return l7rules, nil
}

func translateOxyPolicyRules(l4 *policy.L4Filter) ([]string, error) {
	var l7rules []string

	for _, ep := range l4.L7RulesPerEp {
		rules, err := getOxyPolicyRules(ep.HTTP)
		if err != nil {
			return nil, err
		}
		l7rules = append(rules, l7rules...)
	}

	return l7rules, nil
}

func generateURL(req *http.Request, hostport string) *url.URL {
	newURL := *req.URL
	newURL.Scheme = "http"
	newURL.Host = hostport

	return &newURL
}

// createOxyRedirect creates a redirect with corresponding proxy
// configuration. This will launch a proxy instance.
func createOxyRedirect(l4 *policy.L4Filter, id string, source ProxySource, to uint16) (Redirect, error) {
	for _, ep := range l4.L7RulesPerEp {
		if len(ep.Kafka) > 0 {
			log.Debug("Kafka Parser not supported by Oxy proxy.")
			return nil, fmt.Errorf("unsupported L7 protocol proxy: \"%s\"", l4.L7Parser)
		}
	}

	if l4.L7Parser != policy.ParserTypeHTTP {
		return nil, fmt.Errorf("unknown L7 protocol \"%s\"", l4.L7Parser)
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           ciliumDialerWithContext,
		MaxIdleConns:          2048,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	fwd, err := forward.New(forward.RoundTripper(transport))
	if err != nil {
		return nil, err
	}

	l7rules, err := translateOxyPolicyRules(l4)
	if err != nil {
		return nil, err
	}

	redir := &OxyRedirect{
		id:      id,
		toPort:  to,
		source:  source,
		router:  route.New(),
		ingress: l4.Ingress,
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

		if redir.ingress {
			record.ObservationPoint = accesslog.Ingress
		} else {
			record.ObservationPoint = accesslog.Egress
		}

		srcIdentity, dstIPPort, err := lookupNewDestFromHttp(req, to)
		if err != nil {
			// FIXME: What do we do here long term?
			log.WithError(err).Error("cannot generate redirect destination url")
			http.Error(w, err.Error(), http.StatusBadRequest)
			record.Info = fmt.Sprintf("cannot generate redirect destination url: %s", err)
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
		redir.mutex.Lock()
		if len(redir.rules) > 0 {
			rule, _ := redir.router.Route(req)
			if rule == nil {
				http.Error(w, "Access denied", http.StatusForbidden)
				redir.mutex.Unlock()
				accesslog.Log(record, accesslog.TypeRequest, accesslog.VerdictDenied, http.StatusForbidden)
				return
			}
			ar := rule.(string)
			log.WithField(logfields.Object, logfields.Repr(ar)).Debug("Allowing request based on rule")
			record.Info = fmt.Sprintf("rule: %+v", ar)
		} else {
			log.Debug("Allowing request as there are no rules")
		}
		redir.mutex.Unlock()

		// Reconstruct original URL used for the request
		req.URL = generateURL(req, dstIPPort)

		// log valid request
		accesslog.Log(record, accesslog.TypeRequest, accesslog.VerdictForwarded, http.StatusOK)

		ctx := req.Context()
		if ctx != nil {
			marker := GetMagicMark(redir.ingress) | int(record.SourceEndpoint.Identity)
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

	redir.updateRules(l7rules)

	// The following code up until the go-routine is from manners/server.go:ListenAndServe()
	// It was extracted in order to keep the listening on the TCP socket synchronous so that
	// when policies are regenerated, the port is listening for connections before policy
	// revisions get bumped for an endpoint.
	addr := redir.server.Addr
	if addr == "" {
		addr = ":http"
	}

	marker := GetMagicMark(redir.ingress)

	// As ingress proxy, all replies to incoming requests must have the
	// identity of the endpoint we are proxying for
	if redir.ingress {
		marker |= int(source.GetIdentity())
	}

	// Listen needs to be in the synchronous part of this function to ensure that
	// the proxy port is never refusing connections.
	socket, err := listenSocket(addr, marker)
	if err != nil {
		return nil, err
	}

	go func() {
		err := redir.server.Serve(socket.listener)
		if err != nil {
			log.WithError(err).Error("Unable to listen and serve proxy")
		}
	}()

	return redir, nil
}

// UpdateRules replaces old l7 rules of a redirect with new ones.
func (r *OxyRedirect) UpdateRules(l4 *policy.L4Filter) error {
	l7rules, err := translateOxyPolicyRules(l4)
	if err == nil {
		r.mutex.Lock()
		r.updateRules(l7rules)
		r.mutex.Unlock()
	}
	return err
}

// Close the redirect.
func (r *OxyRedirect) Close() {
	r.server.Close()
}
