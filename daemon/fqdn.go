// Copyright 2019 Authors of Cilium
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
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/policy"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/fqdn/matchpattern"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	policyApi "github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/proxy"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/proxy/logger"
	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"

	"github.com/cilium/dns"
)

const (
	upstream       = "upstreamTime"
	processingTime = "processingTime"

	metricErrorTimeout = "timeout"
	metricErrorProxy   = "proxyErr"
	metricErrorDenied  = "denied"
	metricErrorAllow   = "allow"
)

// bootstrapFQDN initializes the toFQDNs related subsystems: DNSPoller,
// d.dnsRuleGen, and the DNS proxy.
// dnsRuleGen and DNSPoller will use the default resolver and, implicitly, the
// default DNS cache. The proxy binds to all interfaces, and uses the
// configured DNS proxy port (this may be 0 and so OS-assigned).
func (d *Daemon) bootstrapFQDN(restoredEndpoints *endpointRestoreState) (err error) {
	cfg := fqdn.Config{
		MinTTL:         option.Config.ToFQDNsMinTTL,
		Cache:          fqdn.DefaultDNSCache,
		LookupDNSNames: fqdn.DNSLookupDefaultResolver,
		AddGeneratedRules: func(generatedRules []*policyApi.Rule) error {
			// Insert the new rules into the policy repository. We need them to
			// replace the previous set. This requires the labels to match (including
			// the ToFQDN-UUID one).
			_, err := d.PolicyAdd(generatedRules, &AddOptions{Replace: true, Generated: true})
			return err
		},
		PollerResponseNotify: func(lookupTime time.Time, qname string, response *fqdn.DNSIPRecords) {
			// Do nothing if this option is off
			if !option.Config.ToFQDNsEnablePollerEvents {
				return
			}

			// FIXME: Not always true but we don't have the protocol information here
			protocol := accesslog.TransportProtocol(u8proto.ProtoIDs["udp"])

			record := logger.LogRecord{
				LogRecord: accesslog.LogRecord{
					Type:              accesslog.TypeResponse,
					ObservationPoint:  accesslog.Ingress,
					IPVersion:         accesslog.VersionIPv4,
					TransportProtocol: protocol,
					Timestamp:         time.Now().UTC().Format(time.RFC3339Nano),
					NodeAddressInfo:   accesslog.NodeAddressInfo{},
				},
			}

			if ip := node.GetExternalIPv4(); ip != nil {
				record.LogRecord.NodeAddressInfo.IPv4 = ip.String()
			}

			if ip := node.GetIPv6(); ip != nil {
				record.LogRecord.NodeAddressInfo.IPv6 = ip.String()
			}

			logger.LogTags.Verdict(accesslog.VerdictForwarded, "DNSPoller")(&record)
			logger.LogTags.DNS(&accesslog.LogRecordDNS{
				Query:             qname,
				IPs:               response.IPs,
				TTL:               uint32(response.TTL),
				CNAMEs:            nil,
				ObservationSource: accesslog.DNSSourceAgentPoller,
			})(&record)
			record.Log()
		}}

	d.dnsRuleGen = fqdn.NewRuleGen(cfg)
	d.dnsPoller = fqdn.NewDNSPoller(cfg, d.dnsRuleGen)
	if option.Config.ToFQDNsEnablePoller {
		fqdn.StartDNSPoller(d.dnsPoller)
	}

	// Prefill the cache with DNS lookups from restored endpoints. This is needed
	// to maintain continuity of which IPs are allowed.
	// Note: This is TTL aware, and expired data will not be used (e.g. when
	// restoring after a long delay).
	for _, restoredEP := range restoredEndpoints.restored {
		// Upgrades from old ciliums have this nil
		if restoredEP.DNSHistory != nil {
			fqdn.DefaultDNSCache.UpdateFromCache(restoredEP.DNSHistory)
		}
	}

	// Once we stop returning errors from StartDNSProxy this should live in
	// StartProxySupport
	port, _, err := proxy.FindProxyPort(policy.ParserTypeDNS, false)
	if err != nil {
		return err
	}
	proxy.DefaultDNSProxy, err = dnsproxy.StartDNSProxy("", port,
		// LookupEPByIP
		func(endpointIP net.IP) (endpointID string, err error) {
			e := endpointmanager.LookupIP(endpointIP)
			if e == nil {
				return "", fmt.Errorf("Cannot find endpoint with IP %s", endpointIP.String())
			}

			return e.StringID(), nil
		},
		// NotifyOnDNSMsg handles DNS data in the daemon by emitting monitor
		// events, proxy metrics and storing DNS data in the DNS cache. This may
		// result in rule generation.
		// It will:
		// - Report a monitor error event and proxy metrics when the proxy sees an
		//   error, and when it can't process something in this function
		// - Report the verdict in a monitor event and emit proxy metrics
		// - Insert the DNS data into the cache when msg is a DNS response and we
		//   can lookup the endpoint related to it
		// srcAddr and dstAddr should match the packet reported on (i.e. the
		// endpoint is srcAddr for requests, and dstAddr for responses).
		func(lookupTime time.Time, srcAddr, dstAddr string, msg *dns.Msg, protocol string, allowed bool, stat dnsproxy.ProxyRequestContext) error {
			var protoID = u8proto.ProtoIDs[strings.ToLower(protocol)]

			var verdict accesslog.FlowVerdict
			var reason string
			metricError := metricErrorAllow
			stat.ProcessingTime.Start()

			endMetric := func() {
				stat.ProcessingTime.End(true)
				metrics.ProxyUpstreamTime.WithLabelValues(metrics.ErrorTimeout, metrics.L7DNS, upstream).Observe(
					stat.UpstreamTime.Total().Seconds())
				metrics.ProxyUpstreamTime.WithLabelValues(metricError, metrics.L7DNS, processingTime).Observe(
					stat.ProcessingTime.Total().Seconds())
			}

			switch {
			case stat.IsTimeout():
				metricError = metricErrorTimeout
				endMetric()
				return nil
			case stat.Err != nil:
				metricError = metricErrorProxy
				verdict = accesslog.VerdictError
				reason = "Error: " + stat.Err.Error()
			case allowed:
				verdict = accesslog.VerdictForwarded
				reason = "Allowed by policy"
			case !allowed:
				metricError = metricErrorDenied
				verdict = accesslog.VerdictDenied
				reason = "Denied by policy"
			}

			var epAddr string     // the address of the endpoint that originated the request
			var serverAddr string // the address of the DNS target
			var ingress = msg.Response
			var flowType accesslog.FlowType
			if ingress {
				flowType = accesslog.TypeResponse
				epAddr = dstAddr
				serverAddr = srcAddr
			} else {
				flowType = accesslog.TypeRequest
				epAddr = srcAddr
				serverAddr = dstAddr
			}

			var serverPort int
			_, serverPortStr, err := net.SplitHostPort(serverAddr)
			if err != nil {
				log.WithError(err).Error("cannot extract endpoint IP from DNS request")
			} else {
				if serverPort, err = strconv.Atoi(serverPortStr); err != nil {
					log.WithError(err).WithField(logfields.Port, serverPortStr).Error("cannot parse destination port")
				}
			}

			var ep *endpoint.Endpoint
			epIPStr, _, err := net.SplitHostPort(epAddr)
			if err != nil {
				log.WithError(err).Error("cannot extract endpoint IP from DNS request")
				ep.UpdateProxyStatistics("dns", uint16(serverPort), ingress, !ingress, accesslog.VerdictError)
				endMetric()
				return err
			}
			epIP := net.ParseIP(epIPStr)
			if epIP == nil {
				log.WithError(err).Error("cannot parse endpoint IP from DNS request")
				ep.UpdateProxyStatistics("dns", uint16(serverPort), ingress, !ingress, accesslog.VerdictError)
				endMetric()
				return err
			}
			ep = endpointmanager.LookupIP(epIP)
			if ep == nil {
				// This is a hard fail. We cannot proceed because record.Log requires a
				// non-nil ep, and we also don't want to insert this data into the
				// cache if we don't know that an endpoint asked for it (this is
				// asserted via ep != nil here and msg.Response && msg.Rcode ==
				// dns.RcodeSuccess below).
				err := fmt.Errorf("Cannot find matching endpoint for IPs %s or %s", srcAddr, dstAddr)
				log.WithError(err).Error("cannot find matching endpoint")
				endMetric()
				return err
			}

			qname, responseIPs, TTL, CNAMEs, err := dnsproxy.ExtractMsgDetails(msg)
			if err != nil {
				// This error is ok because all these values are used for reporting, or filling in the cache.
				log.WithError(err).Error("cannot extract DNS message details")
			}

			ep.UpdateProxyStatistics("dns", uint16(serverPort), ingress, !ingress, verdict)
			record := logger.NewLogRecord(proxy.DefaultEndpointInfoRegistry, ep, flowType, ingress,
				func(lr *logger.LogRecord) { lr.LogRecord.TransportProtocol = accesslog.TransportProtocol(protoID) },
				logger.LogTags.Verdict(verdict, reason),
				logger.LogTags.Addressing(logger.AddressingInfo{
					SrcIPPort:   srcAddr,
					DstIPPort:   dstAddr,
					SrcIdentity: 0, // 0 more correctly finds src and dst EP data
				}),
				logger.LogTags.DNS(&accesslog.LogRecordDNS{
					Query:             qname,
					IPs:               responseIPs,
					TTL:               TTL,
					CNAMEs:            CNAMEs,
					ObservationSource: accesslog.DNSSourceProxy,
				}),
			)
			record.Log()

			if msg.Response && msg.Rcode == dns.RcodeSuccess {
				// This must happen before the ruleGen update below, to ensure that
				// this data is included in the serialized Endpoint object.
				// Note: We need to fixup minTTL to be consistent with how we insert it
				// elsewhere i.e. we don't want to lose the lower bound for DNS data
				// TTL if we reboot twice.
				log.WithField(logfields.EndpointID, ep.ID).Debug("Recording DNS lookup in endpoint specific cache")
				effectiveTTL := int(TTL)
				if effectiveTTL < option.Config.ToFQDNsMinTTL {
					effectiveTTL = option.Config.ToFQDNsMinTTL
				}
				ep.DNSHistory.Update(lookupTime, qname, responseIPs, effectiveTTL)
				log.Debug("Updating DNS name in cache from response to to query")
				err = d.dnsRuleGen.UpdateGenerateDNS(lookupTime, map[string]*fqdn.DNSIPRecords{
					qname: {
						IPs: responseIPs,
						TTL: int(effectiveTTL),
					}})
				if err != nil {
					log.WithError(err).Error("error updating internal DNS cache for rule generation")
				}
				endMetric()
			}

			stat.ProcessingTime.End(true)
			return nil
		})
	proxy.DefaultDNSProxy.SetRejectReply(option.Config.FQDNRejectResponse)
	return err // filled by StartDNSProxy
}

type getFqdnCache struct {
	daemon *Daemon
}

func NewGetFqdnCacheHandler(d *Daemon) GetFqdnCacheHandler {
	return &getFqdnCache{daemon: d}
}

func (h *getFqdnCache) Handle(params GetFqdnCacheParams) middleware.Responder {
	// endpoints we want data from
	endpoints := endpointmanager.GetEndpoints()

	CIDRStr := ""
	if params.Cidr != nil {
		CIDRStr = *params.Cidr
	}

	matchPatternStr := ""
	if params.Matchpattern != nil {
		matchPatternStr = *params.Matchpattern
	}

	lookups, err := extractDNSLookups(endpoints, CIDRStr, matchPatternStr)
	switch {
	case err != nil:
		return api.Error(GetFqdnCacheBadRequestCode, err)
	case len(lookups) == 0:
		return NewGetFqdnCacheIDNotFound()
	}

	return NewGetFqdnCacheIDOK().WithPayload(lookups)
}

type deleteFqdnCache struct {
	daemon *Daemon
}

func NewDeleteFqdnCacheHandler(d *Daemon) DeleteFqdnCacheHandler {
	return &deleteFqdnCache{daemon: d}
}

func (h *deleteFqdnCache) Handle(params DeleteFqdnCacheParams) middleware.Responder {
	// endpoints we want to modify
	endpoints := endpointmanager.GetEndpoints()

	matchPatternStr := ""
	if params.Matchpattern != nil {
		matchPatternStr = *params.Matchpattern
	}

	namesToRegen, err := deleteDNSLookups(endpoints, time.Now(), matchPatternStr)
	if err != nil {
		return api.Error(DeleteFqdnCacheBadRequestCode, err)
	}
	h.daemon.dnsRuleGen.ForceGenerateDNS(namesToRegen)
	return NewDeleteFqdnCacheOK()
}

type getFqdnCacheID struct {
	daemon *Daemon
}

func NewGetFqdnCacheIDHandler(d *Daemon) GetFqdnCacheIDHandler {
	return &getFqdnCacheID{daemon: d}
}

func (h *getFqdnCacheID) Handle(params GetFqdnCacheIDParams) middleware.Responder {
	var endpoints []*endpoint.Endpoint
	if params.ID != "" {
		ep, err := endpointmanager.Lookup(params.ID)
		switch {
		case err != nil:
			return api.Error(GetFqdnCacheIDBadRequestCode, err)
		case ep == nil:
			return api.Error(GetFqdnCacheIDNotFoundCode, fmt.Errorf("Cannot find endpoint %s", params.ID))
		default:
			endpoints = []*endpoint.Endpoint{ep}
		}
	}

	CIDRStr := ""
	if params.Cidr != nil {
		CIDRStr = *params.Cidr
	}

	matchPatternStr := ""
	if params.Matchpattern != nil {
		matchPatternStr = *params.Matchpattern
	}

	lookups, err := extractDNSLookups(endpoints, CIDRStr, matchPatternStr)
	switch {
	case err != nil:
		return api.Error(GetFqdnCacheBadRequestCode, err)
	case len(lookups) == 0:
		return NewGetFqdnCacheIDNotFound()
	}

	return NewGetFqdnCacheIDOK().WithPayload(lookups)
}

// extractDNSLookups returns API models.DNSLookup copies of DNS data in each
// endpoint's DNSHistory. These are filtered by CIDRStr and matchPatternStr if
// they are non-empty.
func extractDNSLookups(endpoints []*endpoint.Endpoint, CIDRStr, matchPatternStr string) (lookups []*models.DNSLookup, err error) {
	cidrMatcher := func(ip net.IP) bool { return true }
	if CIDRStr != "" {
		_, cidr, err := net.ParseCIDR(CIDRStr)
		if err != nil {
			return nil, err
		}
		cidrMatcher = func(ip net.IP) bool { return cidr.Contains(ip) }
	}

	nameMatcher := func(name string) bool { return true }
	if matchPatternStr != "" {
		matcher, err := matchpattern.Validate(matchpattern.Sanitize(matchPatternStr))
		if err != nil {
			return nil, err
		}
		nameMatcher = func(name string) bool { return matcher.MatchString(name) }
	}

	for _, ep := range endpoints {
		for _, lookup := range ep.DNSHistory.Dump() {
			if !nameMatcher(lookup.Name) {
				continue
			}

			// The API model needs strings
			IPStrings := make([]string, 0, len(lookup.IPs))

			// only proceed if any IP matches the cidr selector
			anIPMatches := false
			for _, ip := range lookup.IPs {
				anIPMatches = anIPMatches || cidrMatcher(ip)
				IPStrings = append(IPStrings, ip.String())
			}
			if !anIPMatches {
				continue
			}

			lookups = append(lookups, &models.DNSLookup{
				Fqdn:           lookup.Name,
				Ips:            IPStrings,
				LookupTime:     strfmt.DateTime(lookup.LookupTime),
				TTL:            int64(lookup.TTL),
				ExpirationTime: strfmt.DateTime(lookup.ExpirationTime),
				EndpointID:     int64(ep.ID),
			})
		}
	}

	return lookups, nil
}

func deleteDNSLookups(endpoints []*endpoint.Endpoint, expireLookupsBefore time.Time, matchPatternStr string) (namesToRegen []string, err error) {
	var nameMatcher *regexp.Regexp // nil matches all in our implementation
	if matchPatternStr != "" {
		nameMatcher, err = matchpattern.Validate(matchPatternStr)
		if err != nil {
			return nil, err
		}
	}

	// Clear any to-delete entries globally
	// Clear any to-delete entries in each endpoint, then update globally to
	// insert any entries that now should be in the global cache (because they
	// provide an IP at the latest expiration time).
	namesToRegen = append(namesToRegen, fqdn.DefaultDNSCache.ForceExpire(expireLookupsBefore, nameMatcher)...)
	for _, ep := range endpoints {
		namesToRegen = append(namesToRegen, ep.DNSHistory.ForceExpire(expireLookupsBefore, nameMatcher)...)
		fqdn.DefaultDNSCache.UpdateFromCache(ep.DNSHistory)
	}

	return namesToRegen, nil
}
