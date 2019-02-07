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
	"io/ioutil"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/policy"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/fqdn/matchpattern"
	secIDCache "github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	policyApi "github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/proxy"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/proxy/logger"
	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"

	"github.com/miekg/dns"
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
func (d *Daemon) bootstrapFQDN(restoredEndpoints *endpointRestoreState, preCachePath string) (err error) {
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

	// Controller to cleanup TTL expired entries from the DNS policies.
	dnsGCJobName := "dns-garbage-collector-job"
	controller.NewManager().UpdateController(dnsGCJobName, controller.ControllerParams{
		RunInterval: 1 * time.Minute,
		DoFunc: func() error {

			namesToClean := []string{}
			endpoints := endpointmanager.GetEndpoints()
			for _, ep := range endpoints {
				namesToClean = append(namesToClean, ep.DNSHistory.GC()...)
			}

			namesToClean = fqdn.KeepUniqueNames(namesToClean)
			if len(namesToClean) == 0 {
				return nil
			}

			//Before doing the loop the DNS names to clean will be removed from
			//cfg.Cache, to make sure that data is persistant across cache.
			namesRegex, err := regexp.Compile("^" + strings.Join(namesToClean, ".|") + ".$")
			if err != nil {
				return err
			}
			cfg.Cache.ForceExpire(time.Now(), namesRegex)

			// A second loop is needed to update the global cache from the
			// endpoints cache. Looping this way is generally safe despite not
			// locking; If a new lookup happens during these updates the new
			// DNS data will be reinserted from the endpoint.DNSHistory cache
			// that made the request.
			for _, ep := range endpoints {
				cfg.Cache.UpdateFromCache(ep.DNSHistory, namesToClean)
			}
			log.WithField(logfields.Controller, dnsGCJobName).Infof(
				"FQDN garbage collector work deleted %d name entries", len(namesToClean))
			return d.dnsRuleGen.ForceGenerateDNS(namesToClean)
		},
	})

	// Prefill the cache with the CLI provided pre-cache data. This allows various bridging arrangements during upgrades, or just ensure critical DNS mappings remain.
	if preCachePath != "" {
		log.WithField(logfields.Path, preCachePath).Info("Reading toFQDNs pre-cache data")
		precache, err := readPreCache(preCachePath)
		if err != nil {
			// FIXME: add a link to the "documented format"
			log.WithError(err).WithField(logfields.Path, preCachePath).Error("Cannot parse toFQDNs pre-cache data. Please ensure the file is JSON and follows the documented format")
			// We do not stop the agent here. It is safer to continue with best effort
			// than to enter crash backoffs when this file is broken.
		} else {
			fqdn.DefaultDNSCache.UpdateFromCache(precache, nil)
		}
	}

	// Prefill the cache with DNS lookups from restored endpoints. This is needed
	// to maintain continuity of which IPs are allowed.
	// Note: This is TTL aware, and expired data will not be used (e.g. when
	// restoring after a long delay).
	for _, restoredEP := range restoredEndpoints.restored {
		// Upgrades from old ciliums have this nil
		if restoredEP.DNSHistory != nil {
			fqdn.DefaultDNSCache.UpdateFromCache(restoredEP.DNSHistory, []string{})
		}
	}
	// Once we stop returning errors from StartDNSProxy this should live in
	// StartProxySupport
	proxy.DefaultDNSProxy, err = dnsproxy.StartDNSProxy("", uint16(option.Config.ToFQDNsProxyPort),
		// LookupEPByIP
		func(endpointIP net.IP) (endpointID string, err error) {
			e := endpointmanager.LookupIPv4(endpointIP.String())
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
		// epAddr and serverAddr should match the original request, where epAddr is
		// the source for egress (the only case current).
		func(lookupTime time.Time, epAddr, serverAddr string, msg *dns.Msg, protocol string, allowed bool, stat dnsproxy.ProxyRequestContext) error {
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

			var serverPort int
			serverIP, serverPortStr, err := net.SplitHostPort(serverAddr)
			if err != nil {
				log.WithError(err).Error("cannot extract endpoint IP from DNS request")
			} else {
				if serverPort, err = strconv.Atoi(serverPortStr); err != nil {
					log.WithError(err).WithField(logfields.Port, serverPortStr).Error("cannot parse destination port")
				}
			}

			var ep *endpoint.Endpoint
			epIP, _, err := net.SplitHostPort(epAddr)
			if err != nil {
				log.WithError(err).Error("cannot extract endpoint IP from DNS request")
				// We are always egress
				ep.UpdateProxyStatistics("dns", uint16(serverPort), false, !msg.Response, accesslog.VerdictError)
				endMetric()
				return err
			}
			ep = endpointmanager.LookupIPv4(epIP)
			if ep == nil {
				// This is a hard fail. We cannot proceed because record.Log requires a
				// non-nil ep, and we also don't want to insert this data into the
				// cache if we don't know that an endpoint asked for it (this is
				// asserted via ep != nil here and msg.Response && msg.Rcode ==
				// dns.RcodeSuccess below).
				err := fmt.Errorf("Cannot find matching endpoint for IP %s", epAddr)
				log.WithError(err).Error("cannot find matching endpoint")
				endMetric()
				return err
			}

			qname, responseIPs, TTL, CNAMEs, err := dnsproxy.ExtractMsgDetails(msg)
			if err != nil {
				// This error is ok because all these values are used for reporting, or filling in the cache.
				log.WithError(err).Error("cannot extract DNS message details")
			}

			// We are always egress
			ep.UpdateProxyStatistics("dns", uint16(serverPort), false, !msg.Response, verdict)
			record := logger.NewLogRecord(proxy.DefaultEndpointInfoRegistry, ep, accesslog.TypeRequest, false,
				func(lr *logger.LogRecord) { lr.LogRecord.TransportProtocol = accesslog.TransportProtocol(protoID) },
				logger.LogTags.Verdict(verdict, reason),
				logger.LogTags.Addressing(logger.AddressingInfo{
					SrcIPPort:   epAddr,
					DstIPPort:   serverAddr,
					SrcIdentity: ep.GetIdentity().Uint32(),
				}),
				func(lr *logger.LogRecord) {
					lr.LogRecord.SourceEndpoint = accesslog.EndpointInfo{
						ID:           ep.GetID(),
						IPv4:         ep.GetIPv4Address(),
						IPv6:         ep.GetIPv6Address(),
						Labels:       ep.GetLabels(),
						LabelsSHA256: ep.GetLabelsSHA(),
						Identity:     uint64(ep.GetIdentity()),
					}

					// When the server is an endpoint, get all the data for it.
					// When external, use the ipcache to fill in the SecID
					if serverEP := endpointmanager.LookupIPv4(serverIP); serverEP != nil {
						lr.LogRecord.DestinationEndpoint = accesslog.EndpointInfo{
							ID:           serverEP.GetID(),
							IPv4:         serverEP.GetIPv4Address(),
							IPv6:         serverEP.GetIPv6Address(),
							Labels:       serverEP.GetLabels(),
							LabelsSHA256: serverEP.GetLabelsSHA(),
							Identity:     uint64(serverEP.GetIdentity()),
						}
					} else if serverSecID, exists := ipcache.IPIdentityCache.LookupByIP(serverIP); exists {
						secID := secIDCache.LookupIdentityByID(serverSecID.ID)
						// TODO: handle IPv6
						lr.LogRecord.DestinationEndpoint = accesslog.EndpointInfo{
							IPv4: serverIP,
							// IPv6:         serverEP.GetIPv6Address(),
							Labels:       secID.Labels.GetModel(),
							LabelsSHA256: secID.GetLabelsSHA256(),
							Identity:     uint64(serverSecID.ID.Uint32()),
						}
					}
				},
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

				if ep.DNSHistory.Update(lookupTime, qname, responseIPs, effectiveTTL) {
					ep.SyncEndpointHeaderFile(d)
				}

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
		fqdn.DefaultDNSCache.UpdateFromCache(ep.DNSHistory, nil)
	}

	return namesToRegen, nil
}

// readPreCache returns a fqdn.DNSCache object created from the json data at
// preCachePath
func readPreCache(preCachePath string) (cache *fqdn.DNSCache, err error) {
	data, err := ioutil.ReadFile(preCachePath)
	if err != nil {
		return nil, err
	}

	cache = fqdn.NewDNSCache() // no per-host limit here
	if err = cache.UnmarshalJSON(data); err != nil {
		return nil, err
	}
	return cache, nil
}
