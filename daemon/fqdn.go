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
	"context"
	"errors"
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
	"github.com/cilium/cilium/pkg/identity"
	secIDCache "github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
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
	"github.com/sirupsen/logrus"

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

func identitiesForFQDNSelectorIPs(selectorsWithIPsToUpdate map[policyApi.FQDNSelector][]net.IP) (map[policyApi.FQDNSelector][]*identity.Identity, error) {
	var err error

	// Used to track identities which are allocated in calls to
	// AllocateCIDRs. If we for some reason cannot allocate new CIDRs,
	// we have to undo all of our changes and release the identities.
	// This is best effort, as releasing can fail as well.
	usedIdentities := make([]*identity.Identity, 0)
	selectorIdentitySliceMapping := make(map[policyApi.FQDNSelector][]*identity.Identity)

	// Allocate identities for each IPNet and then map to selector
	for selector, selectorIPs := range selectorsWithIPsToUpdate {
		var currentlyAllocatedIdentities []*identity.Identity
		if currentlyAllocatedIdentities, err = ipcache.AllocateCIDRsForIPs(selectorIPs); err != nil {
			secIDCache.ReleaseSlice(context.TODO(), nil, usedIdentities)
			log.WithError(err).WithField("prefixes", selectorIPs).Warn(
				"failed to allocate identities for IPs")
			return nil, err
		}
		usedIdentities = append(usedIdentities, currentlyAllocatedIdentities...)
		selectorIdentitySliceMapping[selector] = currentlyAllocatedIdentities
	}

	return selectorIdentitySliceMapping, nil
}

func (d *Daemon) updateSelectorCacheFQDNs(selectors map[policyApi.FQDNSelector][]*identity.Identity, selectorsWithoutIPs []policyApi.FQDNSelector) {
	// Update mapping of selector to set of IPs in selector cache.
	for selector, identitySlice := range selectors {
		log.WithFields(logrus.Fields{
			"fqdnSelectorString": selector,
			"identitySlice":      identitySlice}).Debug("updating FQDN selector")
		numIds := make([]identity.NumericIdentity, len(identitySlice))
		for _, numId := range identitySlice {
			// Nil check here? Hopefully not necessary...
			numIds = append(numIds, numId.ID)
		}
		d.policy.GetSelectorCache().UpdateFQDNSelector(selector, numIds)
	}

	// Selectors which no longer map to IPs (due to TTL expiry, cache being
	// cleared forcibly via CLI, etc.) still exist in the selector cache
	// since policy is imported which allows it, but the selector does
	// not map to any IPs anymore.
	log.WithFields(logrus.Fields{
		"fqdnSelectors": selectorsWithoutIPs,
	}).Debug("removing all identities from FQDN selectors")
	d.policy.GetSelectorCache().RemoveIdentitiesFQDNSelectors(selectorsWithoutIPs)
}

// bootstrapFQDN initializes the toFQDNs related subsystems: DNSPoller,
// d.dnsRuleGen, and the DNS proxy.
// dnsRuleGen and DNSPoller will use the default resolver and, implicitly, the
// default DNS cache. The proxy binds to all interfaces, and uses the
// configured DNS proxy port (this may be 0 and so OS-assigned).
func (d *Daemon) bootstrapFQDN(restoredEndpoints *endpointRestoreState, preCachePath string) (err error) {
	cfg := fqdn.Config{
		MinTTL:         option.Config.ToFQDNsMinTTL,
		OverLimit:      option.Config.ToFQDNsMaxIPsPerHost,
		Cache:          fqdn.NewDNSCache(option.Config.ToFQDNsMinTTL),
		LookupDNSNames: fqdn.DNSLookupDefaultResolver,
		AddGeneratedRulesAndUpdateSelectors: func(generatedRules []*policyApi.Rule, selectorWithIPsToUpdate map[policyApi.FQDNSelector][]net.IP, selectorsWithoutIPs []policyApi.FQDNSelector) error {
			// Convert set of selectors with IPs to update to set of selectors
			// with identities corresponding to said IPs.
			selectorsIdentities, err := identitiesForFQDNSelectorIPs(selectorWithIPsToUpdate)
			if err != nil {
				return err
			}

			// Update selector cache for said FQDN selectors.
			d.updateSelectorCacheFQDNs(selectorsIdentities, selectorsWithoutIPs)

			// Insert the new rules into the policy repository. We need them to
			// replace the previous set. This requires the labels to match (including
			// the ToFQDN-UUID one).
			_, err = d.PolicyAdd(generatedRules, &AddOptions{Replace: true, Generated: true, Source: metrics.LabelEventSourceFQDN})
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

			// Construct the list of DNS types for question and answer RRs
			questionTypes := []uint16{dns.TypeA, dns.TypeAAAA}
			answerTypes := []uint16{}
			for _, ip := range response.IPs {
				if ip.To4() == nil {
					answerTypes = append(answerTypes, dns.TypeAAAA)
				} else {
					answerTypes = append(answerTypes, dns.TypeA)
				}
			}

			// Update DNS specific data in the LogRecord
			logger.LogTags.Verdict(accesslog.VerdictForwarded, "DNSPoller")(&record)
			logger.LogTags.DNS(&accesslog.LogRecordDNS{
				Query:             qname,
				IPs:               response.IPs,
				TTL:               uint32(response.TTL),
				CNAMEs:            nil,
				ObservationSource: accesslog.DNSSourceAgentPoller,
				RCode:             dns.RcodeSuccess,
				QTypes:            questionTypes,
				AnswerTypes:       answerTypes,
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
		DoFunc: func(ctx context.Context) error {

			namesToClean := []string{}
			// cleanup poller cache
			namesToClean = append(namesToClean, d.dnsPoller.DNSHistory.GC()...)

			// cleanup caches for all existing endpoints as well.
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
			cfg.Cache.ForceExpireByNames(time.Now(), namesToClean)

			// A second loop is needed to update the global cache from the
			// endpoints cache. Looping this way is generally safe despite not
			// locking; If a new lookup happens during these updates the new
			// DNS data will be reinserted from the endpoint.DNSHistory cache
			// that made the request.
			for _, ep := range endpoints {
				cfg.Cache.UpdateFromCache(ep.DNSHistory, namesToClean)
			}
			// Also update from the poller.
			cfg.Cache.UpdateFromCache(d.dnsPoller.DNSHistory, namesToClean)

			metrics.FQDNGarbageCollectorCleanedTotal.Add(float64(len(namesToClean)))
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
			d.dnsRuleGen.GetDNSCache().UpdateFromCache(precache, nil)
		}
	}

	// Prefill the cache with DNS lookups from restored endpoints. This is needed
	// to maintain continuity of which IPs are allowed.
	// Note: This is TTL aware, and expired data will not be used (e.g. when
	// restoring after a long delay).
	for _, restoredEP := range restoredEndpoints.restored {
		// Upgrades from old ciliums have this nil
		if restoredEP.DNSHistory != nil {
			d.dnsRuleGen.GetDNSCache().UpdateFromCache(restoredEP.DNSHistory, []string{})
		}
	}

	// Do not start the proxy in dry mode. The proxy would not get any traffic in the
	// dry mode anyway, and some of the socket operations require privileges not availabe
	// in all unit tests.
	if option.Config.DryMode {
		return nil
	}

	// Once we stop returning errors from StartDNSProxy this should live in
	// StartProxySupport
	port, listenerName, err := proxy.GetProxyPort(policy.ParserTypeDNS, false)
	if option.Config.ToFQDNsProxyPort != 0 {
		port = uint16(option.Config.ToFQDNsProxyPort)
	}
	if err != nil {
		return err
	}
	proxy.DefaultDNSProxy, err = dnsproxy.StartDNSProxy("", port,
		// LookupEPByIP
		func(endpointIP net.IP) (endpoint *endpoint.Endpoint, err error) {
			e := endpointmanager.LookupIP(endpointIP)
			if e == nil {
				return nil, fmt.Errorf("Cannot find endpoint with IP %s", endpointIP.String())
			}

			return e, nil
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
		func(lookupTime time.Time, ep *endpoint.Endpoint, serverAddr string, msg *dns.Msg, protocol string, allowed bool, stat dnsproxy.ProxyRequestContext) error {
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

			// We determine the direction based on the DNS packet. The observation
			// point is always Egress, however.
			var flowType accesslog.FlowType
			if msg.Response {
				flowType = accesslog.TypeResponse
			} else {
				flowType = accesslog.TypeRequest
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
			if ep == nil {
				// This is a hard fail. We cannot proceed because record.Log requires a
				// non-nil ep, and we also don't want to insert this data into the
				// cache if we don't know that an endpoint asked for it (this is
				// asserted via ep != nil here and msg.Response && msg.Rcode ==
				// dns.RcodeSuccess below).
				err := errors.New("DNS request cannot be associated with an existing endpoint")
				log.WithError(err).Error("cannot find matching endpoint")
				endMetric()
				return err
			}
			qname, responseIPs, TTL, CNAMEs, rcode, recordTypes, qTypes, err := dnsproxy.ExtractMsgDetails(msg)
			if err != nil {
				// This error is ok because all these values are used for reporting, or filling in the cache.
				log.WithError(err).Error("cannot extract DNS message details")
			}

			ep.UpdateProxyStatistics("dns", uint16(serverPort), false, !msg.Response, verdict)
			record := logger.NewLogRecord(proxy.DefaultEndpointInfoRegistry, ep, flowType, false,
				func(lr *logger.LogRecord) { lr.LogRecord.TransportProtocol = accesslog.TransportProtocol(protoID) },
				logger.LogTags.Verdict(verdict, reason),
				logger.LogTags.Addressing(logger.AddressingInfo{
					SrcIPPort:   ep.String(),
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
					RCode:             rcode,
					QTypes:            qTypes,
					AnswerTypes:       recordTypes,
				}),
			)
			record.Log()

			if msg.Response && msg.Rcode == dns.RcodeSuccess && len(responseIPs) > 0 {
				// This must happen before the ruleGen update below, to ensure that
				// this data is included in the serialized Endpoint object.
				log.WithField(logfields.EndpointID, ep.ID).Debug("Recording DNS lookup in endpoint specific cache")
				if ep.DNSHistory.Update(lookupTime, qname, responseIPs, int(TTL)) {
					ep.SyncEndpointHeaderFile(d)
				}

				log.WithFields(logrus.Fields{
					"qname": qname,
					"ips":   responseIPs,
				}).Debug("Updating DNS name in cache from response to to query")
				err = d.dnsRuleGen.UpdateGenerateDNS(lookupTime, map[string]*fqdn.DNSIPRecords{
					qname: {
						IPs: responseIPs,
						TTL: int(TTL),
					}})
				if err != nil {
					log.WithError(err).Error("error updating internal DNS cache for rule generation")
				}
				endMetric()
			}

			stat.ProcessingTime.End(true)
			return nil
		})
	if err == nil {
		// Increase the ProxyPort reference count so that it will never get released.
		err = d.l7Proxy.SetProxyPort(listenerName, proxy.DefaultDNSProxy.BindPort)

		proxy.DefaultDNSProxy.SetRejectReply(option.Config.FQDNRejectResponse)
	}
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

	return NewGetFqdnCacheOK().WithPayload(lookups)
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

	namesToRegen, err := deleteDNSLookups(
		h.daemon.dnsRuleGen.GetDNSCache(),
		h.daemon.dnsPoller.DNSHistory,
		endpoints,
		time.Now(),
		matchPatternStr)
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

func deleteDNSLookups(globalCache *fqdn.DNSCache, pollerCache *fqdn.DNSCache, endpoints []*endpoint.Endpoint, expireLookupsBefore time.Time, matchPatternStr string) (namesToRegen []string, err error) {
	var nameMatcher *regexp.Regexp // nil matches all in our implementation
	if matchPatternStr != "" {
		nameMatcher, err = matchpattern.Validate(matchPatternStr)
		if err != nil {
			return nil, err
		}
	}

	// Clear any to-delete entries globally
	// Clear any to-delete entries from the poller cache.
	// Clear any to-delete entries in each endpoint, then update globally to
	// insert any entries that now should be in the global cache (because they
	// provide an IP at the latest expiration time).
	namesToRegen = append(namesToRegen, globalCache.ForceExpire(expireLookupsBefore, nameMatcher)...)
	namesToRegen = append(namesToRegen, pollerCache.ForceExpire(expireLookupsBefore, nameMatcher)...)
	for _, ep := range endpoints {
		namesToRegen = append(namesToRegen, ep.DNSHistory.ForceExpire(expireLookupsBefore, nameMatcher)...)
		globalCache.UpdateFromCache(ep.DNSHistory, nil)
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

	cache = fqdn.NewDNSCache(0) // no per-host limit here
	if err = cache.UnmarshalJSON(data); err != nil {
		return nil, err
	}
	return cache, nil
}
