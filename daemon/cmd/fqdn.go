// Copyright 2019-2021 Authors of Cilium
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

package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/policy"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/fqdn/matchpattern"
	"github.com/cilium/cilium/pkg/identity"
	secIDCache "github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
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

	dnsSourceLookup     = "lookup"
	dnsSourceConnection = "connection"
)

func identitiesForFQDNSelectorIPs(selectorsWithIPsToUpdate map[policyApi.FQDNSelector][]net.IP, identityAllocator *secIDCache.CachingIdentityAllocator) (map[policyApi.FQDNSelector][]*identity.Identity, map[string]*identity.Identity, error) {
	var err error

	// Used to track identities which are allocated in calls to
	// AllocateCIDRs. If we for some reason cannot allocate new CIDRs,
	// we have to undo all of our changes and release the identities.
	// This is best effort, as releasing can fail as well.
	usedIdentities := make([]*identity.Identity, 0, len(selectorsWithIPsToUpdate))
	selectorIdentitySliceMapping := make(map[policyApi.FQDNSelector][]*identity.Identity, len(selectorsWithIPsToUpdate))
	newlyAllocatedIdentities := make(map[string]*identity.Identity)

	// Allocate identities for each IPNet and then map to selector
	for selector, selectorIPs := range selectorsWithIPsToUpdate {
		log.WithFields(logrus.Fields{
			"fqdnSelector": selector,
			"ips":          selectorIPs,
		}).Debug("getting identities for IPs associated with FQDNSelector")
		var currentlyAllocatedIdentities []*identity.Identity
		if currentlyAllocatedIdentities, err = ipcache.AllocateCIDRsForIPs(selectorIPs, newlyAllocatedIdentities); err != nil {
			identityAllocator.ReleaseSlice(context.TODO(), nil, usedIdentities)
			log.WithError(err).WithField("prefixes", selectorIPs).Warn(
				"failed to allocate identities for IPs")
			return nil, nil, err
		}
		usedIdentities = append(usedIdentities, currentlyAllocatedIdentities...)
		selectorIdentitySliceMapping[selector] = currentlyAllocatedIdentities
	}

	return selectorIdentitySliceMapping, newlyAllocatedIdentities, nil
}

func (d *Daemon) updateSelectorCacheFQDNs(ctx context.Context, selectors map[policyApi.FQDNSelector][]*identity.Identity, selectorsWithoutIPs []policyApi.FQDNSelector) *sync.WaitGroup {
	// There may be nothing to update - in this case, we exit and do not need
	// to trigger policy updates for all endpoints.
	if len(selectors) == 0 && len(selectorsWithoutIPs) == 0 {
		return &sync.WaitGroup{}
	}

	notifyWg := &sync.WaitGroup{}
	// Update mapping of selector to set of IPs in selector cache.
	for selector, identitySlice := range selectors {
		log.WithFields(logrus.Fields{
			"fqdnSelectorString": selector,
			"identitySlice":      identitySlice}).Debug("updating FQDN selector")
		numIds := make([]identity.NumericIdentity, 0, len(identitySlice))
		for _, numId := range identitySlice {
			// Nil check here? Hopefully not necessary...
			numIds = append(numIds, numId.ID)
		}
		d.policy.GetSelectorCache().UpdateFQDNSelector(selector, numIds, notifyWg)
	}

	if len(selectorsWithoutIPs) > 0 {
		// Selectors which no longer map to IPs (due to TTL expiry, cache being
		// cleared forcibly via CLI, etc.) still exist in the selector cache
		// since policy is imported which allows it, but the selector does
		// not map to any IPs anymore.
		log.WithFields(logrus.Fields{
			"fqdnSelectors": selectorsWithoutIPs,
		}).Debug("removing all identities from FQDN selectors")
		d.policy.GetSelectorCache().RemoveIdentitiesFQDNSelectors(selectorsWithoutIPs, notifyWg)
	}

	return d.endpointManager.UpdatePolicyMaps(ctx, notifyWg)
}

// bootstrapFQDN initializes the toFQDNs related subsystems: dnsNameManager and the DNS proxy.
// dnsNameManager will use the default resolver and, implicitly, the
// default DNS cache. The proxy binds to all interfaces, and uses the
// configured DNS proxy port (this may be 0 and so OS-assigned).
func (d *Daemon) bootstrapFQDN(possibleEndpoints map[uint16]*endpoint.Endpoint, preCachePath string) (err error) {
	cfg := fqdn.Config{
		MinTTL:          option.Config.ToFQDNsMinTTL,
		Cache:           fqdn.NewDNSCache(option.Config.ToFQDNsMinTTL),
		UpdateSelectors: d.updateSelectors,
	}

	rg := fqdn.NewNameManager(cfg)
	d.policy.GetSelectorCache().SetLocalIdentityNotifier(rg)
	d.dnsNameManager = rg

	// Controller to cleanup TTL expired entries from the DNS policies.
	// dns-garbage-collector-job runs the logic to remove stale or undesired
	// entries from the DNS caches. This is done for all per-EP DNSCache
	// instances (ep.DNSHistory) with evictions (whether due to TTL expiry or
	// overlimit eviction) cascaded into ep.DNSZombies. Data in DNSHistory and
	// DNSZombies is further collected into the global DNSCache instance. The
	// data there drives toFQDNs policy via NameManager and ToFQDNs selectors.
	// DNSCache entries expire data when the TTL elapses and when the entries for
	// a DNS name are above a limit. The data is then placed into
	// DNSZombieMappings instances. These rely on the CT GC loop to update
	// liveness for each to-delete IP. When an IP is not in-use it is finally
	// deleted from the global DNSCache. Until then, each of these IPs is
	// inserted into the global cache as a synthetic DNS lookup.
	dnsGCJobName := "dns-garbage-collector-job"
	dnsGCJobInterval := 1 * time.Minute
	controller.NewManager().UpdateController(dnsGCJobName, controller.ControllerParams{
		RunInterval: dnsGCJobInterval,
		DoFunc: func(ctx context.Context) error {
			var (
				GCStart      = time.Now()
				namesToClean []string

				// activeConnections holds DNSName -> single IP entries that have been
				// marked active by the CT GC. Since we expire in this controller, we
				// give these entries 2 cycles of TTL to allow for timing mismatches
				// with the CT GC.
				activeConnectionsTTL = int(2 * dnsGCJobInterval.Seconds())
				activeConnections    = fqdn.NewDNSCache(activeConnectionsTTL)
			)

			// Cleanup each endpoint cache, deferring deletions via DNSZombies.
			endpoints := d.endpointManager.GetEndpoints()
			for _, ep := range endpoints {
				namesToClean = append(namesToClean, ep.DNSHistory.GC(GCStart, ep.DNSZombies)...)
				alive, dead := ep.DNSZombies.GC()

				// Alive zombie need to be added to the global cache as name->IP
				// entries.
				//
				// NB: The following  comment is _no longer true_ (see
				// DNSZombies.GC()).  We keep it to maintain the original intention
				// of the code for future reference:
				//    We accumulate the names into namesToClean to ensure that the
				//    original full DNS lookup (name -> many IPs) is expired and
				//    only the active connections (name->single IP) are re-added.
				//    Note: Other DNS lookups may also use an active IP. This is
				//    fine.
				//
				lookupTime := time.Now()
				for _, zombie := range alive {
					namesToClean = fqdn.KeepUniqueNames(append(namesToClean, zombie.Names...))
					for _, name := range zombie.Names {
						activeConnections.Update(lookupTime, name, []net.IP{zombie.IP}, activeConnectionsTTL)
					}
				}

				// Dead entries can be deleted outright, without any replacement.
				// Entries here have been evicted from the DNS cache (via .GC due to
				// TTL expiration or overlimit) and are no longer active connections.
				for _, zombie := range dead {
					namesToClean = fqdn.KeepUniqueNames(append(namesToClean, zombie.Names...))
				}
			}

			namesToClean = fqdn.KeepUniqueNames(namesToClean)
			if len(namesToClean) == 0 {
				return nil
			}

			// Collect DNS data into the global cache. This aggregates all endpoint
			// and existing connection data into one place for use elsewhere.
			// In the case where a lookup occurs in a race with .ReplaceFromCache the
			// result is consistent:
			// - If before, the ReplaceFromCache will use the new data when pulling
			// in from each EP cache.
			// - If after, the normal update process occurs after .ReplaceFromCache
			// releases its locks.
			caches := []*fqdn.DNSCache{activeConnections}
			for _, ep := range endpoints {
				caches = append(caches, ep.DNSHistory)
			}
			cfg.Cache.ReplaceFromCacheByNames(namesToClean, caches...)

			metrics.FQDNGarbageCollectorCleanedTotal.Add(float64(len(namesToClean)))
			_, err := d.dnsNameManager.ForceGenerateDNS(context.TODO(), namesToClean)
			namesCount := len(namesToClean)
			// Limit the amount of info level logging to some sane amount
			if namesCount > 20 {
				// namedsToClean is only used for logging after this so we can reslice it in place
				namesToClean = namesToClean[:20]
			}
			log.WithField(logfields.Controller, dnsGCJobName).Infof(
				"FQDN garbage collector work deleted %d name entries: %s", namesCount, strings.Join(namesToClean, ","))
			return err
		},
		Context: d.ctx,
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
			d.dnsNameManager.GetDNSCache().UpdateFromCache(precache, nil)
		}
	}

	// Prefill the cache with DNS lookups from restored endpoints. This is needed
	// to maintain continuity of which IPs are allowed. The GC cascade logic
	// below mimics the logic found in the dns-garbage-collector controller.
	// Note: This is TTL aware, and expired data will not be used (e.g. when
	// restoring after a long delay).
	globalCache := d.dnsNameManager.GetDNSCache()
	now := time.Now()
	for _, possibleEP := range possibleEndpoints {
		// Upgrades from old ciliums have this nil
		if possibleEP.DNSHistory != nil {
			globalCache.UpdateFromCache(possibleEP.DNSHistory, []string{})

			// GC any connections that have expired, but propagate it to the zombies
			// list. DNSCache.GC can handle a nil DNSZombies parameter. We use the
			// actual now time because we are checkpointing at restore time.
			possibleEP.DNSHistory.GC(now, possibleEP.DNSZombies)
		}

		if possibleEP.DNSZombies != nil {
			lookupTime := time.Now()
			alive, _ := possibleEP.DNSZombies.GC()
			for _, zombie := range alive {
				for _, name := range zombie.Names {
					globalCache.Update(lookupTime, name, []net.IP{zombie.IP}, int(2*dnsGCJobInterval.Seconds()))
				}
			}
		}
	}

	// Do not start the proxy in dry mode or if L7 proxy is disabled.
	// The proxy would not get any traffic in the dry mode anyway, and some of the socket
	// operations require privileges not available in all unit tests.
	if option.Config.DryMode || !option.Config.EnableL7Proxy {
		return nil
	}

	// Once we stop returning errors from StartDNSProxy this should live in
	// StartProxySupport
	port, listenerName, err := proxy.GetProxyPort(policy.ParserTypeDNS, false)
	if option.Config.ToFQDNsProxyPort != 0 {
		port = uint16(option.Config.ToFQDNsProxyPort)
	} else if port == 0 {
		// Try locate old DNS proxy port number from the datapath
		port = d.datapath.GetProxyPort(listenerName)
	}
	if err != nil {
		return err
	}
	proxy.DefaultDNSProxy, err = dnsproxy.StartDNSProxy("", port, option.Config.ToFQDNsEnableDNSCompression,
		option.Config.DNSMaxIPsPerRestoredRule, d.lookupEPByIP, d.LookupSecIDByIP, d.lookupIPsBySecID,
		d.notifyOnDNSMsg)
	if err == nil {
		// Increase the ProxyPort reference count so that it will never get released.
		err = d.l7Proxy.SetProxyPort(listenerName, proxy.DefaultDNSProxy.BindPort)
		if err == nil && port == proxy.DefaultDNSProxy.BindPort {
			log.Infof("Reusing previous DNS proxy port: %d", port)
		}
		proxy.DefaultDNSProxy.SetRejectReply(option.Config.FQDNRejectResponse)
		// Restore old rules
		for _, possibleEP := range possibleEndpoints {
			// Upgrades from old ciliums have this nil
			if possibleEP.DNSRules != nil {
				proxy.DefaultDNSProxy.RestoreRules(possibleEP)
			}
		}
	}
	return err // filled by StartDNSProxy
}

// updateDNSDatapathRules updates the DNS proxy iptables rules. Must be
// called after iptables has been initailized, and only after
// successful bootstrapFQDN().
func (d *Daemon) updateDNSDatapathRules() error {
	return d.l7Proxy.AckProxyPort(policy.ParserTypeDNS, false)
}

// updateSelectors propagates the mapping of FQDNSelector to identity, as well
// as the set of FQDNSelectors which have no IPs which correspond to them
// (usually due to TTL expiry), down to policy layer managed by this daemon.
func (d *Daemon) updateSelectors(ctx context.Context, selectorWithIPsToUpdate map[policyApi.FQDNSelector][]net.IP, selectorsWithoutIPs []policyApi.FQDNSelector) (wg *sync.WaitGroup, newlyAllocatedIdentities map[string]*identity.Identity, err error) {
	// Convert set of selectors with IPs to update to set of selectors
	// with identities corresponding to said IPs.
	selectorsIdentities, newlyAllocatedIdentities, err := identitiesForFQDNSelectorIPs(selectorWithIPsToUpdate, d.identityAllocator)
	if err != nil {
		return &sync.WaitGroup{}, nil, err
	}

	// Update mapping in selector cache with new identities.
	return d.updateSelectorCacheFQDNs(ctx, selectorsIdentities, selectorsWithoutIPs), newlyAllocatedIdentities, nil
}

// lookupEPByIP returns the endpoint that this IP belongs to
func (d *Daemon) lookupEPByIP(endpointIP net.IP) (endpoint *endpoint.Endpoint, err error) {
	e := d.endpointManager.LookupIP(endpointIP)
	if e == nil {
		return nil, fmt.Errorf("Cannot find endpoint with IP %s", endpointIP.String())
	}

	return e, nil
}

func (d *Daemon) lookupIPsBySecID(nid identity.NumericIdentity) []string {
	return ipcache.IPIdentityCache.LookupByIdentity(nid)
}

// NotifyOnDNSMsg handles DNS data in the daemon by emitting monitor
// events, proxy metrics and storing DNS data in the DNS cache. This may
// result in rule generation.
// It will:
// - Report a monitor error event and proxy metrics when the proxy sees an
//   error, and when it can't process something in this function
// - Report the verdict in a monitor event and emit proxy metrics
// - Insert the DNS data into the cache when msg is a DNS response and we
//   can lookup the endpoint related to it
// epIPPort and serverAddr should match the original request, where epAddr is
// the source for egress (the only case current).
func (d *Daemon) notifyOnDNSMsg(lookupTime time.Time, ep *endpoint.Endpoint, epIPPort string, serverAddr string, msg *dns.Msg, protocol string, allowed bool, stat *dnsproxy.ProxyRequestContext) error {
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

	var epPort, serverPort uint16
	_, epPortStr, err := net.SplitHostPort(epIPPort)
	if err != nil {
		log.WithError(err).Error("cannot extract source IP from DNS request")
	} else {
		if epPortUint64, err := strconv.ParseUint(epPortStr, 10, 16); err != nil {
			log.WithError(err).WithField(logfields.Port, epPortStr).Error("cannot parse source port")
		} else {
			epPort = uint16(epPortUint64)
		}
	}

	serverIP, serverPortStr, err := net.SplitHostPort(serverAddr)
	if err != nil {
		log.WithError(err).Error("cannot extract destination IP from DNS request")
	} else {
		if serverPortUint64, err := strconv.ParseUint(serverPortStr, 10, 16); err != nil {
			log.WithError(err).WithField(logfields.Port, serverPortStr).Error("cannot parse destination port")
		} else {
			serverPort = uint16(serverPortUint64)
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

	ep.UpdateProxyStatistics(strings.ToUpper(protocol), serverPort, false, !msg.Response, verdict)
	record := logger.NewLogRecord(proxy.DefaultEndpointInfoRegistry, ep, flowType, false,
		func(lr *logger.LogRecord) { lr.LogRecord.TransportProtocol = accesslog.TransportProtocol(protoID) },
		logger.LogTags.Verdict(verdict, reason),
		logger.LogTags.Addressing(logger.AddressingInfo{
			SrcIPPort:   epIPPort,
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
				Port:         epPort,
			}

			// When the server is an endpoint, get all the data for it.
			// When external, use the ipcache to fill in the SecID
			if serverEP := d.endpointManager.LookupIPv4(serverIP); serverEP != nil {
				lr.LogRecord.DestinationEndpoint = accesslog.EndpointInfo{
					ID:           serverEP.GetID(),
					IPv4:         serverEP.GetIPv4Address(),
					IPv6:         serverEP.GetIPv6Address(),
					Labels:       serverEP.GetLabels(),
					LabelsSHA256: serverEP.GetLabelsSHA(),
					Identity:     uint64(serverEP.GetIdentity()),
					Port:         serverPort,
				}
			} else if serverSecID, exists := ipcache.IPIdentityCache.LookupByIP(serverIP); exists {
				// TODO: handle IPv6
				lr.LogRecord.DestinationEndpoint = accesslog.EndpointInfo{
					IPv4: serverIP,
					// IPv6:         serverEP.GetIPv6Address(),
					Identity: uint64(serverSecID.ID.Uint32()),
					Port:     serverPort,
				}
				if secID := d.identityAllocator.LookupIdentityByID(d.ctx, serverSecID.ID); secID != nil {
					lr.LogRecord.DestinationEndpoint.Labels = secID.Labels.GetModel()
					lr.LogRecord.DestinationEndpoint.LabelsSHA256 = secID.GetLabelsSHA256()
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
		// This must happen before the NameManager update below, to ensure that
		// this data is included in the serialized Endpoint object.
		// We also need to add to the cache before we purge any matching zombies
		// because they are locked separately and we want to keep the allowed IPs
		// consistent if a regeneration happens between the two steps. If an update
		// doesn't happen in the case, we play it safe and don't purge the zombie
		// in case of races.
		log.WithField(logfields.EndpointID, ep.ID).Debug("Recording DNS lookup in endpoint specific cache")
		if updated := ep.DNSHistory.Update(lookupTime, qname, responseIPs, int(TTL)); updated {
			ep.DNSZombies.ForceExpireByNameIP(lookupTime, qname, responseIPs...)
			ep.SyncEndpointHeaderFile()
		}

		log.WithFields(logrus.Fields{
			"qname": qname,
			"ips":   responseIPs,
		}).Debug("Updating DNS name in cache from response to to query")

		updateCtx, updateCancel := context.WithTimeout(context.TODO(), option.Config.FQDNProxyResponseMaxDelay)
		defer updateCancel()
		updateStart := time.Now()

		wg, newlyAllocatedIdentities, err := d.dnsNameManager.UpdateGenerateDNS(updateCtx, lookupTime, map[string]*fqdn.DNSIPRecords{
			qname: {
				IPs: responseIPs,
				TTL: int(TTL),
			}})
		if err != nil {
			log.WithError(err).Error("error updating internal DNS cache for rule generation")
		}

		updateComplete := make(chan struct{})
		go func(wg *sync.WaitGroup, done chan struct{}) {
			wg.Wait()
			close(updateComplete)
		}(wg, updateComplete)

		select {
		case <-updateCtx.Done():
			log.Error("Timed out waiting for datapath updates of FQDN IP information; returning response")
		case <-updateComplete:
		}

		log.WithFields(logrus.Fields{
			logfields.Duration:   time.Since(updateStart),
			logfields.EndpointID: ep.GetID(),
			"qname":              qname,
		}).Debug("Waited for endpoints to regenerate due to a DNS response")

		// Add new identities to the ipcache after the wait for the policy updates above
		ipcache.UpsertGeneratedIdentities(newlyAllocatedIdentities)

		endMetric()
	}

	stat.ProcessingTime.End(true)
	return nil
}

type getFqdnCache struct {
	daemon *Daemon
}

func NewGetFqdnCacheHandler(d *Daemon) GetFqdnCacheHandler {
	return &getFqdnCache{daemon: d}
}

func (h *getFqdnCache) Handle(params GetFqdnCacheParams) middleware.Responder {
	// endpoints we want data from
	endpoints := h.daemon.endpointManager.GetEndpoints()

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
	endpoints := h.daemon.endpointManager.GetEndpoints()

	matchPatternStr := ""
	if params.Matchpattern != nil {
		matchPatternStr = *params.Matchpattern
	}

	namesToRegen, err := deleteDNSLookups(
		h.daemon.dnsNameManager.GetDNSCache(),
		endpoints,
		time.Now(),
		matchPatternStr)
	if err != nil {
		return api.Error(DeleteFqdnCacheBadRequestCode, err)
	}
	h.daemon.dnsNameManager.ForceGenerateDNS(context.TODO(), namesToRegen)
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
		ep, err := h.daemon.endpointManager.Lookup(params.ID)
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

type getFqdnNamesHandler struct {
	daemon *Daemon
}

func NewGetFqdnNamesHandler(d *Daemon) GetFqdnNamesHandler {
	return &getFqdnNamesHandler{daemon: d}
}

func (h *getFqdnNamesHandler) Handle(params GetFqdnNamesParams) middleware.Responder {
	payload := h.daemon.dnsNameManager.GetModel()
	return NewGetFqdnNamesOK().WithPayload(payload)
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
				Source:         dnsSourceLookup,
			})
		}

		for _, delete := range ep.DNSZombies.DumpAlive(cidrMatcher) {
			for _, name := range delete.Names {
				if !nameMatcher(name) {
					continue
				}

				lookups = append(lookups, &models.DNSLookup{
					Fqdn:           name,
					Ips:            []string{delete.IP.String()},
					LookupTime:     strfmt.DateTime(delete.AliveAt),
					TTL:            0,
					ExpirationTime: strfmt.DateTime(delete.AliveAt),
					EndpointID:     int64(ep.ID),
					Source:         dnsSourceConnection,
				})
			}
		}
	}

	return lookups, nil
}

func deleteDNSLookups(globalCache *fqdn.DNSCache, endpoints []*endpoint.Endpoint, expireLookupsBefore time.Time, matchPatternStr string) (namesToRegen []string, err error) {
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
	namesToRegen = append(namesToRegen, globalCache.ForceExpire(expireLookupsBefore, nameMatcher)...)
	for _, ep := range endpoints {
		namesToRegen = append(namesToRegen, ep.DNSHistory.ForceExpire(expireLookupsBefore, nameMatcher)...)
		globalCache.UpdateFromCache(ep.DNSHistory, nil)

		namesToRegen = append(namesToRegen, ep.DNSZombies.ForceExpire(expireLookupsBefore, nameMatcher, nil)...)
		activeConnections := fqdn.NewDNSCache(0)
		zombies, _ := ep.DNSZombies.GC()
		lookupTime := time.Now()
		for _, zombie := range zombies {
			namesToRegen = append(namesToRegen, zombie.Names...)
			for _, name := range zombie.Names {
				activeConnections.Update(lookupTime, name, []net.IP{zombie.IP}, 0)
			}
		}
		globalCache.UpdateFromCache(activeConnections, nil)
	}

	return namesToRegen, nil
}

// readPreCache returns a fqdn.DNSCache object created from the json data at
// preCachePath
func readPreCache(preCachePath string) (cache *fqdn.DNSCache, err error) {
	data, err := os.ReadFile(preCachePath)
	if err != nil {
		return nil, err
	}

	cache = fqdn.NewDNSCache(0) // no per-host limit here
	if err = cache.UnmarshalJSON(data); err != nil {
		return nil, err
	}
	return cache, nil
}
