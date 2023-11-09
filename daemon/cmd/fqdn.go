// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"github.com/cilium/dns"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/policy"
	"github.com/cilium/cilium/pkg/api"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/fqdn/matchpattern"
	"github.com/cilium/cilium/pkg/fqdn/re"
	"github.com/cilium/cilium/pkg/identity"
	ippkg "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	policyApi "github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/proxy"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
	"github.com/cilium/cilium/pkg/proxy/logger"
	proxytypes "github.com/cilium/cilium/pkg/proxy/types"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/u8proto"
)

const (
	upstreamTime    = "upstreamTime"
	processingTime  = "processingTime"
	semaphoreTime   = "semaphoreTime"
	policyCheckTime = "policyCheckTime"
	policyGenTime   = "policyGenerationTime"
	dataplaneTime   = "dataplaneTime"
	totalTime       = "totalTime"

	metricErrorTimeout = "timeout"
	metricErrorProxy   = "proxyErr"
	metricErrorDenied  = "denied"
	metricErrorAllow   = "allow"

	dnsSourceLookup     = "lookup"
	dnsSourceConnection = "connection"
)

// requestNameKey is used as a key to context.Value(). It is used
// to pass the triggering DNS name for logging purposes.
type requestNameKey struct{}

// updateSelectors propagates the mapping of FQDNSelector to IPs
// to the policy engine.
// First, it updates any selectors in the SelectorCache, then it triggers
// all endpoints to push incremental updates via UpdatePolicyMaps.
//
// returns a WaitGroup that is done when all policymaps have been updated
// and all endpoints referencing the IPs are able to pass traffic.
func (d *Daemon) updateSelectors(ctx context.Context, selectors map[policyApi.FQDNSelector][]netip.Addr, ipcacheRevision uint64) (wg *sync.WaitGroup) {
	// There may be nothing to update - in this case, we exit and do not need
	// to trigger policy updates for all endpoints.
	if len(selectors) == 0 {
		return &sync.WaitGroup{}
	}
	logger := log.WithField("qname", ctx.Value(requestNameKey{}))

	// notifyWg is a waitgroup that is incremented for every "user" of a selector; i.e.
	// every single SelectorPolicy. Once that selector has pushed out incremental changes
	// to every relevant endpoint, the WaitGroup will be done.
	notifyWg := &sync.WaitGroup{}
	updateResult := policy.UpdateResultUnchanged
	// Update mapping of selector to set of IPs in selector cache.
	for selector, ips := range selectors {
		logger.WithFields(logrus.Fields{
			"fqdnSelectorString": selector,
			"ips":                ips}).Debug("updating FQDN selector")
		res := d.policy.GetSelectorCache().UpdateFQDNSelector(selector, ips, notifyWg)
		updateResult |= res
	}

	// UpdatePolicyMaps consumes notifyWG, and returns its own WaitGroup
	// that is Done() when all endpoints have pushed their incremental changes
	// down in to their bpf PolicyMap.
	if updateResult&policy.UpdateResultUpdatePolicyMaps > 0 {
		logger.Debug("FQDN selector update requires UpdatePolicyMaps.")
		wg = d.endpointManager.UpdatePolicyMaps(ctx, notifyWg)
	} else {
		wg = &sync.WaitGroup{}
	}

	// If any of the selectors indicated they're missing identities,
	// we also need to wait for a full ipcache round.
	if updateResult&policy.UpdateResultIdentitiesNeeded > 0 && ipcacheRevision > 0 {
		wg.Add(1)
		go func() {
			logger.Debug("FQDN selector update requires IPCache completion.")
			d.ipcache.WaitForRevision(ipcacheRevision)
			wg.Done()
		}()
	}

	// This releases the nameManager lock; at this point, it is safe for another fqdn update to proceed
	return
}

// bootstrapFQDN initializes the toFQDNs related subsystems: dnsNameManager and the DNS proxy.
// dnsNameManager will use the default resolver and, implicitly, the
// default DNS cache. The proxy binds to all interfaces, and uses the
// configured DNS proxy port (this may be 0 and so OS-assigned).
func (d *Daemon) bootstrapFQDN(possibleEndpoints map[uint16]*endpoint.Endpoint, preCachePath string, ipcache fqdn.IPCache) (err error) {
	cfg := fqdn.Config{
		MinTTL:              option.Config.ToFQDNsMinTTL,
		Cache:               fqdn.NewDNSCache(option.Config.ToFQDNsMinTTL),
		UpdateSelectors:     d.updateSelectors,
		GetEndpointsDNSInfo: d.getEndpointsDNSInfo,
		IPCache:             ipcache,
	}
	// Disable cleanup tracking on the default DNS cache. This cache simply
	// tracks which api.FQDNSelector are present in policy which apply to
	// locally running endpoints.
	cfg.Cache.DisableCleanupTrack()

	rg := fqdn.NewNameManager(cfg)
	d.policy.GetSelectorCache().SetLocalIdentityNotifier(rg)
	d.dnsNameManager = rg

	// Controller to cleanup TTL expired entries from the DNS policies.
	d.dnsNameManager.StartGC(d.ctx)

	// restore the global DNS cache state
	epInfo := make([]fqdn.EndpointDNSInfo, 0, len(possibleEndpoints))
	for _, ep := range possibleEndpoints {
		epInfo = append(epInfo, fqdn.EndpointDNSInfo{
			ID:         ep.StringID(),
			DNSHistory: ep.DNSHistory,
			DNSZombies: ep.DNSZombies,
		})
	}
	d.dnsNameManager.RestoreCache(preCachePath, epInfo)

	// Do not start the proxy in dry mode or if L7 proxy is disabled.
	// The proxy would not get any traffic in the dry mode anyway, and some of the socket
	// operations require privileges not available in all unit tests.
	if option.Config.DryMode || !option.Config.EnableL7Proxy {
		return nil
	}

	// Once we stop returning errors from StartDNSProxy this should live in
	// StartProxySupport
	port, err := d.l7Proxy.GetProxyPort(proxytypes.DNSProxyName)
	if err != nil {
		return err
	}
	if option.Config.ToFQDNsProxyPort != 0 {
		port = uint16(option.Config.ToFQDNsProxyPort)
	} else if port == 0 {
		// Try locate old DNS proxy port number from the datapath, and reuse it if it's not open
		oldPort := d.datapath.GetProxyPort(proxytypes.DNSProxyName)
		openLocalPorts := proxy.OpenLocalPorts()
		if _, alreadyOpen := openLocalPorts[oldPort]; !alreadyOpen {
			port = oldPort
		}
	}
	if err := re.InitRegexCompileLRU(option.Config.FQDNRegexCompileLRUSize); err != nil {
		return fmt.Errorf("could not initialize regex LRU cache: %w", err)
	}
	proxy.DefaultDNSProxy, err = dnsproxy.StartDNSProxy("", port,
		option.Config.EnableIPv4, option.Config.EnableIPv6,
		option.Config.ToFQDNsEnableDNSCompression,
		option.Config.DNSMaxIPsPerRestoredRule, d.lookupEPByIP, d.ipcache.LookupSecIDByIP, d.lookupIPsBySecID,
		d.notifyOnDNSMsg, option.Config.DNSProxyConcurrencyLimit, option.Config.DNSProxyConcurrencyProcessingGracePeriod)
	if err == nil {
		// Increase the ProxyPort reference count so that it will never get released.
		err = d.l7Proxy.SetProxyPort(proxytypes.DNSProxyName, proxytypes.ProxyTypeDNS, proxy.DefaultDNSProxy.GetBindPort(), false)
		if err == nil && port == proxy.DefaultDNSProxy.GetBindPort() {
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

// getEndpointsDNSInfo is used by the NameManager to iterate through endpoints
// without having to have access to the EndpointManager.
func (d *Daemon) getEndpointsDNSInfo() []fqdn.EndpointDNSInfo {
	eps := d.endpointManager.GetEndpoints()
	out := make([]fqdn.EndpointDNSInfo, 0, len(eps))
	for _, ep := range eps {
		out = append(out, fqdn.EndpointDNSInfo{
			ID:         ep.StringID(),
			DNSHistory: ep.DNSHistory,
			DNSZombies: ep.DNSZombies,
		})
	}
	return out
}

// updateDNSDatapathRules updates the DNS proxy iptables rules. Must be
// called after iptables has been initailized, and only after
// successful bootstrapFQDN().
func (d *Daemon) updateDNSDatapathRules(ctx context.Context) error {
	if option.Config.DryMode || !option.Config.EnableL7Proxy {
		return nil
	}

	return d.l7Proxy.AckProxyPort(ctx, proxytypes.DNSProxyName)
}

// lookupEPByIP returns the endpoint that this IP belongs to
func (d *Daemon) lookupEPByIP(endpointAddr netip.Addr) (endpoint *endpoint.Endpoint, err error) {
	e := d.endpointManager.LookupIP(endpointAddr)
	if e == nil {
		return nil, fmt.Errorf("cannot find endpoint with IP %s", endpointAddr)
	}

	return e, nil
}

func (d *Daemon) lookupIPsBySecID(nid identity.NumericIdentity) []string {
	return d.ipcache.LookupByIdentity(nid)
}

// notifyOnDNSMsg handles DNS data in the daemon by emitting monitor
// events, proxy metrics and storing DNS data in the DNS cache. This may
// result in rule generation.
// It will:
//   - Report a monitor error event and proxy metrics when the proxy sees an
//     error, and when it can't process something in this function
//   - Report the verdict in a monitor event and emit proxy metrics
//   - Insert the DNS data into the cache when msg is a DNS response, and we
//     can lookup the endpoint related to it.
//
// It may return dnsproxy.ErrDNSRequestNoEndpoint{} error if the endpoint is nil.
// Note that the caller should log beforehand the contextualized error.

// epIPPort and serverAddr should match the original request, where epAddr is
// the source for egress (the only case current).
// serverID is the destination server security identity at the time of the DNS event.
func (d *Daemon) notifyOnDNSMsg(lookupTime time.Time, ep *endpoint.Endpoint, epIPPort string, serverID identity.NumericIdentity, serverAddr string, msg *dns.Msg, protocol string, allowed bool, stat *dnsproxy.ProxyRequestContext) error {
	var protoID = u8proto.ProtoIDs[strings.ToLower(protocol)]
	var verdict accesslog.FlowVerdict
	var reason string
	metricError := metricErrorAllow
	stat.ProcessingTime.Start()

	endMetric := func() {
		stat.DataplaneTime.End(true)
		stat.ProcessingTime.End(true)
		stat.TotalTime.End(true)
		if errors.As(stat.Err, &dnsproxy.ErrFailedAcquireSemaphore{}) || errors.As(stat.Err, &dnsproxy.ErrTimedOutAcquireSemaphore{}) {
			metrics.FQDNSemaphoreRejectedTotal.Inc()
		}
		metrics.ProxyUpstreamTime.WithLabelValues(metricError, metrics.L7DNS, totalTime).Observe(
			stat.TotalTime.Total().Seconds())
		metrics.ProxyUpstreamTime.WithLabelValues(metricError, metrics.L7DNS, upstreamTime).Observe(
			stat.UpstreamTime.Total().Seconds())
		metrics.ProxyUpstreamTime.WithLabelValues(metricError, metrics.L7DNS, processingTime).Observe(
			stat.ProcessingTime.Total().Seconds())
		metrics.ProxyUpstreamTime.WithLabelValues(metricError, metrics.L7DNS, semaphoreTime).Observe(
			stat.SemaphoreAcquireTime.Total().Seconds())
		metrics.ProxyUpstreamTime.WithLabelValues(metricError, metrics.L7DNS, policyGenTime).Observe(
			stat.PolicyGenerationTime.Total().Seconds())
		metrics.ProxyUpstreamTime.WithLabelValues(metricError, metrics.L7DNS, policyCheckTime).Observe(
			stat.PolicyCheckTime.Total().Seconds())
		metrics.ProxyUpstreamTime.WithLabelValues(metricError, metrics.L7DNS, dataplaneTime).Observe(
			stat.DataplaneTime.Total().Seconds())
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

	if ep == nil {
		// This is a hard fail. We cannot proceed because record.Log requires a
		// non-nil ep, and we also don't want to insert this data into the
		// cache if we don't know that an endpoint asked for it (this is
		// asserted via ep != nil here and msg.Response && msg.Rcode ==
		// dns.RcodeSuccess below).
		endMetric()
		return dnsproxy.ErrDNSRequestNoEndpoint{}
	}

	// We determine the direction based on the DNS packet. The observation
	// point is always Egress, however.
	var flowType accesslog.FlowType
	var addrInfo logger.AddressingInfo
	if msg.Response {
		flowType = accesslog.TypeResponse
		addrInfo.DstIPPort = epIPPort
		addrInfo.DstIdentity = ep.GetIdentity()
		addrInfo.SrcIPPort = serverAddr
		addrInfo.SrcIdentity = serverID
	} else {
		flowType = accesslog.TypeRequest
		addrInfo.SrcIPPort = epIPPort
		addrInfo.SrcIdentity = ep.GetIdentity()
		addrInfo.DstIPPort = serverAddr
		addrInfo.DstIdentity = serverID
	}

	qname, responseIPs, TTL, CNAMEs, rcode, recordTypes, qTypes, err := dnsproxy.ExtractMsgDetails(msg)
	if err != nil {
		// This error is ok because all these values are used for reporting, or filling in the cache.
		log.WithError(err).Error("cannot extract DNS message details")
	}

	var serverPort uint16
	_, serverPortStr, err := net.SplitHostPort(serverAddr)
	if err != nil {
		log.WithError(err).Error("cannot extract destination IP from DNS request")
	} else {
		if serverPortUint64, err := strconv.ParseUint(serverPortStr, 10, 16); err != nil {
			log.WithError(err).WithField(logfields.Port, serverPortStr).Error("cannot parse destination port")
		} else {
			serverPort = uint16(serverPortUint64)
		}
	}
	ep.UpdateProxyStatistics("fqdn", strings.ToUpper(protocol), serverPort, false, !msg.Response, verdict)

	if msg.Response && msg.Rcode == dns.RcodeSuccess && len(responseIPs) > 0 {
		stat.PolicyGenerationTime.Start()

		// This must happen before the NameManager update below, to ensure that
		// this data is included in the serialized Endpoint object.
		// We also need to add to the cache before we purge any matching zombies
		// because they are locked separately and we want to keep the allowed IPs
		// consistent if a regeneration happens between the two steps. If an update
		// doesn't happen in the case, we play it safe and don't purge the zombie
		// in case of races.
		log.WithField(logfields.EndpointID, ep.ID).Debug("Recording DNS lookup in endpoint specific cache")
		if updated := ep.DNSHistory.Update(lookupTime, qname, ippkg.MustAddrsFromIPs(responseIPs), int(TTL)); updated {
			ep.DNSZombies.ForceExpireByNameIP(lookupTime, qname, responseIPs...)
			ep.SyncEndpointHeaderFile()
		}

		log.WithFields(logrus.Fields{
			"qname": qname,
			"ips":   responseIPs,
		}).Debug("Updating DNS name in cache from response to query")

		updateCtx, updateCancel := context.WithTimeout(
			context.WithValue(d.ctx, requestNameKey{}, qname), // set the name as a context key for logging
			option.Config.FQDNProxyResponseMaxDelay)
		defer updateCancel()
		updateStart := time.Now()

		wg := d.dnsNameManager.UpdateGenerateDNS(updateCtx, lookupTime, map[string]*fqdn.DNSIPRecords{
			qname: {
				IPs: responseIPs,
				TTL: int(TTL),
			}})

		stat.PolicyGenerationTime.End(true)
		stat.DataplaneTime.Start()
		updateComplete := make(chan struct{})
		go func(wg *sync.WaitGroup, done chan struct{}) {
			wg.Wait()
			close(updateComplete)
		}(wg, updateComplete)

		select {
		case <-updateCtx.Done():
			log.Error("Timed out waiting for datapath updates of FQDN IP information; returning response")
			metrics.ProxyDatapathUpdateTimeout.Inc()
		case <-updateComplete:
		}

		log.WithFields(logrus.Fields{
			logfields.Duration:   time.Since(updateStart),
			logfields.EndpointID: ep.GetID(),
			"qname":              qname,
		}).Debug("Waited for endpoints to regenerate due to a DNS response")

		endMetric()
	}

	stat.ProcessingTime.End(true)

	// Ensure that there are no early returns from this function before the
	// code below, otherwise the log record will not be made.
	record := logger.NewLogRecord(flowType, false,
		func(lr *logger.LogRecord) { lr.LogRecord.TransportProtocol = accesslog.TransportProtocol(protoID) },
		logger.LogTags.Verdict(verdict, reason),
		logger.LogTags.Addressing(addrInfo),
		logger.LogTags.DNS(&accesslog.LogRecordDNS{
			Query:             qname,
			IPs:               responseIPs,
			TTL:               TTL,
			CNAMEs:            CNAMEs,
			ObservationSource: stat.DataSource,
			RCode:             rcode,
			QTypes:            qTypes,
			AnswerTypes:       recordTypes,
		}),
	)
	record.Log()

	return nil
}

func getFqdnCacheHandler(d *Daemon, params GetFqdnCacheParams) middleware.Responder {
	// endpoints we want data from
	endpoints := d.endpointManager.GetEndpoints()

	CIDRStr := ""
	if params.Cidr != nil {
		CIDRStr = *params.Cidr
	}

	matchPatternStr := ""
	if params.Matchpattern != nil {
		matchPatternStr = *params.Matchpattern
	}

	source := ""
	if params.Source != nil {
		source = *params.Source
	}

	lookups, err := extractDNSLookups(endpoints, CIDRStr, matchPatternStr, source)
	switch {
	case err != nil:
		return api.Error(GetFqdnCacheBadRequestCode, err)
	case len(lookups) == 0:
		return NewGetFqdnCacheIDNotFound()
	}

	return NewGetFqdnCacheOK().WithPayload(lookups)
}

func deleteFqdnCacheHandler(d *Daemon, params DeleteFqdnCacheParams) middleware.Responder {
	matchPatternStr := ""
	if params.Matchpattern != nil {
		matchPatternStr = *params.Matchpattern
	}

	err := d.dnsNameManager.DeleteDNSLookups(time.Now(), matchPatternStr)
	if err != nil {
		return api.Error(DeleteFqdnCacheBadRequestCode, err)
	}
	return NewDeleteFqdnCacheOK()
}

func getFqdnCacheIDHandler(d *Daemon, params GetFqdnCacheIDParams) middleware.Responder {
	var endpoints []*endpoint.Endpoint
	if params.ID != "" {
		ep, err := d.endpointManager.Lookup(params.ID)
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

	source := ""
	if params.Source != nil {
		source = *params.Source
	}

	lookups, err := extractDNSLookups(endpoints, CIDRStr, matchPatternStr, source)
	switch {
	case err != nil:
		return api.Error(GetFqdnCacheBadRequestCode, err)
	case len(lookups) == 0:
		return NewGetFqdnCacheIDNotFound()
	}

	return NewGetFqdnCacheIDOK().WithPayload(lookups)
}

func getFqdnNamesHandler(d *Daemon, params GetFqdnNamesParams) middleware.Responder {
	payload := d.dnsNameManager.GetModel()
	return NewGetFqdnNamesOK().WithPayload(payload)
}

// extractDNSLookups returns API models.DNSLookup copies of DNS data in each
// endpoint's DNSHistory. These are filtered by CIDRStr and matchPatternStr if
// they are non-empty.
func extractDNSLookups(endpoints []*endpoint.Endpoint, CIDRStr, matchPatternStr, source string) (lookups []*models.DNSLookup, err error) {
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
		matcher, err := matchpattern.ValidateWithoutCache(matchpattern.Sanitize(matchPatternStr))
		if err != nil {
			return nil, err
		}
		nameMatcher = func(name string) bool { return matcher.MatchString(name) }
	}

	for _, ep := range endpoints {
		lookupSourceEntries := []*models.DNSLookup{}
		connectionSourceEntries := []*models.DNSLookup{}
		for _, lookup := range ep.DNSHistory.Dump() {
			if !nameMatcher(lookup.Name) {
				continue
			}

			// The API model needs strings
			IPStrings := make([]string, 0, len(lookup.IPs))

			// only proceed if any IP matches the cidr selector
			anIPMatches := false
			for _, ip := range lookup.IPs {
				anIPMatches = anIPMatches || cidrMatcher(ip.AsSlice())
				IPStrings = append(IPStrings, ip.String())
			}
			if !anIPMatches {
				continue
			}

			lookupSourceEntries = append(lookupSourceEntries, &models.DNSLookup{
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

				connectionSourceEntries = append(connectionSourceEntries, &models.DNSLookup{
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

		switch source {
		case dnsSourceLookup:
			lookups = append(lookups, lookupSourceEntries...)
		case dnsSourceConnection:
			lookups = append(lookups, connectionSourceEntries...)
		default:
			lookups = append(lookups, lookupSourceEntries...)
			lookups = append(lookups, connectionSourceEntries...)
		}
	}

	return lookups, nil
}
