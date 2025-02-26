// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"

	"github.com/cilium/dns"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/fqdn/re"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
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
)

// bootstrapFQDN initializes the toFQDNs related subsystems: dnsNameManager and the DNS proxy.
// dnsNameManager will use the default resolver and, implicitly, the
// default DNS cache. The proxy binds to all interfaces, and uses the
// configured DNS proxy port (this may be 0 and so OS-assigned).
func (d *Daemon) bootstrapFQDN(possibleEndpoints map[uint16]*endpoint.Endpoint, preCachePath string) (err error) {
	d.policy.GetSelectorCache().SetLocalIdentityNotifier(d.dnsNameManager)

	// Controller to cleanup TTL expired entries from the DNS policies.
	d.dnsNameManager.StartGC(d.ctx)

	// restore the global DNS cache state
	d.dnsNameManager.RestoreCache(preCachePath, possibleEndpoints)

	// Do not start the proxy in dry mode or if L7 proxy is disabled.
	// The proxy would not get any traffic in the dry mode anyway, and some of the socket
	// operations require privileges not available in all unit tests.
	if option.Config.DryMode || !option.Config.EnableL7Proxy {
		return nil
	}

	// A configured proxy port takes precedence over using the previous port.
	port := uint16(option.Config.ToFQDNsProxyPort)
	if port == 0 {
		// Try reuse previous DNS proxy port number
		if oldPort, isStatic, err := d.l7Proxy.GetProxyPort(proxytypes.DNSProxyName); err == nil {
			if isStatic {
				port = oldPort
			} else {
				openLocalPorts := d.l7Proxy.GetOpenLocalPorts()
				if _, alreadyOpen := openLocalPorts[oldPort]; !alreadyOpen {
					port = oldPort
				} else {
					d.logger.Info(
						"Unable re-use old DNS proxy port as it is already in use",
						slog.Uint64(logfields.Port, uint64(oldPort)),
					)
				}
			}
		}
	}
	if err := re.InitRegexCompileLRU(option.Config.FQDNRegexCompileLRUSize); err != nil {
		return fmt.Errorf("could not initialize regex LRU cache: %w", err)
	}
	dnsProxyConfig := dnsproxy.DNSProxyConfig{
		Address:                "",
		Port:                   port,
		IPv4:                   option.Config.EnableIPv4,
		IPv6:                   option.Config.EnableIPv6,
		EnableDNSCompression:   option.Config.ToFQDNsEnableDNSCompression,
		MaxRestoreDNSIPs:       option.Config.DNSMaxIPsPerRestoredRule,
		ConcurrencyLimit:       option.Config.DNSProxyConcurrencyLimit,
		ConcurrencyGracePeriod: option.Config.DNSProxyConcurrencyProcessingGracePeriod,
	}
	proxy.DefaultDNSProxy, err = dnsproxy.StartDNSProxy(dnsProxyConfig, d.lookupEPByIP, d.ipcache.LookupSecIDByIP, d.ipcache.LookupByIdentity,
		d.notifyOnDNSMsg)
	if err == nil {
		// Increase the ProxyPort reference count so that it will never get released.
		err = d.l7Proxy.SetProxyPort(proxytypes.DNSProxyName, proxytypes.ProxyTypeDNS, proxy.DefaultDNSProxy.GetBindPort(), false)
		if err == nil && port == proxy.DefaultDNSProxy.GetBindPort() {
			d.logger.Info(
				"Reusing previous DNS proxy port:",
				slog.Uint64(logfields.Port, uint64(port)),
			)
		}
		proxy.DefaultDNSProxy.SetRejectReply(option.Config.FQDNRejectResponse)
		// Restore old rules
		for _, possibleEP := range possibleEndpoints {
			// Upgrades from old ciliums have this nil
			if possibleEP.DNSRules != nil || possibleEP.DNSRulesV2 != nil {
				proxy.DefaultDNSProxy.RestoreRules(possibleEP)
			}
		}
	}
	return err // filled by StartDNSProxy
}

// updateDNSDatapathRules updates the DNS proxy iptables rules. Must be
// called after iptables has been initialized, and only after
// successful bootstrapFQDN().
func (d *Daemon) updateDNSDatapathRules(ctx context.Context) error {
	if option.Config.DryMode || !option.Config.EnableL7Proxy {
		return nil
	}

	return d.l7Proxy.AckProxyPort(ctx, proxytypes.DNSProxyName)
}

// lookupEPByIP returns the endpoint that this IP belongs to
func (d *Daemon) lookupEPByIP(endpointAddr netip.Addr) (endpoint *endpoint.Endpoint, isHost bool, err error) {
	if e := d.endpointManager.LookupIP(endpointAddr); e != nil {
		return e, e.IsHost(), nil
	}

	if node.IsNodeIP(endpointAddr) != "" {
		if e := d.endpointManager.GetHostEndpoint(); e != nil {
			return e, true, nil
		} else {
			return nil, true, errors.New("host endpoint has not been created yet")
		}
	}

	return nil, false, fmt.Errorf("cannot find endpoint with IP %s", endpointAddr)
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

// epIPPort and serverAddrPort should match the original request, where epAddr is
// the source for egress (the only case current).
// serverID is the destination server security identity at the time of the DNS event.
func (d *Daemon) notifyOnDNSMsg(
	lookupTime time.Time,
	ep *endpoint.Endpoint,
	epIPPort string,
	serverID identity.NumericIdentity,
	serverAddrPort netip.AddrPort,
	msg *dns.Msg,
	protocol string,
	allowed bool,
	stat *dnsproxy.ProxyRequestContext,
) error {
	protoID := u8proto.ProtoIDs[strings.ToLower(protocol)]
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
	serverAddrPortStr := serverAddrPort.String()
	if msg.Response {
		flowType = accesslog.TypeResponse
		addrInfo.DstIPPort = epIPPort
		addrInfo.DstEPID = ep.GetID()
		// ignore error; log fields are best effort. Only returns error if endpoint
		// is going away.
		addrInfo.DstSecIdentity, _ = ep.GetSecurityIdentity()
		addrInfo.SrcIPPort = serverAddrPortStr
		addrInfo.SrcIdentity = serverID
	} else {
		flowType = accesslog.TypeRequest
		addrInfo.SrcIPPort = epIPPort
		addrInfo.SrcEPID = ep.GetID()
		// ignore error; same reason as above.
		addrInfo.SrcSecIdentity, _ = ep.GetSecurityIdentity()
		addrInfo.DstIPPort = serverAddrPortStr
		addrInfo.DstIdentity = serverID
	}

	qname, responseIPs, TTL, CNAMEs, rcode, recordTypes, qTypes, err := dnsproxy.ExtractMsgDetails(msg)
	if err != nil {
		d.logger.Error(
			"cannot extract DNS message details",
			slog.Any(logfields.Error, err),
			slog.String(logfields.DNSName, qname),
		)
		return fmt.Errorf("failed to extract DNS message details: %w", err)
	}

	if msg.Response && msg.Rcode == dns.RcodeSuccess && len(responseIPs) > 0 {
		stat.PolicyGenerationTime.Start()

		// Create a critical section especially for when multiple DNS requests
		// are in-flight for the same name (i.e. cilium.io).
		//
		// In the absence of such a critical section, consider the following
		// race condition:
		//
		//              G1                                    G2
		//
		// T0 --> NotifyOnDNSMsg()               NotifyOnDNSMsg()            <-- T0
		//
		// T1 --> UpdateGenerateDNS()            UpdateGenerateDNS()         <-- T1
		//
		// T2 ----> mutex.Lock()                 +--------------------------+
		//                                       |No selectors need updating|
		// T3 ----> wg := UpdatePolicyMaps()     +--------------------------+
		//
		// T4 ----> mutex.Unlock()               mutex.Lock() / mutex.Unlock() <-- T4
		//
		// T5 ----> wg.Wait()                    DNS released back to pod    <-- T5
		//                                                    |
		// T6 --> DNS released back to pod                    |
		//              |                                     |
		//              |                                     |
		//              v                                     v
		//       Traffic flows fine                   Leads to policy drop until T6
		//
		// Note how G2 releases the DNS msg back to the pod at T5 because
		// UpdateGenerateDNS() was a no-op. It's a no-op because G1 had executed
		// UpdateGenerateDNS() first at T1 and performed the necessary policy
		// updates for the response IPs. Due to G1 performing all the work
		// first, G2 executes T4 also as a no-op and releases the msg back to the
		// pod at T5 before G1 would at T6.
		//
		// We do not do a `defer unlock()` here, as we should release the lock before
		// doing final bookkeeping.
		mutexAcquireStart := time.Now()
		d.dnsNameManager.LockName(qname)

		if duration := time.Since(mutexAcquireStart); duration >= option.Config.DNSProxyLockTimeout {
			d.logger.Warn(
				fmt.Sprintf(
					"Name lock acquisition time took longer than expected. "+
						"Potentially too many parallel DNS requests being processed, "+
						"consider adjusting --%s and/or --%s",
					option.DNSProxyLockCount, option.DNSProxyLockTimeout,
				),
				slog.String(logfields.DNSName, qname),
				slog.Duration(logfields.Duration, duration),
				slog.Duration(logfields.Expected, option.Config.DNSProxyLockTimeout),
			)
		}

		// This must happen before the NameManager update below, to ensure that
		// this data is included in the serialized Endpoint object.
		// We also need to add to the cache before we purge any matching zombies
		// because they are locked separately and we want to keep the allowed IPs
		// consistent if a regeneration happens between the two steps. If an update
		// doesn't happen in the case, we play it safe and don't purge the zombie
		// in case of races.
		d.logger.Debug(
			"Recording DNS lookup in endpoint specific cache",
			slog.Any(logfields.EndpointID, ep.ID),
		)
		if updated := ep.DNSHistory.Update(lookupTime, qname, responseIPs, int(TTL)); updated {
			ep.DNSZombies.ForceExpireByNameIP(lookupTime, qname, responseIPs...)
			ep.SyncEndpointHeaderFile()
		}

		d.logger.Debug(
			"Updating DNS name in cache from response to query",
			slog.String("qname", qname),
			slog.Any("ips", responseIPs),
		)

		updateCtx, updateCancel := context.WithTimeout(d.ctx, option.Config.FQDNProxyResponseMaxDelay)
		defer updateCancel()
		updateStart := time.Now()

		dpUpdates := d.dnsNameManager.UpdateGenerateDNS(updateCtx, lookupTime, map[string]*fqdn.DNSIPRecords{
			qname: {
				IPs: responseIPs,
				TTL: int(TTL),
			},
		})

		stat.PolicyGenerationTime.End(true)
		stat.DataplaneTime.Start()

		if err := dpUpdates.Wait(); err != nil {
			d.logger.Warn("Timed out waiting for datapath updates of FQDN IP information; returning response. Consider increasing --tofqdns-proxy-response-max-delay if this keeps happening.")
			metrics.ProxyDatapathUpdateTimeout.Inc()
		}

		// Policy updates for this name have been pushed out; we can release the lock.
		d.dnsNameManager.UnlockName(qname)

		d.logger.Debug(
			"Waited for endpoints to regenerate due to a DNS response",
			slog.Duration(logfields.Duration, time.Since(updateStart)),
			slog.Uint64(logfields.EndpointID, ep.GetID()),
			slog.String("qname", qname),
		)

		endMetric()
	}

	stat.ProcessingTime.End(true)

	ep.UpdateProxyStatistics("fqdn", strings.ToUpper(protocol), serverAddrPort.Port(), proxy.DefaultDNSProxy.GetBindPort(), false, !msg.Response, verdict)

	// Ensure that there are no early returns from this function before the
	// code below, otherwise the log record will not be made.
	//
	// Restrict label enrichment time to 10ms; we don't want to block DNS
	// requests because an identity isn't in the local cache yet.
	logContext, lcncl := context.WithTimeout(d.ctx, 10*time.Millisecond)
	defer lcncl()
	record := logger.NewLogRecord(flowType, false,
		func(lr *logger.LogRecord) { lr.LogRecord.TransportProtocol = accesslog.TransportProtocol(protoID) },
		logger.LogTags.Verdict(verdict, reason),
		logger.LogTags.Addressing(logContext, addrInfo),
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
