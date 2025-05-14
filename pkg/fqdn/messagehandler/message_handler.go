// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package messagehandler

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
	"github.com/cilium/cilium/pkg/fqdn/namemanager"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
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

type DNSMessageHandler interface {
	// NotifyOnDNSMsg handles DNS data when the in-agent DNS proxy sees a
	// DNS message. It emits monitor events, proxy metrics and stores DNS
	// data in the DNS cache. To update the DNS cache, it will call
	// UpdateOnDNSMsg() if the DNS message is a response.
	NotifyOnDNSMsg(lookupTime time.Time,
		ep *endpoint.Endpoint,
		epIPPort string,
		serverID identity.NumericIdentity,
		serverAddrPort netip.AddrPort,
		msg *dns.Msg,
		protocol string,
		allowed bool,
		stat *dnsproxy.ProxyRequestContext,
	) error

	// UpdateOnDNSMsg updates the DNS cache with the DNS message data.
	// It is called when the DNS message is a response. It is called by
	// NotifyOnDNSMsg() to update the DNS cache and standalone DNS
	// proxy grpc server with the DNS message data.
	UpdateOnDNSMsg(lookupTime time.Time,
		ep *endpoint.Endpoint,
		qname string,
		responseIPs []netip.Addr,
		TTL int,
		stat *dnsproxy.ProxyRequestContext,
	)

	SetBindPort(uint16)
}

type dnsMessageHandler struct {
	logger            *slog.Logger
	nameManager       namemanager.NameManager
	proxyAccessLogger accesslog.ProxyAccessLogger
	DNSRequestHandler DNSMessageHandler

	bindPort uint16
}

var _ DNSMessageHandler = &dnsMessageHandler{}

// SetBindPort pushes the proxy bind port to the handler;
// this is needed to break an import loop otherwise.
//
// The bind port is ony used for proxy statistics.
func (h *dnsMessageHandler) SetBindPort(port uint16) {
	h.bindPort = port
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
func (h *dnsMessageHandler) NotifyOnDNSMsg(
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
	var addrInfo accesslog.AddressingInfo
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
		h.logger.Error("cannot extract DNS message details",
			logfields.Error, err,
			logfields.DNSName, qname,
		)
		return fmt.Errorf("failed to extract DNS message details: %w", err)
	}

	if msg.Response && msg.Rcode == dns.RcodeSuccess && len(responseIPs) > 0 {
		h.UpdateOnDNSMsg(lookupTime, ep, qname, responseIPs, int(TTL), stat)
		endMetric()
	}

	stat.ProcessingTime.End(true)

	ep.UpdateProxyStatistics("fqdn", strings.ToUpper(protocol), serverAddrPort.Port(), h.bindPort, false, !msg.Response, verdict)

	// Ensure that there are no early returns from this function before the
	// code below, otherwise the log record will not be made.
	//
	// Restrict label enrichment time to 10ms; we don't want to block DNS
	// requests because an identity isn't in the local cache yet.
	logContext, lcncl := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer lcncl()
	record := h.proxyAccessLogger.NewLogRecord(flowType, false,
		func(lr *accesslog.LogRecord, _ accesslog.EndpointInfoRegistry) {
			lr.TransportProtocol = accesslog.TransportProtocol(protoID)
		},
		accesslog.LogTags.Verdict(verdict, reason),
		accesslog.LogTags.Addressing(logContext, addrInfo),
		accesslog.LogTags.DNS(&accesslog.LogRecordDNS{
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
	h.proxyAccessLogger.Log(record)

	return nil
}

func (h *dnsMessageHandler) UpdateOnDNSMsg(lookupTime time.Time, ep *endpoint.Endpoint, qname string, responseIPs []netip.Addr, TTL int, stat *dnsproxy.ProxyRequestContext) {
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
	h.nameManager.LockName(qname)

	if d := time.Since(mutexAcquireStart); d >= option.Config.DNSProxyLockTimeout {
		h.logger.Warn(fmt.Sprintf("Name lock acquisition time took longer than expected. Potentially too many parallel DNS requests being processed, consider adjusting --%s and/or --%s", option.DNSProxyLockCount, option.DNSProxyLockTimeout),
			logfields.DNSName, qname,
			logfields.Duration, d,
			logfields.Expected, option.Config.DNSProxyLockTimeout,
		)
	}

	h.logger.Debug("Recording DNS lookup in endpoint specific cache", logfields.EndpointID, ep.ID)

	// This must happen before the NameManager update below, to ensure that
	// this data is included in the serialized Endpoint object.
	// We also need to add to the cache before we purge any matching zombies
	// because they are locked separately and we want to keep the allowed IPs
	// consistent if a regeneration happens between the two steps. If an update
	// doesn't happen in the case, we play it safe and don't purge the zombie
	// in case of races.
	if updated := ep.DNSHistory.Update(lookupTime, qname, responseIPs, int(TTL)); updated {
		ep.DNSZombies.ForceExpireByNameIP(lookupTime, qname, responseIPs...)
		ep.SyncEndpointHeaderFile()
	}

	h.logger.Debug("Updating DNS name in cache from response to query",
		logfields.DNSName, qname,
		logfields.IPAddrs, responseIPs,
	)

	updateCtx, updateCancel := context.WithTimeout(context.Background(), option.Config.FQDNProxyResponseMaxDelay)
	defer updateCancel()
	updateStart := time.Now()

	dpUpdates := h.nameManager.UpdateGenerateDNS(updateCtx, lookupTime, qname, &fqdn.DNSIPRecords{
		IPs: responseIPs,
		TTL: int(TTL),
	})

	stat.PolicyGenerationTime.End(true)
	stat.DataplaneTime.Start()
	defer stat.DataplaneTime.End(true)

	if err := <-dpUpdates; err != nil {
		h.logger.Warn("Timed out waiting for datapath updates of FQDN IP information; returning response. Consider increasing --tofqdns-proxy-response-max-delay if this keeps happening.")
		metrics.ProxyDatapathUpdateTimeout.Inc()
	}

	// Policy updates for this name have been pushed out; we can release the lock.
	h.nameManager.UnlockName(qname)

	h.logger.Debug("Waited for endpoints to regenerate due to a DNS response",
		logfields.Duration, time.Since(updateStart),
		logfields.EndpointID, ep.GetID(),
		logfields.DNSName, qname,
	)
}
