// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package messagehandler

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"strings"

	"github.com/cilium/dns"
	"go4.org/netipx"

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
	metricErrorAllow   = "allow"
)

type DNSMessageHandler interface {
	OnQuery(ep *endpoint.Endpoint,
		epIPPort string,
		serverID identity.NumericIdentity,
		serverAddrPort netip.AddrPort,
		msg *dns.Msg,
		protocol string,
		stat *dnsproxy.ProxyRequestContext,
	) error

	OnResponse(ep *endpoint.Endpoint,
		epIPPort string,
		serverID identity.NumericIdentity,
		serverAddrPort netip.AddrPort,
		msg *dns.Msg,
		protocol string,
		stat *dnsproxy.ProxyRequestContext,
	) error

	OnError(ep *endpoint.Endpoint,
		epIPPort string,
		serverID identity.NumericIdentity,
		serverAddrPort netip.AddrPort,
		msg *dns.Msg,
		protocol string,
		stat *dnsproxy.ProxyRequestContext,
		err error,
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

func (h *dnsMessageHandler) OnQuery(
	ep *endpoint.Endpoint,
	epIPPort string,
	serverID identity.NumericIdentity,
	serverAddrPort netip.AddrPort,
	query *dns.Msg,
	protocol string,
	stat *dnsproxy.ProxyRequestContext,
) error {
	stat.ProcessingTime.Start()
	if query.Response {
		return fmt.Errorf("expected query, got response")
	} else if ep == nil {
		// This is a hard fail. We cannot proceed because record.Log requires a
		// non-nil ep, and we also don't want to insert this data into the
		// cache if we don't know that an endpoint asked for it
		endMetric(stat, metricErrorAllow)
		return dnsproxy.ErrDNSRequestNoEndpoint{}
	}

	// The observation point is always Egress.
	addrInfo := accesslog.AddressingInfo{
		SrcIPPort: epIPPort,
		SrcEPID:   ep.GetID(),

		DstIPPort:   serverAddrPort.String(),
		DstIdentity: serverID,
	}
	// ignore error; log fields are best effort. Only returns error if endpoint
	// is going away.
	addrInfo.SrcSecIdentity, _ = ep.GetSecurityIdentity()

	qname, qTypes, err := ExtractQueryDetails(query)
	if err != nil {
		h.logger.Error("cannot extract DNS query details",
			logfields.Error, err,
			logfields.DNSName, qname,
		)
		return fmt.Errorf("failed to extract DNS query details: %w", err)
	}

	stat.ProcessingTime.End(true)

	verdict := accesslog.VerdictForwarded
	reason := "Allowed by policy"
	ep.UpdateProxyStatistics("fqdn", strings.ToUpper(protocol), serverAddrPort.Port(), h.bindPort, false, true, verdict)

	// Restrict label enrichment time to 10ms; we don't want to block DNS
	// requests because an identity isn't in the local cache yet.
	logContext, lcncl := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer lcncl()

	protoID := u8proto.ProtoIDs[strings.ToLower(protocol)]
	record := h.proxyAccessLogger.NewLogRecord(accesslog.TypeRequest, false,
		func(lr *accesslog.LogRecord, _ accesslog.EndpointInfoRegistry) {
			lr.TransportProtocol = accesslog.TransportProtocol(protoID)
		},
		accesslog.LogTags.Verdict(verdict, reason),
		accesslog.LogTags.Addressing(logContext, addrInfo),
		accesslog.LogTags.DNS(&accesslog.LogRecordDNS{
			Query:             qname,
			ObservationSource: stat.DataSource,
			QTypes:            qTypes,
		}),
	)
	h.proxyAccessLogger.Log(record)

	return nil
}

func (h *dnsMessageHandler) OnResponse(
	ep *endpoint.Endpoint,
	epIPPort string,
	serverID identity.NumericIdentity,
	serverAddrPort netip.AddrPort,
	response *dns.Msg,
	protocol string,
	stat *dnsproxy.ProxyRequestContext,
) error {
	stat.ProcessingTime.Start()
	if !response.Response {
		return fmt.Errorf("expected response, got query")
	} else if ep == nil {
		// This is a hard fail. We cannot proceed because record.Log requires a
		// non-nil ep, and we also don't want to insert this data into the
		// cache if we don't know that an endpoint asked for it (this is
		// asserted via ep != nil here and msg.Response && msg.Rcode ==
		// dns.RcodeSuccess below).
		endMetric(stat, metricErrorAllow)
		return dnsproxy.ErrDNSRequestNoEndpoint{}
	}

	// The observation point is always Egress.
	addrInfo := accesslog.AddressingInfo{
		DstIPPort: epIPPort,
		DstEPID:   ep.GetID(),

		SrcIPPort:   serverAddrPort.String(),
		SrcIdentity: serverID,
	}
	// ignore error; log fields are best effort. Only returns error if endpoint
	// is going away.
	addrInfo.DstSecIdentity, _ = ep.GetSecurityIdentity()

	qname, responseIPs, TTL, CNAMEs, rcode, recordTypes, qTypes, err := ExtractMsgDetails(response)
	if err != nil {
		h.logger.Error("cannot extract DNS message details",
			logfields.Error, err,
			logfields.DNSName, qname,
		)
		return fmt.Errorf("failed to extract DNS message details: %w", err)
	}

	if response.Rcode == dns.RcodeSuccess && len(responseIPs) > 0 {
		h.UpdateOnDNSMsg(time.Now(), ep, qname, responseIPs, int(TTL), stat)
		endMetric(stat, metricErrorAllow)
	}

	stat.ProcessingTime.End(true)

	verdict := accesslog.VerdictForwarded
	reason := "Allowed by policy"
	ep.UpdateProxyStatistics("fqdn", strings.ToUpper(protocol), serverAddrPort.Port(), h.bindPort, false, false, verdict)

	// Ensure that there are no early returns from this function before the
	// code below, otherwise the log record will not be made.
	//
	// Restrict label enrichment time to 10ms; we don't want to block DNS
	// requests because an identity isn't in the local cache yet.
	logContext, lcncl := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer lcncl()

	protoID := u8proto.ProtoIDs[strings.ToLower(protocol)]
	record := h.proxyAccessLogger.NewLogRecord(accesslog.TypeResponse, false,
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

func isTimeout(err error) bool {
	var neterr net.Error
	if errors.As(err, &neterr) {
		return neterr.Timeout()
	}
	return false
}

// FIXME: docs
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
func (h *dnsMessageHandler) OnError(
	ep *endpoint.Endpoint,
	epIPPort string,
	serverID identity.NumericIdentity,
	serverAddrPort netip.AddrPort,
	query *dns.Msg,
	protocol string,
	stat *dnsproxy.ProxyRequestContext,
	err error,
) error {
	stat.ProcessingTime.Start()
	if query.Response {
		return fmt.Errorf("error callback expected query, got response")
	}

	if isTimeout(err) {
		endMetric(stat, metricErrorTimeout)
		return nil
	}

	if ep == nil {
		// This is a hard fail. We cannot proceed because record.Log requires a
		// non-nil ep, and we also don't want to insert this data into the
		// cache if we don't know that an endpoint asked for it (this is
		// asserted via ep != nil here and msg.Response && msg.Rcode ==
		// dns.RcodeSuccess below).
		endMetric(stat, metricErrorProxy)
		return dnsproxy.ErrDNSRequestNoEndpoint{}
	}

	qname, qTypes, err := ExtractQueryDetails(query)
	if err != nil {
		h.logger.Error("cannot extract DNS query details",
			logfields.Error, err,
			logfields.DNSName, qname,
		)
		return fmt.Errorf("failed to extract DNS query details: %w", err)
	}

	stat.ProcessingTime.End(true)

	verdict := accesslog.VerdictError
	reason := "Error: " + err.Error()
	ep.UpdateProxyStatistics("fqdn", strings.ToUpper(protocol), serverAddrPort.Port(), h.bindPort, false, true, verdict)

	// ignore error; log fields are best effort. Only returns error if endpoint
	// is going away.
	epIdentity, _ := ep.GetSecurityIdentity()
	// The observation point is always Egress.
	addrInfo := accesslog.AddressingInfo{
		SrcIPPort:      epIPPort,
		SrcEPID:        ep.GetID(),
		SrcSecIdentity: epIdentity,

		DstIPPort:   serverAddrPort.String(),
		DstIdentity: serverID,
	}

	// Restrict label enrichment time to 10ms; we don't want to block DNS
	// requests because an identity isn't in the local cache yet.
	logContext, lcncl := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer lcncl()

	protoID := u8proto.ProtoIDs[strings.ToLower(protocol)]
	record := h.proxyAccessLogger.NewLogRecord(accesslog.TypeRequest, false,
		func(lr *accesslog.LogRecord, _ accesslog.EndpointInfoRegistry) {
			lr.TransportProtocol = accesslog.TransportProtocol(protoID)
		},
		accesslog.LogTags.Verdict(verdict, reason),
		accesslog.LogTags.Addressing(logContext, addrInfo),
		accesslog.LogTags.DNS(&accesslog.LogRecordDNS{
			Query:             qname,
			ObservationSource: stat.DataSource,
			QTypes:            qTypes,
		}),
	)
	h.proxyAccessLogger.Log(record)

	return nil
}

// EndMetric ends the span stats for this transaction and updates metrics.
func endMetric(istat *dnsproxy.ProxyRequestContext, metricError string) {
	istat.ProcessingTime.End(true)
	istat.TotalTime.End(true)
	metrics.ProxyUpstreamTime.WithLabelValues(metricError, metrics.L7DNS, totalTime).Observe(
		istat.TotalTime.Total().Seconds())
	metrics.ProxyUpstreamTime.WithLabelValues(metricError, metrics.L7DNS, upstreamTime).Observe(
		istat.UpstreamTime.Total().Seconds())
	metrics.ProxyUpstreamTime.WithLabelValues(metricError, metrics.L7DNS, processingTime).Observe(
		istat.ProcessingTime.Total().Seconds())
	metrics.ProxyUpstreamTime.WithLabelValues(metricError, metrics.L7DNS, semaphoreTime).Observe(
		istat.SemaphoreAcquireTime.Total().Seconds())
	metrics.ProxyUpstreamTime.WithLabelValues(metricError, metrics.L7DNS, policyGenTime).Observe(
		istat.PolicyGenerationTime.Total().Seconds())
	metrics.ProxyUpstreamTime.WithLabelValues(metricError, metrics.L7DNS, policyCheckTime).Observe(
		istat.PolicyCheckTime.Total().Seconds())
	metrics.ProxyUpstreamTime.WithLabelValues(metricError, metrics.L7DNS, dataplaneTime).Observe(
		istat.DataplaneTime.Total().Seconds())
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

// ExtractQueryDetails returns the canonical query name and all question types
// or an error if the message couldn't be understood.
func ExtractQueryDetails(msg *dns.Msg) (
	qname string,
	qTypes []uint16,
	err error,
) {
	if len(msg.Question) == 0 {
		return "", nil, errors.New("invalid DNS query")
	}
	qname = strings.ToLower(string(msg.Question[0].Name))

	qTypes = make([]uint16, 0, len(msg.Question))
	for _, q := range msg.Question {
		qTypes = append(qTypes, q.Qtype)
	}

	return qname, qTypes, nil
}

// ExtractMsgDetails extracts a canonical query name, any IPs in a response,
// the lowest applicable TTL, rcode, anwer rr types and question types
// When a CNAME is returned the chain is collapsed down, keeping the lowest TTL,
// and CNAME targets are returned.
func ExtractMsgDetails(msg *dns.Msg) (
	qname string,
	responseIPs []netip.Addr,
	TTL uint32,
	CNAMEs []string,
	rcode int,
	answerTypes []uint16,
	qTypes []uint16,
	err error,
) {
	if len(msg.Question) == 0 {
		return "", nil, 0, nil, 0, nil, nil, errors.New("Invalid DNS message")
	}
	qname = strings.ToLower(string(msg.Question[0].Name))

	TTL = math.MaxUint32 // a TTL must exist in the RRs

	answerTypes = make([]uint16, 0, len(msg.Answer))
	for _, ans := range msg.Answer {
		// Handle A, AAAA and CNAME records by accumulating IPs and lowest TTL
		switch ans := ans.(type) {
		case *dns.A:
			ip, ok := netipx.FromStdIP(ans.A)
			if !ok {
				return qname, nil, 0, nil, 0, nil, nil, errors.New("invalid IP in A record")
			}
			responseIPs = append(responseIPs, ip)
			if TTL > ans.Hdr.Ttl {
				TTL = ans.Hdr.Ttl
			}
		case *dns.AAAA:
			ip, ok := netipx.FromStdIP(ans.AAAA)
			if !ok {
				return qname, nil, 0, nil, 0, nil, nil, errors.New("invalid IP in AAAA record")
			}
			responseIPs = append(responseIPs, ip)
			if TTL > ans.Hdr.Ttl {
				TTL = ans.Hdr.Ttl
			}
		case *dns.CNAME:
			// We still track the TTL because the lowest TTL in the chain
			// determines the valid caching time for the whole response.
			if TTL > ans.Hdr.Ttl {
				TTL = ans.Hdr.Ttl
			}
			CNAMEs = append(CNAMEs, ans.Target)
		}
		answerTypes = append(answerTypes, ans.Header().Rrtype)
	}

	qTypes = make([]uint16, 0, len(msg.Question))
	for _, q := range msg.Question {
		qTypes = append(qTypes, q.Qtype)
	}

	return qname, responseIPs, TTL, CNAMEs, msg.Rcode, answerTypes, qTypes, nil
}
