// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package messagehandler

import (
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strconv"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/slices"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/standalone-dns-proxy/pkg/client"

	pb "github.com/cilium/cilium/api/v1/standalone-dns-proxy"
)

type messageHandler struct {
	Logger      *slog.Logger
	ConnHandler client.ConnectionHandler
}

// NotifyOnDNSMsg implements messagehandler.DNSMessageHandler.
// It is used by the standalone DNS proxy to notify the gRPC client about the DNS message.
// This method always sends the gRPC message to the agent, even in error cases
// (e.g. ep == nil, timeout, proxy errors), so that the agent can emit the
// corresponding proxy metrics for every DNS event.
func (m *messageHandler) NotifyOnDNSMsg(lookupTime time.Time, ep *endpoint.Endpoint, epIPPort string, serverID identity.NumericIdentity, serverAddrPort netip.AddrPort, details *dnsproxy.MsgDetails, protocol string, allowed bool, stat *dnsproxy.ProxyRequestContext) error {
	var ips [][]byte
	for _, i := range details.ResponseIPs {
		ips = append(ips, []byte(i.String()))
	}

	sourceIP, sourcePort := m.parseSourceAddr(epIPPort)
	sourceIdentity := m.getSourceIdentity(ep)

	errorType, errorMessage := classifyProxyError(stat)

	message := &pb.FQDNMapping{
		Fqdn:           details.QName,
		RecordIp:       ips,
		Ttl:            details.TTL,
		SourceIp:       []byte(sourceIP),
		SourceIdentity: sourceIdentity,
		ResponseCode:   uint32(details.RCode),
		MetricsData: &pb.MetricsData{
			ProcessingStats: &pb.ProcessingStats{
				TotalTimeNs:            stat.TotalTime.Total().Nanoseconds(),
				ProcessingTimeNs:       stat.ProcessingTime.Total().Nanoseconds(),
				UpstreamTimeNs:         stat.UpstreamTime.Total().Nanoseconds(),
				SemaphoreAcquireTimeNs: stat.SemaphoreAcquireTime.Total().Nanoseconds(),
				PolicyCheckTimeNs:      stat.PolicyCheckTime.Total().Nanoseconds(),
			},
			DnsResponseData: &pb.DNSResponseData{
				IsResponse:  details.Response,
				Cnames:      details.CNAMEs,
				Qtypes:      slices.Map(details.QTypes, func(q uint16) uint32 { return uint32(q) }),
				AnswerTypes: slices.Map(details.AnswerTypes, func(a uint16) uint32 { return uint32(a) }),
			},
			SourcePort:     sourcePort,
			ServerAddr:     serverAddrPort.String(),
			ServerIdentity: serverID.Uint32(),
			Protocol:       protocol,
			Allowed:        allowed,
			ErrorMessage:   errorMessage,
			ErrorType:      errorType,
		},
	}
	return m.ConnHandler.NotifyOnMsg(message)
}

// parseSourceAddr extracts the source IP and port from epIPPort (host:port).
func (m *messageHandler) parseSourceAddr(epIPPort string) (string, uint32) {
	host, portStr, err := net.SplitHostPort(epIPPort)
	if err != nil {
		m.Logger.Warn("Failed to parse source IP:port",
			logfields.SourceIP, epIPPort,
			logfields.Error, err,
		)
		return "", 0
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		m.Logger.Warn("Failed to parse source port",
			logfields.Port, portStr,
			logfields.Error, err,
		)
		return host, 0
	}
	return host, uint32(port)
}

// getSourceIdentity returns the numeric security identity of the endpoint,
// or 0 if ep is nil or the identity cannot be retrieved.
func (m *messageHandler) getSourceIdentity(ep *endpoint.Endpoint) uint32 {
	if ep == nil {
		return 0
	}
	secID, err := ep.GetSecurityIdentity()
	if err != nil {
		m.Logger.Warn("Failed to get endpoint security identity", logfields.Error, err)
		return 0
	}
	return secID.ID.Uint32()
}

// classifyProxyError maps the Go error in stat.Err to a ProxyErrorType enum
// value and the error message string. This preserves the structured error
// classification across the gRPC boundary so that the agent can reconstruct
// the correct error type for metrics (timeout vs semaphore vs generic proxy error).
func classifyProxyError(stat *dnsproxy.ProxyRequestContext) (pb.ProxyErrorType, string) {
	if stat.Err == nil {
		return pb.ProxyErrorType_PROXY_ERROR_TYPE_NONE, ""
	}
	msg := stat.Err.Error()

	switch {
	case errors.As(stat.Err, &dnsproxy.ErrTimedOutAcquireSemaphore{}):
		return pb.ProxyErrorType_PROXY_ERROR_TYPE_SEMAPHORE_TIMED_OUT, msg
	case errors.As(stat.Err, &dnsproxy.ErrFailedAcquireSemaphore{}):
		return pb.ProxyErrorType_PROXY_ERROR_TYPE_SEMAPHORE_FAILED, msg
	case stat.IsTimeout():
		return pb.ProxyErrorType_PROXY_ERROR_TYPE_TIMEOUT, msg
	default:
		return pb.ProxyErrorType_PROXY_ERROR_TYPE_PROXY, msg
	}
}

// SetBindPort is not implemented for standalone DNS proxy yet. The port is set in the config map for the standalone DNS proxy.
func (m *messageHandler) SetBindPort(uint16) {
	m.Logger.Warn("SetBindPort is not implemented for standalone DNS proxy")
}

// UpdateOnDNSMsg is not implemented for standalone DNS proxy. The cilium agent is responsible for updating the datapath based on the response from cilium agent.
func (m *messageHandler) UpdateOnDNSMsg(lookupTime time.Time, ep *endpoint.Endpoint, qname string, responseIPs []netip.Addr, TTL int, stat *dnsproxy.ProxyRequestContext) {
	m.Logger.Warn("UpdateOnDNSMsg is not implemented for standalone DNS proxy")
}
