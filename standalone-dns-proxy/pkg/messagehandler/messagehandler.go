// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package messagehandler

import (
	"log/slog"
	"net"
	"net/netip"
	"strconv"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/identity"
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
func (m *messageHandler) NotifyOnDNSMsg(lookupTime time.Time, ep *endpoint.Endpoint, epIPPort string, serverID identity.NumericIdentity, serverAddrPort netip.AddrPort, details dnsproxy.MsgDetails, protocol string, allowed bool, stat *dnsproxy.ProxyRequestContext) error {
	var ips [][]byte
	for _, i := range details.ResponseIPs {
		ips = append(ips, []byte(i.String()))
	}

	// Best-effort extraction of source information. These may fail when
	// the call originates from an error path (e.g. ep is nil).
	var sourceIp string
	var sourcePort uint64
	var sourceIdentityID uint32
	if host, portStr, err := net.SplitHostPort(epIPPort); err == nil {
		sourceIp = host
		sourcePort, _ = strconv.ParseUint(portStr, 10, 16)
	}
	if ep != nil {
		if secID, err := ep.GetSecurityIdentity(); err == nil {
			sourceIdentityID = secID.ID.Uint32()
		}
	}

	// Capture error info
	var errorMessage string
	if stat.Err != nil {
		errorMessage = stat.Err.Error()
	}

	message := &pb.FQDNMapping{
		Fqdn:           details.QName,
		RecordIp:       ips,
		Ttl:            details.TTL,
		SourceIp:       []byte(sourceIp),
		SourceIdentity: sourceIdentityID,
		ResponseCode:   uint32(details.RCode),
		MetricsData: &pb.MetricsData{
			ProcessingStats: &pb.ProcessingStats{
				TotalTimeNs:            stat.TotalTime.Total().Nanoseconds(),
				ProcessingTimeNs:       stat.ProcessingTime.Total().Nanoseconds(),
				UpstreamTimeNs:         stat.UpstreamTime.Total().Nanoseconds(),
				SemaphoreAcquireTimeNs: stat.SemaphoreAcquireTime.Total().Nanoseconds(),
				PolicyCheckTimeNs:      stat.PolicyCheckTime.Total().Nanoseconds(),
				PolicyGenerationTimeNs: stat.PolicyGenerationTime.Total().Nanoseconds(),
				DataplaneTimeNs:        stat.DataplaneTime.Total().Nanoseconds(),
				QnameLockTimeNs:        stat.QnameLockTime.Total().Nanoseconds(),
				UpdateEpCacheTimeNs:    stat.UpdateEpCacheTime.Total().Nanoseconds(),
				UpdateNmCacheTimeNs:    stat.UpdateNmCacheTime.Total().Nanoseconds(),
			},
			DnsResponseData: &pb.DNSResponseData{
				IsResponse:  details.Response,
				Cnames:      details.CNAMEs,
				Qtypes:      slices.Map(details.QTypes, func(q uint16) uint32 { return uint32(q) }),
				AnswerTypes: slices.Map(details.AnswerTypes, func(a uint16) uint32 { return uint32(a) }),
			},
			SourcePort:     uint32(sourcePort),
			ServerAddr:     serverAddrPort.String(),
			ServerIdentity: uint32(serverID),
			Protocol:       protocol,
			Allowed:        allowed,
			ErrorMessage:   errorMessage,
			IsTimeout:      stat.IsTimeout(),
		},
	}
	return m.ConnHandler.NotifyOnMsg(message)
}

// SetBindPort is not implemented for standalone DNS proxy yet. The port is set in the config map for the standalone DNS proxy.
func (m *messageHandler) SetBindPort(uint16) {
	m.Logger.Warn("SetBindPort is not implemented for standalone DNS proxy")
}

// UpdateOnDNSMsg is not implemented for standalone DNS proxy. The cilium agent is responsible for updating the datapath based on the response from cilium agent.
func (m *messageHandler) UpdateOnDNSMsg(lookupTime time.Time, ep *endpoint.Endpoint, qname string, responseIPs []netip.Addr, TTL int, stat *dnsproxy.ProxyRequestContext) {
	m.Logger.Warn("UpdateOnDNSMsg is not implemented for standalone DNS proxy")
}
