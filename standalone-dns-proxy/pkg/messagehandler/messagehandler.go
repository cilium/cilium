// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package messagehandler

import (
	"log/slog"
	"net"
	"net/netip"

	"github.com/cilium/dns"

	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/fqdn/dnsproxy"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/logging/logfields"
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
func (m *messageHandler) NotifyOnDNSMsg(lookupTime time.Time, ep *endpoint.Endpoint, epIPPort string, serverID identity.NumericIdentity, serverAddrPort netip.AddrPort, msg *dns.Msg, protocol string, allowed bool, stat *dnsproxy.ProxyRequestContext) error {
	qname, responseIPs, TTL, _, rcode, _, _, err := dnsproxy.ExtractMsgDetails(msg)
	if err != nil {
		m.Logger.Error("Cannot extract DNS message details", logfields.Error, err)
		return err
	}
	var ips [][]byte
	for _, i := range responseIPs {
		ips = append(ips, []byte(i.String()))
	}

	sourceIp, _, err := net.SplitHostPort(epIPPort)
	if err != nil {
		m.Logger.Error("Failed to split IP:Port", logfields.Error, err)
		return err
	}

	sourceIdentity, err := ep.GetSecurityIdentity()
	if err != nil {
		m.Logger.Error("Failed to get security identity", logfields.Error, err)
		return err
	}
	message := &pb.FQDNMapping{
		Fqdn:           qname,
		RecordIp:       ips,
		Ttl:            TTL,
		SourceIp:       []byte(sourceIp),
		SourceIdentity: uint32(sourceIdentity.ID),
		ResponseCode:   uint32(rcode),
	}
	return m.ConnHandler.NotifyOnMsg(message)
}

// SetBindPort is not implemented for standalone DNS proxy yet. The port is set in the config map for the standalone DNS proxy.
func (m *messageHandler) SetBindPort(uint16) {
	m.Logger.Warn("SetBindPort is not implemented for standalone DNS proxy")
}

// UpdateOnDNSMsg is not implemented for standalone DNS proxy. The cilium agent is responsible for update the datapath based on the response from cilium agent.
func (m *messageHandler) UpdateOnDNSMsg(lookupTime time.Time, ep *endpoint.Endpoint, qname string, responseIPs []netip.Addr, TTL int, stat *dnsproxy.ProxyRequestContext) {
	m.Logger.Warn("UpdateOnDNSMsg is not implemented for standalone DNS proxy")
}
