// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package seven

import (
	"fmt"
	"strings"

	"github.com/google/gopacket/layers"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	"github.com/cilium/cilium/pkg/proxy/accesslog"
)

func decodeDNS(flowType accesslog.FlowType, dns *accesslog.LogRecordDNS) *flowpb.Layer7_Dns {
	qtypes := make([]string, 0, len(dns.QTypes))
	for _, qtype := range dns.QTypes {
		qtypes = append(qtypes, layers.DNSType(qtype).String())
	}
	if flowType == accesslog.TypeRequest {
		// Set only fields that are relevant for requests.
		return &flowpb.Layer7_Dns{
			Dns: &flowpb.DNS{
				Query:             dns.Query,
				ObservationSource: string(dns.ObservationSource),
				Qtypes:            qtypes,
			},
		}
	}
	ips := make([]string, 0, len(dns.IPs))
	for _, ip := range dns.IPs {
		ips = append(ips, ip.String())
	}
	rtypes := make([]string, 0, len(dns.AnswerTypes))
	for _, rtype := range dns.AnswerTypes {
		rtypes = append(rtypes, layers.DNSType(rtype).String())
	}
	return &flowpb.Layer7_Dns{
		Dns: &flowpb.DNS{
			Query:             dns.Query,
			Ips:               ips,
			Ttl:               dns.TTL,
			Cnames:            dns.CNAMEs,
			ObservationSource: string(dns.ObservationSource),
			Rcode:             uint32(dns.RCode),
			Qtypes:            qtypes,
			Rrtypes:           rtypes,
		},
	}
}

func dnsSummary(flowType accesslog.FlowType, dns *accesslog.LogRecordDNS) string {
	types := []string{}
	for _, t := range dns.QTypes {
		types = append(types, layers.DNSType(t).String())
	}
	qTypeStr := strings.Join(types, ",")

	switch flowType {
	case accesslog.TypeRequest:
		return fmt.Sprintf("DNS Query %s %s", dns.Query, qTypeStr)
	case accesslog.TypeResponse:
		rcode := layers.DNSResponseCode(dns.RCode)

		var answer string
		if rcode != layers.DNSResponseCodeNoErr {
			answer = fmt.Sprintf("RCode: %s", rcode)
		} else {
			parts := make([]string, 0)

			if len(dns.IPs) > 0 {
				ips := make([]string, 0, len(dns.IPs))
				for _, ip := range dns.IPs {
					ips = append(ips, ip.String())
				}
				parts = append(parts, fmt.Sprintf("%q", strings.Join(ips, ",")))
			}

			if len(dns.CNAMEs) > 0 {
				parts = append(parts, fmt.Sprintf("CNAMEs: %q", strings.Join(dns.CNAMEs, ",")))
			}

			answer = strings.Join(parts, " ")
		}

		sourceType := "Query"
		switch dns.ObservationSource {
		case accesslog.DNSSourceProxy:
			sourceType = "Proxy"
		}

		return fmt.Sprintf("DNS Answer %s TTL: %d (%s %s %s)", answer, dns.TTL, sourceType, dns.Query, qTypeStr)
	}

	return ""
}
