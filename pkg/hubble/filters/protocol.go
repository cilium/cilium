// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"context"
	"fmt"
	"strings"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

func filterByProtocol(protocols []string) (FilterFunc, error) {
	var l4Protocols, l7Protocols []string
	for _, p := range protocols {
		proto := strings.ToLower(p)
		switch proto {
		case "icmp", "icmpv4", "icmpv6", "tcp", "udp", "sctp":
			l4Protocols = append(l4Protocols, proto)
		case "dns", "http", "kafka":
			l7Protocols = append(l7Protocols, proto)
		default:
			return nil, fmt.Errorf("unknown protocol: %q", p)
		}
	}

	return func(ev *v1.Event) bool {
		l4 := ev.GetFlow().GetL4()
		for _, proto := range l4Protocols {
			switch proto {
			case "icmp":
				if l4.GetICMPv4() != nil || l4.GetICMPv6() != nil {
					return true
				}
			case "icmpv4":
				if l4.GetICMPv4() != nil {
					return true
				}
			case "icmpv6":
				if l4.GetICMPv6() != nil {
					return true
				}
			case "tcp":
				if l4.GetTCP() != nil {
					return true
				}
			case "udp":
				if l4.GetUDP() != nil {
					return true
				}
			case "sctp":
				if l4.GetSCTP() != nil {
					return true
				}
			}
		}

		l7 := ev.GetFlow().GetL7()
		for _, proto := range l7Protocols {
			switch proto {
			case "dns":
				if l7.GetDns() != nil {
					return true
				}
			case "http":
				if l7.GetHttp() != nil {
					return true
				}
			case "kafka":
				if l7.GetKafka() != nil {
					return true
				}
			}
		}

		return false
	}, nil
}

// ProtocolFilter implements filtering based on L4 protocol
type ProtocolFilter struct{}

// OnBuildFilter builds a L4 protocol filter
func (p *ProtocolFilter) OnBuildFilter(ctx context.Context, ff *flowpb.FlowFilter) ([]FilterFunc, error) {
	var fs []FilterFunc

	if ff.GetProtocol() != nil {
		pf, err := filterByProtocol(ff.GetProtocol())
		if err != nil {
			return nil, fmt.Errorf("invalid protocol filter: %v", err)
		}
		fs = append(fs, pf)
	}

	return fs, nil
}
