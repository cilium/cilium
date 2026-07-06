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
		case "icmp", "icmpv4", "icmpv6", "tcp", "udp", "sctp", "vrrp", "igmp":
			l4Protocols = append(l4Protocols, proto)
		case "dns", "http":
			l7Protocols = append(l7Protocols, proto)
		default:
			return nil, fmt.Errorf("unknown protocol: %q", p)
		}
	}

	return func(ev *v1.Event) bool {
		if ev == nil {
			return false
		}
		fl := ev.GetFlow()
		if fl == nil {
			return false
		}
		for _, proto := range l4Protocols {
			switch proto {
			case "icmp":
				if !fl.L4.ICMPv4.IsEmpty() || !fl.L4.ICMPv6.IsEmpty() {
					return true
				}
			case "icmpv4":
				if !fl.L4.ICMPv4.IsEmpty() {
					return true
				}
			case "icmpv6":
				if !fl.L4.ICMPv6.IsEmpty() {
					return true
				}
			case "tcp":
				if !fl.L4.TCP.IsEmpty() {
					return true
				}
			case "udp":
				if !fl.L4.UDP.IsEmpty() {
					return true
				}
			case "sctp":
				if !fl.L4.SCTP.IsEmpty() {
					return true
				}
			case "vrrp":
				if !fl.L4.VRRP.IsEmpty() {
					return true
				}
			case "igmp":
				if !fl.L4.IGMP.IsEmpty() {
					return true
				}
			}
		}

		if fl.L7.IsEmpty() {
			return false
		}
		for _, proto := range l7Protocols {
			switch proto {
			case "dns":
				if !fl.L7.DNS.IsEmpty() {
					return true
				}
			case "http":
				if !fl.L7.HTTP.IsEmpty() {
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
			return nil, fmt.Errorf("invalid protocol filter: %w", err)
		}
		fs = append(fs, pf)
	}

	return fs, nil
}
