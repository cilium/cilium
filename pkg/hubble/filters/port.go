// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package filters

import (
	"context"
	"fmt"
	"strconv"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

func sourcePort(ev *v1.Event) (port uint16, ok bool) {
	l4 := ev.GetFlow().GetL4()
	if tcp := l4.GetTCP(); tcp != nil {
		return uint16(tcp.SourcePort), true
	}
	if udp := l4.GetUDP(); udp != nil {
		return uint16(udp.SourcePort), true
	}
	if sctp := l4.GetSCTP(); sctp != nil {
		return uint16(sctp.SourcePort), true
	}
	return 0, false
}

func destinationPort(ev *v1.Event) (port uint16, ok bool) {
	l4 := ev.GetFlow().GetL4()
	if tcp := l4.GetTCP(); tcp != nil {
		return uint16(tcp.DestinationPort), true
	}
	if udp := l4.GetUDP(); udp != nil {
		return uint16(udp.DestinationPort), true
	}
	if sctp := l4.GetSCTP(); sctp != nil {
		return uint16(sctp.DestinationPort), true
	}
	return 0, false
}

func filterByPort(portStrs []string, getPort func(*v1.Event) (port uint16, ok bool)) (FilterFunc, error) {
	ports := make([]uint16, 0, len(portStrs))
	for _, p := range portStrs {
		port, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %s", p, err)
		}
		ports = append(ports, uint16(port))
	}

	return func(ev *v1.Event) bool {
		if port, ok := getPort(ev); ok {
			for _, p := range ports {
				if p == port {
					return true
				}
			}
		}
		return false
	}, nil
}

// PortFilter implements filtering based on L4 port numbers
type PortFilter struct{}

// OnBuildFilter builds a L4 port filter
func (p *PortFilter) OnBuildFilter(ctx context.Context, ff *flowpb.FlowFilter) ([]FilterFunc, error) {
	var fs []FilterFunc

	if ff.GetSourcePort() != nil {
		spf, err := filterByPort(ff.GetSourcePort(), sourcePort)
		if err != nil {
			return nil, fmt.Errorf("invalid source port filter: %v", err)
		}
		fs = append(fs, spf)
	}

	if ff.GetDestinationPort() != nil {
		dpf, err := filterByPort(ff.GetDestinationPort(), destinationPort)
		if err != nil {
			return nil, fmt.Errorf("invalid destination port filter: %v", err)
		}
		fs = append(fs, dpf)
	}

	return fs, nil
}
